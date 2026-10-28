#include "adi_file.hpp"
#include "codec.hpp"
#include "text.hpp"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include "win32_shim.hpp"
#endif

namespace adi {
namespace {

uint16_t read_u16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (static_cast<uint16_t>(p[1]) << 8));
}

uint32_t read_u32(const uint8_t* p) {
    return p[0] | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t read_u64(const uint8_t* p) {
    return static_cast<uint64_t>(read_u32(p)) |
           (static_cast<uint64_t>(read_u32(p + 4)) << 32);
}

}  // namespace

std::string Guid::to_string() const {
    char buf[64];
    std::snprintf(
        buf, sizeof(buf),
        "{%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
        bytes[3], bytes[2], bytes[1], bytes[0], bytes[5], bytes[4], bytes[7],
        bytes[6], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13],
        bytes[14], bytes[15]);
    return buf;
}

std::string utf16le_z(const uint8_t* data, size_t nbytes) {
    size_t units = nbytes / 2;
    for (size_t i = 0; i < units; ++i) {
        if (read_u16(data + 2 * i) == 0) {
            units = i;
            break;
        }
    }
    // Common helper decodes UTF-16LE with an explicit element count. Upstream
    // used wchar_t here, which is 2 bytes on Windows but 4 on Linux; casting
    // the on-disk bytes to wchar_t* read twice as much as the field contains.
    return text::utf16le_to_utf8(data, units);
}

uint32_t crc32_ieee(const uint8_t* data, size_t n, uint32_t seed) {
    uint32_t crc = seed ^ 0xFFFFFFFFu;
    for (size_t i = 0; i < n; ++i) {
        crc ^= data[i];
        for (int b = 0; b < 8; ++b) {
            uint32_t mask = (crc & 1u) ? 0xFFFFFFFFu : 0u;
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

AdiFile::AdiFile(std::filesystem::path path,
                 std::vector<std::filesystem::path> extra_members)
    : path_(std::move(path)) {
    HANDLE h = CreateFileW(path_.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("cannot open " + path_.string());
    }
    // parse_header(), parse_footer() and the image-set scan can throw. A
    // half-constructed AdiFile never runs ~AdiFile, so release the handle here
    // unless construction reaches the end (a fuzz target found this leak).
    struct HandleGuard {
        HANDLE handle;
        ~HandleGuard() {
            if (handle != INVALID_HANDLE_VALUE) {
                CloseHandle(handle);
            }
        }
    } guard{h};
    handle_ = h;
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz)) {
        throw std::runtime_error("GetFileSizeEx failed");
    }
    file_size_ = static_cast<uint64_t>(sz.QuadPart);
    if (file_size_ < 32) {
        throw std::runtime_error("file too small to be an AOMEI .adi image");
    }
    parse_header();
    parse_footer();

    std::vector<std::filesystem::path> members;
    members.push_back(path_);
    for (const auto& p : extra_members) {
        if (std::find(members.begin(), members.end(), p) == members.end()) {
            members.push_back(p);
        }
    }
    image_set_ = ImageSet::from_paths(members);
    guard.handle = INVALID_HANDLE_VALUE;
}

AdiFile::~AdiFile() {
    if (handle_) {
        CloseHandle(static_cast<HANDLE>(handle_));
    }
}

void AdiFile::read(uint64_t offset, void* dst, size_t n) const {
    if (n == 0) {
        return;
    }
    if (offset + n > file_size_) {
        throw std::runtime_error("read past end of file");
    }
    HANDLE h = static_cast<HANDLE>(handle_);
    LARGE_INTEGER li;
    li.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(h, li, nullptr, FILE_BEGIN)) {
        throw std::runtime_error("seek failed");
    }
    auto* out = static_cast<uint8_t*>(dst);
    size_t left = n;
    while (left) {
        DWORD chunk = left > 0x40000000u ? 0x40000000u : static_cast<DWORD>(left);
        DWORD got = 0;
        if (!ReadFile(h, out, chunk, &got, nullptr) || got == 0) {
            throw std::runtime_error("ReadFile failed");
        }
        out += got;
        left -= got;
    }
}

std::vector<uint8_t> AdiFile::read_vec(uint64_t offset, size_t n) const {
    std::vector<uint8_t> v(n);
    if (n) {
        read(offset, v.data(), n);
    }
    return v;
}

void AdiFile::read_logical(uint64_t offset, void* dst, size_t n) const {
    image_set_.read(offset, dst, n);
}

std::vector<uint8_t> AdiFile::read_logical_vec(uint64_t offset, size_t n) const {
    return image_set_.read_vec(offset, n);
}

uint64_t AdiFile::payload_end() const {
    if (footer_.size && footer_.size < file_size_) {
        return file_size_ - footer_.size;
    }
    return file_size_ > 16 ? file_size_ - 16 : file_size_;
}

void AdiFile::parse_header() {
    auto raw = read_vec(0, 16);
    if (std::string(reinterpret_cast<char*>(raw.data()), 4) != "BIFH") {
        throw std::runtime_error("not an AOMEI Backupper image (missing BIFH)");
    }
    header_.magic[0] = 'B';
    header_.magic[1] = 'I';
    header_.magic[2] = 'F';
    header_.magic[3] = 'H';
    header_.size = read_u32(raw.data() + 4);
    header_.checksum = read_u32(raw.data() + 8);
    if (header_.size < 0x40 || header_.size > 1024 * 1024 || header_.size > file_size_) {
        throw std::runtime_error("implausible BIFH size");
    }
    auto hdr = read_vec(0, header_.size);
    std::vector<uint8_t> header_crc_check = hdr;
    std::fill(header_crc_check.begin() + 8, header_crc_check.begin() + 12, 0);
    header_.crc_valid =
        br_crc32(header_crc_check.data(), header_crc_check.size()) == header_.checksum;
    std::copy(hdr.data() + 0x10, hdr.data() + 0x20, header_.guid_a.bytes);
    std::copy(hdr.data() + 0x20, hdr.data() + 0x30, header_.guid_b.bytes);
    if (header_.size > kHeaderCommentOff) {
        header_.comment = utf16le_z(hdr.data() + kHeaderCommentOff,
                                    header_.size - kHeaderCommentOff);
    }
    if (header_.size > kHeaderFilenameOff) {
        header_.filename = utf16le_z(hdr.data() + kHeaderFilenameOff,
                                     header_.size - kHeaderFilenameOff);
    }
}

void AdiFile::parse_footer() {
    auto tail = read_vec(file_size_ - 16, 16);
    if (std::string(reinterpret_cast<char*>(tail.data() + 12), 4) != "BIFT") {
        throw std::runtime_error("missing BIFT footer (file truncated?)");
    }
    footer_.magic[0] = 'B';
    footer_.magic[1] = 'I';
    footer_.magic[2] = 'F';
    footer_.magic[3] = 'T';
    footer_.checksum = read_u32(tail.data() + 4);
    footer_.size = read_u32(tail.data() + 8);
    if (footer_.size < 16 || footer_.size > file_size_) {
        footer_.size = 16;
        return;
    }
    auto blob = read_vec(file_size_ - footer_.size, footer_.size);
    if (blob.size() >= 12) {
        std::vector<uint8_t> tail_crc_check = blob;
        std::fill(tail_crc_check.end() - 12, tail_crc_check.end() - 8, 0);
        footer_.crc_valid =
            br_crc32(tail_crc_check.data(), tail_crc_check.size()) == footer_.checksum;
    }
    // sizeof(BR_IMAGE_FILE_TAIL) is 0x674 in real images. Our small synthetic
    // fixtures use a 16-byte footer and have no image-set fields.
    if (blob.size() >= 0x630) {
        footer_.has_image_set = true;
        footer_.data_length_in_set = read_u64(blob.data() + 0x620);
        footer_.data_offset_in_set = read_u64(blob.data() + 0x628);
    }
    if (blob.size() >= 92) {
        const uint8_t* end = blob.data() + blob.size();
        footer_.offset_a = read_u64(end - 92);
        footer_.offset_b = read_u64(end - 84);
        footer_.field_a = read_u32(end - 68);
        footer_.field_b = read_u32(end - 64);
        std::copy(end - 48, end - 32, footer_.guid_b.bytes);
        std::copy(end - 32, end - 16, footer_.guid_a.bytes);
    }
    footer_.filename = utf16le_z(blob.data(), blob.size());
    if (blob.size() > 0x410) {
        footer_.comment = utf16le_z(blob.data() + 0x410, blob.size() - 0x410);
    }
}

void AdiFile::print_info() const {
    std::cout << "file:     " << path_.string() << "\n";
    std::cout << "size:     " << file_size_ << " bytes ("
              << std::fixed << std::setprecision(2)
              << (static_cast<double>(file_size_) / 1024.0 / 1024.0 / 1024.0) << " GiB)\n";
    std::cout << "\n[BIFH header]\n";
    std::cout << "  magic:     BIFH\n";
    std::cout << "  size:      " << header_.size << " (0x" << std::hex << header_.size
              << std::dec << ")\n";
    std::cout << "  checksum:  0x" << std::hex << header_.checksum << std::dec << " ("
              << (header_.crc_valid ? "BRCrc32 valid" : "not BRCrc32") << ")\n";
    std::cout << "  guid A:    " << header_.guid_a.to_string() << "\n";
    std::cout << "  guid B:    " << header_.guid_b.to_string() << "\n";
    std::cout << "  comment:   " << header_.comment << "\n";
    std::cout << "  filename:  " << header_.filename << "\n";
    std::cout << "  payload:   offset 0x" << std::hex << payload_offset() << std::dec
              << "\n";

    std::cout << "\n[BIFT footer]\n";
    std::cout << "  magic:     BIFT\n";
    std::cout << "  size:      " << footer_.size << " (0x" << std::hex << footer_.size
              << std::dec << ")\n";
    std::cout << "  checksum:  0x" << std::hex << footer_.checksum << std::dec << " ("
              << (footer_.crc_valid ? "BRCrc32 valid" : "not BRCrc32") << ")\n";
    if (footer_.has_image_set) {
        std::cout << "  image set: DataOffInSet 0x" << std::hex
                  << footer_.data_offset_in_set << ", DataLenInSet 0x"
                  << footer_.data_length_in_set << std::dec << "\n";
    }
    std::cout << "\n[image-set members]\n";
    for (const auto& m : image_set_.members()) {
        std::cout << "  " << m.path.string() << " logical 0x" << std::hex
                  << m.logical_start << "..0x" << (m.logical_start + m.data_length)
                  << std::dec << " (" << m.data_length << " bytes), BIFH 0x"
                  << std::hex << m.header_size << std::dec << "\n";
    }
    std::cout << "  offset A:  0x" << std::hex << footer_.offset_a << std::dec << "\n";
    std::cout << "  offset B:  0x" << std::hex << footer_.offset_b << std::dec << "\n";
    std::cout << "  field A:   " << footer_.field_a << "\n";
    std::cout << "  field B:   " << footer_.field_b << "\n";
    std::cout << "  guid A:    " << footer_.guid_a.to_string() << "\n";
    std::cout << "  guid B:    " << footer_.guid_b.to_string() << "\n";
    std::cout << "  comment:   " << footer_.comment << "\n";
    std::cout << "  filename:  " << footer_.filename << "\n";
}

}  // namespace adi
