#include "diagnostics.hpp"
#include "image_set.hpp"
#include "codec.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <iostream>

namespace adi {
namespace {

uint32_t rd32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t rd64(const uint8_t* p) {
    return static_cast<uint64_t>(rd32(p)) | (static_cast<uint64_t>(rd32(p + 4)) << 32);
}

}  // namespace

ContainerFields parse_container_fields(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("cannot open " + path.string());
    }
    ContainerFields f;
    in.seekg(0, std::ios::end);
    const auto end = in.tellg();
    if (end < 32) {
        throw std::runtime_error(path.string() + " is too small to be an .adi member");
    }
    f.file_size = static_cast<uint64_t>(end);
    uint8_t head16[16]{};
    in.seekg(0);
    in.read(reinterpret_cast<char*>(head16), 16);
    if (std::memcmp(head16, "BIFH", 4) != 0) {
        throw std::runtime_error(path.string() + " has no BIFH header");
    }
    f.header_size = rd32(head16 + 4);
    f.header_checksum = rd32(head16 + 8);
    if (f.header_size >= 16 && f.header_size <= f.file_size) {
        std::vector<uint8_t> hdr(static_cast<size_t>(f.header_size));
        in.seekg(0);
        in.read(reinterpret_cast<char*>(hdr.data()), static_cast<std::streamsize>(hdr.size()));
        std::fill(hdr.begin() + 8, hdr.begin() + 12, 0);
        f.header_crc_valid = br_crc32(hdr.data(), hdr.size()) == f.header_checksum;
        if (hdr.size() > 0x44)
            f.name = utf16le_z(hdr.data() + 0x44, hdr.size() - 0x44);
    }

    uint8_t tail16[16]{};
    in.seekg(static_cast<std::streamoff>(f.file_size - 16));
    in.read(reinterpret_cast<char*>(tail16), 16);
    if (std::memcmp(tail16 + 12, "BIFT", 4) != 0) {
        throw std::runtime_error(path.string() + " has no BIFT footer");
    }
    f.tail_size = rd32(tail16 + 8);
    f.tail_checksum = rd32(tail16 + 4);
    if (f.tail_size < 12 || f.tail_size > f.file_size) {
        f.tail_size = 16;
    }
    std::vector<uint8_t> tail(static_cast<size_t>(f.tail_size));
    in.seekg(static_cast<std::streamoff>(f.file_size - f.tail_size));
    in.read(reinterpret_cast<char*>(tail.data()), static_cast<std::streamsize>(tail.size()));
    // BIFT +0x620 / +0x628: this member's range in the image set.
    f.has_image_set = tail.size() >= 0x630;
    if (f.has_image_set) {
        f.data_length_in_set = rd64(tail.data() + 0x620);
        f.data_offset_in_set = rd64(tail.data() + 0x628);
    }
    if (tail.size() >= 12) {
        std::vector<uint8_t> check = tail;
        for (size_t i = check.size() - 12; i < check.size() - 8; ++i) {
            check[i] = 0;
        }
        f.tail_crc_valid = br_crc32(check.data(), check.size()) == f.tail_checksum;
    }
    f.comment = utf16le_z(tail.data(), tail.size());
    return f;
}

ImageSet ImageSet::from_paths(const std::vector<std::filesystem::path>& paths) {
    ImageSet out;
    if (paths.empty()) {
        throw std::runtime_error("image set has no members");
    }
    for (const auto& p : paths) {
        const ContainerFields f = parse_container_fields(p);
        if (!f.header_crc_valid || !f.tail_crc_valid)
            adi::debug_log()
                << "  warning: " << p.string()
                << ": BIFH/BIFT checksum unverified/mismatched; metadata needs verification\n";
        if (!f.has_image_set || f.data_length_in_set == 0 ||
            f.data_length_in_set > f.file_size - std::min(f.file_size, f.header_size + f.tail_size))
            adi::debug_log() << "  warning: " << p.string()
                      << ": absent/invalid image-set length; using physical payload bounds; verify "
                         "member mapping\n";
        const uint64_t payload =
            f.file_size > f.header_size + f.tail_size
                ? f.file_size - f.header_size - f.tail_size
                : 0;
        uint64_t length = f.data_length_in_set;
        if (length == 0 || length > payload) {
            length = payload;
        }
        auto file = std::make_shared<std::ifstream>(p, std::ios::binary);
        if (!*file) {
            throw std::runtime_error("cannot open " + p.string());
        }
        ImageSetMemberInfo info;
        info.path = p;
        info.logical_start = f.data_offset_in_set;
        info.data_length = length;
        info.header_size = f.header_size;
        out.state_.push_back(State{info, file});
        out.members_.push_back(info);
    }
    std::sort(out.state_.begin(), out.state_.end(), [](const State& a, const State& b) {
        return a.info.logical_start < b.info.logical_start;
    });
    std::sort(out.members_.begin(), out.members_.end(),
              [](const ImageSetMemberInfo& a, const ImageSetMemberInfo& b) {
                  return a.logical_start < b.logical_start;
              });
    for (size_t i = 1; i < out.members_.size(); ++i) {
        const auto &a = out.members_[i - 1];
        const auto &b = out.members_[i];
        if (a.logical_start + a.data_length != b.logical_start)
            adi::debug_log() << "  warning: image-set members have a gap or overlap before "
                      << b.path.string() << "; first covering member used; verify mapping\n";
    }
    return out;
}

void ImageSet::read(uint64_t logical, void* dst, size_t n) const {
    auto* out = static_cast<uint8_t*>(dst);
    uint64_t cur = logical;
    size_t done = 0;
    while (done < n) {
        const State* m = nullptr;
        for (const State& s : state_) {
            if (cur >= s.info.logical_start &&
                cur < s.info.logical_start + s.info.data_length) {
                m = &s;
                break;
            }
        }
        if (!m) {
            throw std::runtime_error("image-set offset is not covered by any member");
        }
        const uint64_t available = std::min<uint64_t>(
            m->info.logical_start + m->info.data_length - cur, n - done);
        const uint64_t physical =
            m->info.header_size + (cur - m->info.logical_start);
        m->file->clear();
        m->file->seekg(static_cast<std::streamoff>(physical));
        m->file->read(reinterpret_cast<char*>(out + done),
                      static_cast<std::streamsize>(available));
        if (static_cast<size_t>(m->file->gcount()) != available) {
            throw std::runtime_error("image-set member ended during read");
        }
        cur += available;
        done += static_cast<size_t>(available);
    }
}

std::vector<uint8_t> ImageSet::read_vec(uint64_t logical, size_t n) const {
    std::vector<uint8_t> v(n);
    if (n) {
        read(logical, v.data(), n);
    }
    return v;
}

std::vector<std::filesystem::path> extra_member_paths(const char* var) {
    std::vector<std::filesystem::path> out;
    const char* raw = std::getenv(var);
    if (!raw || !*raw) {
        return out;
    }
    std::string s(raw);
    size_t start = 0;
    while (start <= s.size()) {
        const size_t sep = s.find(':', start);
        const std::string part = s.substr(start, sep == std::string::npos
                                                    ? std::string::npos
                                                    : sep - start);
        if (!part.empty()) {
            out.emplace_back(part);
        }
        if (sep == std::string::npos) {
            break;
        }
        start = sep + 1;
    }
    return out;
}

}  // namespace adi
