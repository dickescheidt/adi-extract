#include "diagnostics.hpp"
#include "image.hpp"
#include "text.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#include <winioctl.h>
#else
#include "win32_shim.hpp"
#endif

namespace adi {
namespace {

constexpr uint32_t kSector = 512;

bool read_at(const std::filesystem::path& p, uint64_t off, void* dst, size_t n) {
    std::ifstream in(p, std::ios::binary);
    if (!in) {
        return false;
    }
    in.seekg(static_cast<std::streamoff>(off));
    in.read(static_cast<char*>(dst), static_cast<std::streamsize>(n));
    return bool(in);
}

std::string utf16_field(const uint8_t* p, size_t n) {
    std::string s;
    for (size_t i = 0; i + 1 < n; i += 2) {
        char16_t ch = char16_t(p[i] | (p[i + 1] << 8));
        if (ch == 0) {
            break;
        }
        if (ch < 0x80) {
            s.push_back(char(ch));
        }
    }
    return s;
}

}  // namespace

DiskGeometry inspect_image(const std::filesystem::path& img_path) {
    DiskGeometry geo;
    if (!std::filesystem::exists(img_path) || std::filesystem::file_size(img_path) < 1024) {
        geo.partition_style = "none";
        return geo;
    }
    geo.sector_count = std::filesystem::file_size(img_path) / kSector;
    std::vector<uint8_t> mbr(512);
    if (!read_at(img_path, 0, mbr.data(), 512)) {
        geo.partition_style = "unreadable";
        return geo;
    }
    std::vector<uint8_t> gpt(92);
    if (read_at(img_path, 512, gpt.data(), 92) && std::memcmp(gpt.data(), "EFI PART", 8) == 0) {
        geo.partition_style = "GPT";
        uint32_t esize = gpt[80] | (uint32_t(gpt[81]) << 8) | (uint32_t(gpt[82]) << 16) |
                         (uint32_t(gpt[83]) << 24);
        uint32_t ecount = gpt[84] | (uint32_t(gpt[85]) << 8) | (uint32_t(gpt[86]) << 16) |
                          (uint32_t(gpt[87]) << 24);
        uint64_t eoff = 0;
        std::memcpy(&eoff, gpt.data() + 72, 8);
        if (!esize) {
            esize = 128;
        }
        if (ecount > 128) {
            ecount = 128;
        }
        std::vector<uint8_t> ents(esize * ecount);
        if (read_at(img_path, eoff * kSector, ents.data(), ents.size())) {
            for (uint32_t i = 0; i < ecount; ++i) {
                const uint8_t* e = ents.data() + i * esize;
                bool empty = true;
                for (int b = 0; b < 16; ++b) {
                    if (e[b]) {
                        empty = false;
                        break;
                    }
                }
                if (empty) {
                    continue;
                }
                Partition p;
                p.index = uint32_t(geo.partitions.size());
                std::memcpy(&p.first_lba, e + 32, 8);
                std::memcpy(&p.last_lba, e + 40, 8);
                p.name = utf16_field(e + 56, 72);
                char guid[40];
                std::snprintf(guid, sizeof(guid),
                              "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                              e[3], e[2], e[1], e[0], e[5], e[4], e[7], e[6], e[8], e[9], e[10],
                              e[11], e[12], e[13], e[14], e[15]);
                p.type_guid = guid;
                geo.partitions.push_back(std::move(p));
            }
        }
        return geo;
    }
    if (mbr[510] == 0x55 && mbr[511] == 0xAA) {
        geo.partition_style = "MBR";
        for (int i = 0; i < 4; ++i) {
            const uint8_t* e = mbr.data() + 446 + i * 16;
            if (e[4] == 0) {
                continue;
            }
            Partition p;
            p.index = uint32_t(geo.partitions.size());
            p.first_lba = uint32_t(e[8] | (e[9] << 8) | (e[10] << 16) | (e[11] << 24));
            uint32_t nsec = uint32_t(e[12] | (e[13] << 8) | (e[14] << 16) | (e[15] << 24));
            p.last_lba = p.first_lba + (nsec ? nsec - 1 : 0);
            p.name = "p" + std::to_string(i);
            geo.partitions.push_back(std::move(p));
        }
        return geo;
    }
    geo.partition_style = "unknown";
    return geo;
}

namespace {

class SparseImage {
public:
    explicit SparseImage(const std::filesystem::path& path) {
        h_ = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h_ == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("cannot create " + path.string());
        }
        DWORD ret = 0;
        DeviceIoControl(h_, FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0, &ret, nullptr);
    }
    ~SparseImage() {
        if (h_ != INVALID_HANDLE_VALUE) {
            CloseHandle(h_);
        }
    }
    SparseImage(const SparseImage&) = delete;
    SparseImage& operator=(const SparseImage&) = delete;

    uint64_t write_at(uint64_t off, const uint8_t* p, size_t n) {
        if (!n) {
            return 0;
        }
        // A hole reads back as zeros, so leading/trailing zero bytes can be
        // skipped entirely. AOMEI often stores whole clusters of zeros (it
        // backs up sectors, not files); writing those explicitly allocates
        // real blocks and destroys sparseness on Linux, where the Win32
        // FSCTL_SET_SPARSE shim is a no-op.
        size_t first = 0;
        while (first < n && p[first] == 0) {
            ++first;
        }
        if (first == n) {
            LARGE_INTEGER li;
            li.QuadPart = static_cast<LONGLONG>(off + n);
            SetFilePointerEx(h_, li, nullptr, FILE_BEGIN);
            pos_ = off + n;
            return n;  // logical length, for the caller's counters
        }
        size_t last = n;
        while (last > first && p[last - 1] == 0) {
            --last;
        }
        const uint64_t dst = off + first;
        const size_t len = last - first;
        if (dst != pos_) {
            LARGE_INTEGER li;
            li.QuadPart = static_cast<LONGLONG>(dst);
            SetFilePointerEx(h_, li, nullptr, FILE_BEGIN);
            pos_ = dst;
        }
        uint64_t done = 0;
        while (done < len) {
            DWORD wrote = 0;
            if (!WriteFile(h_, p + first + done, static_cast<DWORD>(len - done), &wrote,
                           nullptr) ||
                wrote == 0) {
                break;
            }
            done += wrote;
        }
        pos_ += done;
        return done == len ? n : done;
    }
    void set_size(uint64_t size) {
        LARGE_INTEGER li;
        li.QuadPart = static_cast<LONGLONG>(size);
        SetFilePointerEx(h_, li, nullptr, FILE_BEGIN);
        SetEndOfFile(h_);
        pos_ = size;
    }

private:
    HANDLE h_ = INVALID_HANDLE_VALUE;
    uint64_t pos_ = 0;
};

uint32_t crc32(const uint8_t* p, size_t n) {
    static uint32_t table[256];
    static bool init = false;
    if (!init) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) {
                c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            }
            table[i] = c;
        }
        init = true;
    }
    uint32_t c = 0xffffffffu;
    for (size_t i = 0; i < n; ++i) {
        c = table[(c ^ p[i]) & 0xff] ^ (c >> 8);
    }
    return c ^ 0xffffffffu;
}

void put32(uint8_t* p, uint32_t v) {
    p[0] = uint8_t(v);
    p[1] = uint8_t(v >> 8);
    p[2] = uint8_t(v >> 16);
    p[3] = uint8_t(v >> 24);
}

void put64(uint8_t* p, uint64_t v) {
    put32(p, uint32_t(v));
    put32(p + 4, uint32_t(v >> 32));
}

const uint8_t kEspGuid[16] = {0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11,
                              0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B};
const uint8_t kMsrGuid[16] = {0x16, 0xE3, 0xC9, 0xE3, 0x5C, 0x0B, 0xB8, 0x4D,
                              0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE};
const uint8_t kDataGuid[16] = {0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
                               0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7};
const uint8_t kRecoveryGuid[16] = {0xA4, 0xBB, 0x94, 0xDE, 0xD1, 0x06, 0x40, 0x4D,
                                   0xA1, 0x6A, 0xBF, 0xD5, 0x01, 0x79, 0xD6, 0xAC};

struct PartType {
    const uint8_t* guid;
    const char* name;
};

PartType part_type(const Volume& v, bool last) {
    if (v.fs.rfind("FAT", 0) == 0 && v.lba <= 4096) {
        return {kEspGuid, "EFI system partition"};
    }
    if (v.fs.empty() || v.fs == "raw") {
        return {kMsrGuid, "Microsoft reserved partition"};
    }
    if (last && v.sectors * kSector < (4ull << 30)) {
        return {kRecoveryGuid, "Basic data partition"};
    }
    return {kDataGuid, "Basic data partition"};
}

void write_gpt(SparseImage& img, const SectorMap& map) {
    const uint64_t last = map.disk_sectors - 1;
    std::vector<uint8_t> mbr(512, 0);
    mbr[446 + 0] = 0x00;
    mbr[446 + 1] = 0x02;
    mbr[446 + 2] = 0x00;
    mbr[446 + 3] = 0x00;
    mbr[446 + 4] = 0xEE;
    mbr[446 + 5] = 0xFF;
    mbr[446 + 6] = 0xFF;
    mbr[446 + 7] = 0xFF;
    put32(mbr.data() + 446 + 8, 1);
    put32(mbr.data() + 446 + 12,
          uint32_t(std::min<uint64_t>(last, 0xffffffffull)));
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    img.write_at(0, mbr.data(), mbr.size());

    if (map.volumes.size() > 128)
        adi::debug_log() << "  warning: GPT has only 128 entries; excess volumes omitted from partition "
                     "table; verify output\n";
    std::vector<uint8_t> ents(size_t(128) * 128, 0);
    uint32_t n = 0;
    for (size_t i = 0; i < map.volumes.size() && n < 128; ++i) {
        const Volume& v = map.volumes[i];
        if (std::all_of(std::begin(v.type_guid), std::end(v.type_guid),
                        [](uint8_t b) { return b == 0; }) ||
            std::all_of(std::begin(v.unique_guid), std::end(v.unique_guid),
                        [](uint8_t b) { return b == 0; }))
            adi::debug_log() << "  warning: missing partition GUIDs; generated/inferred GPT metadata "
                         "needs verification\n";
        if (!v.sectors) {
            adi::debug_log() << "  warning: zero-sector volume omitted from GPT; verify output\n";
            continue;
        }
        const PartType t = part_type(v, i + 1 == map.volumes.size());
        uint8_t* e = ents.data() + size_t(n) * 128;
        const auto any = [](const uint8_t* g) {
            for (int k = 0; k < 16; ++k) {
                if (g[k]) return true;
            }
            return false;
        };
        const bool recovered_type = any(v.type_guid);
        const bool recovered_unique = any(v.unique_guid);
        const uint8_t* type = recovered_type ? v.type_guid : t.guid;
        std::memcpy(e, type, 16);
        std::memcpy(e + 16, type, 16);
        if (recovered_unique) {
            std::memcpy(e + 16, v.unique_guid, 16);
        } else {
            e[16] = uint8_t(0xA0 + n);
            e[17] = uint8_t(0x51 + n);
        }
        put64(e + 32, v.lba);
        put64(e + 40, v.lba + v.sectors - 1);
        if (v.part_name.empty()) {
            const std::string name = t.name;
            for (size_t k = 0; k < name.size() && k < 35; ++k) {
                e[56 + 2 * k] = uint8_t(name[k]);
            }
        } else {
            // GPT names are UTF-16LE, up to 36 code units. Convert the UTF-8
            // label properly: emitting one byte per UTF-8 unit turned every
            // non-ASCII character into mojibake such as '??????'.
            std::string u16 = text::utf8_to_utf16le(v.part_name);
            constexpr size_t kNameBytes = 72;  // 36 code units
            if (u16.size() > kNameBytes) {
                u16.resize(kNameBytes);
                // Do not leave half a surrogate pair at the end of the field.
                const auto hi = static_cast<uint8_t>(u16[kNameBytes - 2]);
                const auto lo = static_cast<uint8_t>(u16[kNameBytes - 1]);
                const uint16_t last = static_cast<uint16_t>(hi | (lo << 8));
                if (last >= 0xd800u && last <= 0xdbffu) {
                    u16.resize(kNameBytes - 2);
                }
            }
            std::memcpy(e + 56, u16.data(), u16.size());
        }
        ++n;
    }
    img.write_at(2 * kSector, ents.data(), ents.size());
    img.write_at((last - 32) * kSector, ents.data(), ents.size());

    auto header = [&](uint64_t self, uint64_t other, uint64_t ent_lba) {
        std::vector<uint8_t> h(kSector, 0);
        std::memcpy(h.data(), "EFI PART", 8);
        put32(h.data() + 8, 0x00010000);
        put32(h.data() + 12, 92);
        put64(h.data() + 24, self);
        put64(h.data() + 32, other);
        put64(h.data() + 40, 34);
        put64(h.data() + 48, last - 33);
        for (size_t i = 0; i < 16; ++i) {
            h[56 + i] = uint8_t(0x40 + i);
        }
        put64(h.data() + 72, ent_lba);
        put32(h.data() + 80, 128);
        put32(h.data() + 84, 128);
        put32(h.data() + 88, crc32(ents.data(), ents.size()));
        put32(h.data() + 16, crc32(h.data(), 92));
        return h;
    };
    const auto primary = header(1, last, 2);
    img.write_at(kSector, primary.data(), primary.size());
    const auto backup = header(last, 1, last - 32);
    img.write_at(last * kSector, backup.data(), backup.size());
}

void probe_volume(const AdiFile& file, const std::vector<BlockRec>& blocks, Volume* v) {
    constexpr size_t kMaxProbe = 512;
    const size_t stop = std::min(v->last + 1, v->first + kMaxProbe);
    std::vector<BlockRec> sub(blocks.begin() + static_cast<std::ptrdiff_t>(v->first),
                                   blocks.begin() + static_cast<std::ptrdiff_t>(stop));
    Lz4Stream st(file, sub);
    const BlockRec* b = nullptr;
    const uint8_t* data = nullptr;
    size_t n = 0;
    uint32_t cluster = 0;
    while ((b = st.next_chunk(&data, &n)) != nullptr) {
        if (n != b->usize || !block_crc_ok(*b, data, n)) {
            adi::debug_log() << "  warning: block at logical " << b->off
                      << ": size/checksum failure during discovery; skipped; verify output\n";
            continue;
        }
        BlockLayout lay;
        if (!split_block(data, b->usize, cluster, &lay)) {
            adi::debug_log() << "  warning: block at logical " << b->off
                      << ": unrecognised layout during volume probe; skipped; verify output\n";
            continue;
        }
        if (!cluster && !lay.all_present) {
            cluster = lay.cluster;
        }
        if (b->region != 0 || lay.units == 0 || !unit_present(data, lay, 0)) {
            continue;
        }
        if (size_t(lay.hdr) > n || lay.cluster > n - lay.hdr) {
            continue;
        }
        BootSector bs;
        if (!parse_boot_sector(data + lay.hdr, lay.cluster, &bs)) {
            continue;
        }
        v->fs = bs.fs;
        v->label = bs.label;
        v->cluster = bs.bytes_per_sector * bs.sectors_per_cluster;
        v->data_base = b->stream == 0 ? 0 : bs.data_start;
        v->lba = bs.hidden_sectors;
        v->sectors = bs.total_sectors + (bs.fs == "NTFS" ? 1 : 0);
        return;
    }
    v->fs = "raw";
    v->cluster = cluster ? cluster : 512;
}

struct BootHit {
    uint64_t stream_off = 0;  // region*256KiB + unit*cluster
    uint64_t lba = 0;         // hidden_sectors from the boot sector
    uint64_t sectors = 0;     // total_sectors (+1 for NTFS)
    uint32_t cluster = 0;     // bytes_per_sector * sectors_per_cluster
    std::string fs;
    std::string label;
};

struct BootScan {
    std::vector<BootHit> hits;
    bool region0_has_mbr = false;
};

// Decompress the whole block stream once and collect every volume boot record.
// probe_volume() above only inspects region 0 of each index-chain run, which
// misses most partitions when AOMEI writes a multi-partition disk as one
// contiguous chain (the common case). Each boot sector knows its own LBA via
// hidden_sectors, so it anchors that partition on the disk.
BootScan scan_boot_sectors(const AdiFile& file, const std::vector<BlockRec>& blocks) {
    BootScan out;
    if (blocks.empty()) {
        return out;
    }
    Lz4Stream st(file, blocks);
    const BlockRec* b = nullptr;
    const uint8_t* data = nullptr;
    size_t n = 0;
    std::vector<uint64_t> seen;
    while ((b = st.next_chunk(&data, &n)) != nullptr) {
        if (n != b->usize || !block_crc_ok(*b, data, n)) {
            adi::debug_log() << "  warning: block at logical " << b->off
                      << ": size/checksum failure during discovery; skipped; verify output\n";
            continue;
        }
        BlockLayout lay;
        if (!split_block(data, b->usize, 0, &lay) || lay.units == 0 ||
            lay.cluster < kSector) {
            adi::debug_log() << "  warning: block at logical " << b->off
                      << ": unrecognised/empty layout during discovery; skipped; verify output\n";
            continue;
        }
        uint32_t slot = 0;
        for (uint32_t u = 0; u < kRegion / lay.cluster && slot < lay.units; ++u) {
            if (!unit_present(data, lay, u)) {
                continue;
            }
            const size_t src_off = size_t(lay.hdr) + size_t(slot) * lay.cluster;
            ++slot;
            if (src_off > n || lay.cluster > n - src_off) {
                adi::debug_log() << "  warning: truncated cluster data at logical " << b->off
                          << "; remaining clusters skipped; verify output\n";
                break;
            }
            const uint8_t* src = data + src_off;
            const uint64_t stream_off = region_offset(b->region) + uint64_t(u) * lay.cluster;
            if (b->region == 0 && u == 0 && src[kSector - 2] == 0x55 &&
                src[kSector - 1] == 0xAA &&
                (src[446 + 4] == 0xEE ||
                 (lay.cluster >= 2 * kSector &&
                  std::memcmp(src + kSector, "EFI PART", 8) == 0))) {
                out.region0_has_mbr = true;
            }
            BootSector bs;
            if (!parse_boot_sector(src, lay.cluster, &bs) || !bs.hidden_sectors ||
                !bs.bytes_per_sector || !bs.sectors_per_cluster) {
                continue;
            }
            if (std::find(seen.begin(), seen.end(), bs.hidden_sectors) != seen.end()) {
                continue;  // NTFS mirror boot sector or a duplicate hit
            }
            seen.push_back(bs.hidden_sectors);
            BootHit h;
            h.stream_off = stream_off;
            h.lba = bs.hidden_sectors;
            h.sectors = bs.total_sectors + (bs.fs == "NTFS" ? 1 : 0);
            h.cluster = bs.bytes_per_sector * bs.sectors_per_cluster;
            h.fs = bs.fs;
            h.label = bs.label;
            out.hits.push_back(h);
        }
    }
    std::sort(out.hits.begin(), out.hits.end(),
              [](const BootHit& x, const BootHit& y) {
                  return x.stream_off < y.stream_off;
              });
    return out;
}

}  // namespace

SectorMap discover_map(const AdiFile& file, const std::vector<BlockRec>& blocks,
                       const std::filesystem::path& out_csv) {
    SectorMap map;
    map.sector_size = kSector;
    if (blocks.empty()) {
        return map;
    }

    uint32_t max_region = 0;
    for (const auto& b : blocks) {
        max_region = std::max(max_region, b.region);
    }
    const uint64_t stream_span = (uint64_t(max_region) + 1) * kRegion;

    const BootScan scan = scan_boot_sectors(file, blocks);

    // Every boot sector must agree on (LBA*512 - stream offset). Then the
    // block stream is a whole-disk coordinate space shifted by one constant,
    // and every cluster can be placed at (stream offset + origin).
    bool consistent = !scan.hits.empty();
    int64_t delta = 0;
    if (!scan.hits.empty()) {
        delta = int64_t(scan.hits[0].lba * kSector) - int64_t(scan.hits[0].stream_off);
        if (delta < 0) {
            consistent = false;
        }
    }
    for (const auto& h : scan.hits) {
        if (int64_t(h.lba * kSector) - int64_t(h.stream_off) != delta) {
            consistent = false;
            break;
        }
    }

    std::cout << "  boot sectors: " << scan.hits.size() << "\n";
    for (const auto& h : scan.hits) {
        std::cout << "    LBA " << h.lba << " (byte " << h.lba * kSector
                  << ") at stream " << h.stream_off << " -> origin "
                  << int64_t(h.lba * kSector) - int64_t(h.stream_off) << "  "
                  << (h.fs.empty() ? "raw" : h.fs) << " " << h.sectors << " sectors\n";
    }
    if (std::getenv("ADI_EXTRACT_LEGACY_MAP")) {
        consistent = false;  // escape hatch: force the old volume-run layout
    }
    std::cout << "  layout: ";
    if (consistent) {
        map.passthrough = true;
        map.origin = uint64_t(delta);
        map.native_table = (map.origin == 0 && scan.region0_has_mbr);
        map.source = "whole-disk stream + " + std::to_string(map.origin) + "B origin, " +
                     std::to_string(scan.hits.size()) + " partitions";
        std::vector<BootHit> by_lba = scan.hits;
        std::sort(by_lba.begin(), by_lba.end(),
                  [](const BootHit& a, const BootHit& b) { return a.lba < b.lba; });
        const uint64_t end_lba = (map.origin + stream_span + kSector - 1) / kSector;
        for (const auto& h : by_lba) {
            Volume v;
            v.first = 0;
            v.last = blocks.size() - 1;
            v.fs = h.fs;
            v.label = h.label;
            v.cluster = h.cluster ? h.cluster : 512;
            v.lba = h.lba;
            v.sectors = h.sectors;
            v.data_base = 0;
            map.volumes.push_back(v);
        }
        for (size_t i = 0; i < map.volumes.size(); ++i) {
            if (map.volumes[i].sectors) {
                continue;
            }
            const uint64_t end =
                (i + 1 < map.volumes.size()) ? map.volumes[i + 1].lba : end_lba;
            if (end > map.volumes[i].lba) {
                map.volumes[i].sectors = end - map.volumes[i].lba;
            }
        }
        uint64_t volume_end = 0;
        for (const auto& v : map.volumes) {
            volume_end = std::max(volume_end, v.lba + v.sectors);
        }
        map.disk_sectors = std::max(volume_end, end_lba) + 34;
        std::cout << "whole-disk stream (origin " << map.origin << " bytes)";
        if (map.native_table) {
            std::cout << ", native partition table preserved";
        }
    } else {
        // Fallback: one volume per gap in the compressed block chain.
        map.source = "volume runs from the block index, region*256KiB + unit*cluster";
        std::vector<uint32_t> run_max_region;
        for (size_t i = 0; i < blocks.size(); ++i) {
            if (i == 0 || blocks[i].off != blocks[i - 1].end()) {
                Volume v;
                v.first = i;
                map.volumes.push_back(v);
                run_max_region.push_back(0);
            }
            map.volumes.back().last = i;
            map.volumes.back().stored += blocks[i].usize;
            run_max_region.back() = std::max(run_max_region.back(), blocks[i].region);
        }
        for (auto& v : map.volumes) {
            probe_volume(file, blocks, &v);
        }
        for (size_t i = 0; i < map.volumes.size(); ++i) {
            if (!map.volumes[i].lba && i) {
                map.volumes[i].lba = map.volumes[i - 1].lba + map.volumes[i - 1].sectors;
            }
        }
        for (size_t i = 0; i < map.volumes.size(); ++i) {
            Volume& v = map.volumes[i];
            if (v.sectors) {
                continue;
            }
            const uint64_t span = (uint64_t(run_max_region[i]) + 1) * kRegion / kSector;
            v.sectors = span;
            if (i + 1 < map.volumes.size() && map.volumes[i + 1].lba > v.lba) {
                v.sectors = map.volumes[i + 1].lba - v.lba;
            }
        }
        for (const auto& v : map.volumes) {
            map.disk_sectors = std::max(map.disk_sectors, v.lba + v.sectors + 34);
        }
        std::cout << "legacy volume runs";
        if (std::getenv("ADI_EXTRACT_LEGACY_MAP")) {
            std::cout << " (forced by ADI_EXTRACT_LEGACY_MAP)";
        } else if (!scan.hits.empty()) {
            std::cout << " (boot-sector origins disagree; falling back to index-run volumes)";
        }
    }
    std::cout << "\n" << std::flush;

    if (!out_csv.empty()) {
        std::ofstream csv(out_csv, std::ios::trunc);
        csv << "volume,fs,label,lba,sectors,cluster,data_base,blocks,stored_bytes,origin,passthrough\n";
        for (size_t i = 0; i < map.volumes.size(); ++i) {
            const Volume& v = map.volumes[i];
            csv << i << "," << v.fs << "," << v.label << "," << v.lba << "," << v.sectors
                << "," << v.cluster << "," << v.data_base << ","
                << (v.last - v.first + 1) << "," << v.stored << "," << map.origin << ","
                << (map.passthrough ? 1 : 0) << "\n";
        }
    }
    return map;
}

uint64_t reconstruct_image(const AdiFile& file, const std::vector<BlockRec>& blocks,
                           const SectorMap& map, const std::filesystem::path& out_img,
                           uint64_t max_bytes) {
    if (blocks.empty() || map.volumes.empty()) {
        return 0;
    }
    SparseImage img(out_img);
    img.set_size(map.disk_sectors * map.sector_size);
    if (!map.native_table) {
        write_gpt(img, map);
    }

    uint64_t written = 0;
    uint64_t units = 0;
    adi::debug_log() << "  warning: legacy reconstruction uses inferred geometry and placement and may "
                 "generate GPT; verify output layout and filesystem\n";
    uint64_t odd_blocks = 0;
    uint64_t short_blocks = 0;
    uint64_t outside = 0;
    uint64_t crc_checked = 0;
    uint64_t crc_bad = 0;
    uint64_t next_note = 2ull << 30;

    auto emit = [&](const BlockRec &b, const uint8_t *data, size_t n, uint64_t base, uint64_t limit,
                    uint32_t cluster_hint) {
        if (b.crc == 0)
            adi::debug_log() << "  warning: block at logical " << b.off
                      << ": no decoded checksum; contents need verification\n";
        if (n != b.usize) {
            ++short_blocks;
            adi::debug_log() << "  warning: block at logical " << b.off
                      << ": decoded size mismatch; skipped; verify output\n";
            return;
        }
        if (b.crc != 0) {
            ++crc_checked;
            if (!block_crc_ok(b, data, n)) {
                ++crc_bad;
                ++odd_blocks;
                std::cerr << "  warning: block at adi 0x" << std::hex << b.off << std::dec
                          << ": BRCrc32 mismatch, skipping\n";
                return;
            }
        }
        BlockLayout lay;
        if (!split_block(data, b.usize, cluster_hint, &lay)) {
            ++odd_blocks;
            adi::debug_log() << "  warning: block at logical " << b.off
                      << ": unrecognised layout; skipped; verify output\n";
            return;
        }
        uint32_t slot = 0;
        uint64_t run_dst = 0;
        const uint8_t* run_src = nullptr;
        size_t run_len = 0;
        auto flush = [&]() {
            if (run_len) {
                written += img.write_at(run_dst, run_src, run_len);
                run_len = 0;
            }
        };
        for (uint32_t u = 0; u < kRegion / lay.cluster && slot < lay.units; ++u) {
            if (!unit_present(data, lay, u)) {
                continue;
            }
            const size_t src_off = size_t(lay.hdr) + size_t(slot) * lay.cluster;
            ++slot;
            if (src_off > n || lay.cluster > n - src_off) {
                adi::debug_log() << "  warning: truncated cluster data at logical " << b.off
                          << "; remaining clusters skipped; verify output\n";
                break;
            }
            const uint8_t* src = data + src_off;
            const uint64_t dst = base + uint64_t(u) * lay.cluster;
            if (dst + lay.cluster > limit) {
                ++outside;
                adi::debug_log() << "  warning: block at logical " << b.off
                          << ": cluster exceeds volume boundary; skipped; verify output\n";
                continue;
            }
            if (run_len && run_dst + run_len == dst && run_src + run_len == src) {
                run_len += lay.cluster;
            } else {
                flush();
                run_dst = dst;
                run_src = src;
                run_len = lay.cluster;
            }
            ++units;
        }
        flush();
    };

    if (map.passthrough) {
        std::cout << "  reconstructing whole-disk stream, " << map.volumes.size()
                  << " partitions\n" << std::flush;
        Lz4Stream st(file, blocks);
        const BlockRec* b = nullptr;
        const uint8_t* data = nullptr;
        size_t n = 0;
        const uint64_t limit = map.disk_sectors * map.sector_size;
        while ((b = st.next_chunk(&data, &n)) != nullptr) {
            if (max_bytes && written >= max_bytes) {
                break;
            }
            emit(*b, data, n, map.origin + region_offset(b->region), limit, 0);
            if (written >= next_note) {
                std::cout << "    " << (written >> 30) << " GiB written, block "
                          << st.block_index() << "/" << blocks.size() << "\n"
                          << std::flush;
                next_note += 2ull << 30;
            }
        }
        if (!st.ok()) {
            std::cerr << "  warning: decode stopped: " << st.error() << " at adi 0x" << std::hex
                      << st.error_in_pos() << std::dec << "\n";
        }
        if (st.bad_blocks()) {
            std::cerr << "  warning: " << st.bad_blocks() << " blocks decoded to the wrong size\n";
        }
    } else {
        for (size_t vi = 0; vi < map.volumes.size(); ++vi) {
            const Volume& v = map.volumes[vi];
            std::cout << "  volume " << vi << " " << (v.fs.empty() ? "raw" : v.fs) << " lba "
                      << v.lba << ", " << (v.last - v.first + 1) << " blocks, cluster "
                      << v.cluster << "\n" << std::flush;
            std::vector<BlockRec> sub(blocks.begin() + static_cast<std::ptrdiff_t>(v.first),
                                   blocks.begin() + static_cast<std::ptrdiff_t>(v.last + 1));
            Lz4Stream st(file, sub);
            const uint64_t vol_off = v.lba * map.sector_size;
            const uint64_t vol_end = vol_off + v.sectors * map.sector_size;
            const BlockRec* b = nullptr;
            const uint8_t* data = nullptr;
            size_t n = 0;
            while ((b = st.next_chunk(&data, &n)) != nullptr) {
                if (max_bytes && written >= max_bytes) {
                    break;
                }
                const uint64_t base =
                    vol_off + (b->stream == 0 ? v.data_base : 0) + region_offset(b->region);
                emit(*b, data, n, base, vol_end, v.cluster);
                if (written >= next_note) {
                    std::cout << "    " << (written >> 30) << " GiB written, block "
                              << st.block_index() << "/" << sub.size() << "\n"
                              << std::flush;
                    next_note += 2ull << 30;
                }
            }
            if (!st.ok()) {
                std::cerr << "  warning: decode stopped: " << st.error() << " at adi 0x" << std::hex
                          << st.error_in_pos() << std::dec << "\n";
            }
            if (st.bad_blocks()) {
                std::cerr << "  warning: " << st.bad_blocks()
                          << " blocks decoded to the wrong size\n";
            }
        }
    }
    std::cout << "  " << units << " units placed";
    if (odd_blocks) {
        std::cout << ", " << odd_blocks << " unrecognised headers";
    }
    if (short_blocks) {
        std::cout << ", " << short_blocks << " short blocks";
    }
    if (outside) {
        std::cout << ", " << outside << " units outside their volume";
    }
    if (crc_checked) {
        std::cout << ", " << crc_checked << " BRCrc32 checked, " << crc_bad << " bad";
    }
    std::cout << "\n";
    return written;
}

uint64_t reconstruct_standard(const AdiFile& file, const StandardImage& std_img,
                              const std::filesystem::path& out_img) {
    if (std_img.have_encrypt && std_img.encrypt_mode != 0) {
        throw std::runtime_error(
            "encrypted images are not supported (0x106 mode != 0)");
    }
    SectorMap map;
    map.source = "standard 0x201/0x202/0x109 records";
    map.sector_size = kSector;
    map.disk_sectors = std_img.disk_sectors;
    for (const auto& v : std_img.volumes) {
        Volume vol;
        vol.first = 0;
        vol.last = std_img.blocks.empty() ? 0 : std_img.blocks.size() - 1;
        vol.cluster = v.cluster;
        vol.lba = v.lba;
        vol.sectors = v.sectors;
        vol.fs = v.fs;
        vol.label = v.label;
        vol.part_name = v.part_name;
        std::copy(v.type_guid, v.type_guid + 16, vol.type_guid);
        std::copy(v.unique_guid, v.unique_guid + 16, vol.unique_guid);
        map.volumes.push_back(std::move(vol));
    }

    SparseImage img(out_img);
    const uint64_t limit = std_img.disk_sectors * map.sector_size;
    img.set_size(limit);
    write_gpt(img, map);

    const std::vector<BlockRec> no_blocks;
    Lz4Stream dec(file, no_blocks);
    uint64_t written = 0;
    uint64_t units = 0;
    uint64_t crc_checked = 0;
    uint64_t crc_bad = 0;
    uint64_t odd = 0;
    for (const StdBlock& b : std_img.blocks) {
        adi::debug_log() << "  trace: vdb region=" << b.reg_no << " block=" << b.block_no
                         << " logical=0x" << std::hex << b.off << std::dec << " stored=" << b.csize
                         << " expected=" << b.usize << " output_base=0x" << std::hex << b.base
                         << std::dec << " region_remaining=" << b.region_remaining << "\n";
        const auto comp = file.read_logical_vec(b.off, b.csize);
        const uint8_t* data = nullptr;
        size_t n = 0;
        if (b.csize == b.usize) {
            data = comp.data();
            n = comp.size();
        } else {
            if (std_img.have_compress && std_img.compress_mode > 1) {
                throw std::runtime_error("unsupported compression mode (0x105)");
            }
            if (std_img.have_compress && std_img.compress_mode == 0)
                adi::debug_log() << "  warning: compression mode 0 but unequal stored/decoded sizes; "
                             "attempting LZ4; verify output\n";
            if (!dec.decode_buffer(comp.data(), comp.size(), b.usize, &data, &n)) {
                std::cerr << "  warning: block at logical 0x" << std::hex << b.off
                          << std::dec << ": LZ4 decode failed: " << dec.error() << "\n";
                ++odd;
                continue;
            }
        }
        if (n != b.usize) {
            std::cerr << "  warning: block at logical 0x" << std::hex << b.off
                      << std::dec << ": decoded " << n << " bytes, expected "
                      << b.usize << "\n";
            ++odd;
            continue;
        }
        if (b.crc != 0) {
            ++crc_checked;
            if (br_crc32(data, n) != b.crc) {
                ++crc_bad;
                std::cerr << "  warning: block at logical 0x" << std::hex << b.off
                          << std::dec << ": BRCrc32 mismatch, skipping\n";
                continue;
            }
        }
        if (adi::debug_diagnostics) {
            adi::debug_log() << "  trace: decoded logical=0x" << std::hex << b.off << std::dec
                             << " bytes=" << n << " crc_actual=0x" << std::hex << br_crc32(data, n)
                             << " crc_expected=0x" << b.crc << std::dec << "\n";
        }
        const size_t bmp = b.bitmap_len;
        const size_t cluster = b.cluster;
        const uint32_t cpb = b.clusters_per_block;
        if (n < bmp || !cluster || !cpb) {
            adi::debug_log() << "  warning: block at logical " << b.off
                      << ": invalid bitmap/geometry; skipped; verify output\n";
            ++odd;
            continue;
        }
        if (adi::debug_diagnostics) {
            adi::debug_log() << "  trace: bitmap logical=0x" << std::hex << b.off << " bytes=";
            for (size_t i = 0; i < bmp; ++i)
                adi::debug_log() << std::setw(2) << std::setfill('0')
                                 << static_cast<unsigned>(data[i]);
            adi::debug_log() << std::setfill(' ') << std::dec << " clusters=" << cpb
                             << " cluster_bytes=" << cluster << "\n";
        }
        size_t pop = 0;
        for (uint32_t u = 0; u < cpb; ++u) {
            if (u / 8 < bmp && (data[u / 8] & (1u << (u & 7)))) {
                ++pop;
            }
        }
        auto bytes_at = [&](uint32_t u) -> size_t {
            const uint64_t offset = static_cast<uint64_t>(u) * cluster;
            return offset < b.region_remaining
                ? static_cast<size_t>(std::min<uint64_t>(cluster, b.region_remaining - offset)) : 0;
        };
        size_t bounded = bmp;
        for (uint32_t u = 0; u < cpb; ++u) {
            if (u / 8 < bmp && (data[u / 8] & (1u << (u & 7)))) bounded += bytes_at(u);
        }
        const bool padded = n == bmp + pop * cluster;
        if (!b.region_remaining || (!padded && n != bounded)) {
            throw std::runtime_error("decoded block size does not match 0x109 geometry at logical offset " + std::to_string(b.off));
        }
        size_t source = bmp;
        uint64_t run_dst = 0;
        const uint8_t* run_src = nullptr;
        size_t run_len = 0;
        auto flush = [&]() {
            if (run_len) {
                adi::debug_log() << "  trace: write logical=0x" << std::hex << b.off << std::dec
                                 << " decoded_offset=" << (run_src - data) << " output=0x"
                                 << std::hex << run_dst << std::dec << " bytes=" << run_len << "\n";
                written += img.write_at(run_dst, run_src, run_len);
                run_len = 0;
            }
        };
        for (uint32_t u = 0; u < cpb; ++u) {
            if (u / 8 >= bmp || !(data[u / 8] & (1u << (u & 7)))) {
                continue;
            }
            const size_t len = bytes_at(u);
            const size_t src = source;
            source += padded ? cluster : len;
            const uint64_t dst = b.base + static_cast<uint64_t>(u) * cluster;
            if (!len) continue;
            if (dst + len > limit) throw std::runtime_error("standard block exceeds output boundary");
            if (run_len && run_dst + run_len == dst && run_src + run_len == data + src) {
                run_len += len;
            } else {
                flush();
                run_dst = dst;
                run_src = data + src;
                run_len = len;
            }
            ++units;
        }
        flush();
    }
    if (!written && !std_img.blocks.empty()) {
        throw std::runtime_error(
            "no VDB block could be decoded; nothing was recovered from " +
            std::to_string(std_img.blocks.size()) + " block(s)");
    }
    std::cout << "  " << units << " units placed, " << crc_checked
              << " BRCrc32 checked, " << crc_bad << " bad";
    if (odd) {
        std::cout << ", " << odd << " odd blocks";
    }
    std::cout << "\n";
    return written;
}

}  // namespace adi
