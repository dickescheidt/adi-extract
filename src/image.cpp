#include "image.hpp"

#include <algorithm>
#include <cstdio>
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
        if (off != pos_) {
            LARGE_INTEGER li;
            li.QuadPart = static_cast<LONGLONG>(off);
            SetFilePointerEx(h_, li, nullptr, FILE_BEGIN);
            pos_ = off;
        }
        uint64_t done = 0;
        while (done < n) {
            DWORD wrote = 0;
            if (!WriteFile(h_, p + done, static_cast<DWORD>(n - done), &wrote, nullptr) ||
                wrote == 0) {
                break;
            }
            done += wrote;
        }
        pos_ += done;
        return done;
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

    std::vector<uint8_t> ents(size_t(128) * 128, 0);
    uint32_t n = 0;
    for (size_t i = 0; i < map.volumes.size() && n < 128; ++i) {
        const Volume& v = map.volumes[i];
        if (!v.sectors) {
            continue;
        }
        const PartType t = part_type(v, i + 1 == map.volumes.size());
        uint8_t* e = ents.data() + size_t(n) * 128;
        std::memcpy(e, t.guid, 16);
        std::memcpy(e + 16, t.guid, 16);
        e[16] = uint8_t(0xA0 + n);
        e[17] = uint8_t(0x51 + n);
        put64(e + 32, v.lba);
        put64(e + 40, v.lba + v.sectors - 1);
        const std::string name = t.name;
        for (size_t k = 0; k < name.size() && k < 35; ++k) {
            e[56 + 2 * k] = uint8_t(name[k]);
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
        for (int i = 0; i < 16; ++i) {
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
    std::vector<BlockRec> sub(blocks.begin() + v->first, blocks.begin() + stop);
    Lz4Stream st(file, sub);
    const BlockRec* b = nullptr;
    const uint8_t* data = nullptr;
    size_t n = 0;
    uint32_t cluster = 0;
    while ((b = st.next_chunk(&data, &n)) != nullptr) {
        if (n != b->usize) {
            continue;
        }
        BlockLayout lay;
        if (!split_block(data, b->usize, cluster, &lay)) {
            continue;
        }
        if (!cluster && lay.hdr != 1) {
            cluster = lay.cluster;
        }
        if (b->region != 0 || lay.units == 0 || !unit_present(data, lay, 0)) {
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

}  // namespace

SectorMap discover_map(const AdiFile& file, const std::vector<BlockRec>& blocks,
                       const std::filesystem::path& out_csv) {
    SectorMap map;
    map.sector_size = kSector;
    map.source = "volume runs from the block index, region*256KiB + unit*cluster";
    if (blocks.empty()) {
        return map;
    }
    std::vector<uint32_t> max_region;
    for (size_t i = 0; i < blocks.size(); ++i) {
        if (i == 0 || blocks[i].off != blocks[i - 1].end()) {
            Volume v;
            v.first = i;
            map.volumes.push_back(v);
            max_region.push_back(0);
        }
        map.volumes.back().last = i;
        map.volumes.back().stored += blocks[i].usize;
        max_region.back() = std::max(max_region.back(), blocks[i].region);
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
        const uint64_t span = (uint64_t(max_region[i]) + 1) * kRegion / kSector;
        v.sectors = span;
        if (i + 1 < map.volumes.size() && map.volumes[i + 1].lba > v.lba) {
            v.sectors = map.volumes[i + 1].lba - v.lba;
        }
    }
    for (const auto& v : map.volumes) {
        map.disk_sectors = std::max(map.disk_sectors, v.lba + v.sectors + 34);
    }
    if (!out_csv.empty()) {
        std::ofstream csv(out_csv, std::ios::trunc);
        csv << "volume,fs,label,lba,sectors,cluster,data_base,blocks,stored_bytes\n";
        for (size_t i = 0; i < map.volumes.size(); ++i) {
            const Volume& v = map.volumes[i];
            csv << i << "," << v.fs << "," << v.label << "," << v.lba << "," << v.sectors << ","
                << v.cluster << "," << v.data_base << "," << (v.last - v.first + 1) << ","
                << v.stored << "\n";
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
    write_gpt(img, map);

    uint64_t written = 0;
    uint64_t units = 0;
    uint64_t odd_blocks = 0;
    uint64_t short_blocks = 0;
    uint64_t outside = 0;
    uint64_t next_note = 2ull << 30;

    for (size_t vi = 0; vi < map.volumes.size(); ++vi) {
        const Volume& v = map.volumes[vi];
        std::cout << "  volume " << vi << " " << (v.fs.empty() ? "raw" : v.fs) << " lba " << v.lba
                  << ", " << (v.last - v.first + 1) << " blocks, cluster " << v.cluster << "\n"
                  << std::flush;
        std::vector<BlockRec> sub(blocks.begin() + v.first, blocks.begin() + v.last + 1);
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
            if (n != b->usize) {
                ++short_blocks;
                continue;
            }
            BlockLayout lay;
            if (!split_block(data, b->usize, v.cluster, &lay)) {
                ++odd_blocks;
                continue;
            }
            const uint64_t base =
                vol_off + (b->stream == 0 ? v.data_base : 0) + region_offset(b->region);
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
                const uint8_t* src = data + lay.hdr + size_t(slot) * lay.cluster;
                const uint64_t dst = base + uint64_t(u) * lay.cluster;
                ++slot;
                if (dst + lay.cluster > vol_end) {
                    ++outside;
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
            if (written >= next_note) {
                std::cout << "    " << (written >> 30) << " GiB written, block "
                          << st.block_index() << "/" << sub.size() << "\n"
                          << std::flush;
                next_note += 2ull << 30;
            }
        }
        if (!st.ok()) {
            std::cout << "    decode stopped: " << st.error() << " at adi 0x" << std::hex
                      << st.error_in_pos() << std::dec << "\n";
        }
        if (st.bad_blocks()) {
            std::cout << "    " << st.bad_blocks() << " blocks decoded to the wrong size\n";
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
    std::cout << "\n";
    return written;
}

}  // namespace adi
