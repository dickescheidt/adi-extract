#include "diagnostics.hpp"
#include "records.hpp"
#include "adi_file.hpp"
#include "codec.hpp"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <map>
#include <sstream>
#include <stdexcept>

namespace adi {
namespace {

constexpr uint32_t kVolumeIndex = 0x201;
constexpr uint32_t kDataBlockIndex = 0x202;
constexpr uint32_t kMetadata = 0x102;
constexpr uint32_t kCompress = 0x105;
constexpr uint32_t kEncrypt = 0x106;
constexpr uint32_t kRegion = 0x109;

constexpr size_t kStdHdr = 0x10;
constexpr size_t kVdbSize = 0x20;
constexpr size_t kMaxRecord = 1u << 20;
constexpr size_t kChunk = 4u << 20;
constexpr size_t kOverlap = kStdHdr - 1;
/// Bytes at the end of the primary member searched before the whole file.
/// AOMEI writes the record block after the payload, so the real image's
/// records sit in the last few kilobytes; four MiB leaves room for hundreds of
/// volumes and replaces a full pass over a 70 GiB file.
constexpr uint64_t kTailWindow = 4ull << 20;

uint32_t rd32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}
uint64_t rd64(const uint8_t* p) {
    return static_cast<uint64_t>(rd32(p)) | (static_cast<uint64_t>(rd32(p + 4)) << 32);
}
uint32_t u32(const std::vector<uint8_t>& b, size_t o) {
    return o + 4 <= b.size() ? rd32(b.data() + o) : 0;
}
uint64_t u64(const std::vector<uint8_t>& b, size_t o) {
    return o + 8 <= b.size() ? rd64(b.data() + o) : 0;
}
std::string txt(const std::vector<uint8_t>& b, size_t o, size_t n) {
    if (o >= b.size()) {
        return {};
    }
    return utf16le_z(b.data() + o, std::min(n, b.size() - o));
}

struct Header {
    uint64_t off = 0;
    uint32_t rec_type = 0;
};

struct DataBlockRef {
    uint64_t data_offset = 0;
    uint32_t data_size = 0;
    uint32_t entry_count = 0;
};

struct DataBlockIndex {
    uint64_t off = 0;
    uint32_t entry_count = 0;
    std::vector<DataBlockRef> refs;
};

struct DirEntry {
    uint32_t rec_type = 0;
    uint64_t offset = 0;
};

struct DirectoryIndex {
    uint64_t off = 0;
    std::vector<DirEntry> entries;
};

struct Region {
    uint64_t off = 0;
    uint32_t reg_no = 0;
    uint64_t block_begin_sector = 0;
    uint64_t total_sectors = 0;
    uint32_t clusters_per_block = 0;
    uint32_t sectors_per_cluster = 0;
    uint32_t bytes_per_sector = 0;

    uint64_t cluster() const {
        return static_cast<uint64_t>(sectors_per_cluster) * bytes_per_sector;
    }
    uint64_t sectors_per_region() const {
        return static_cast<uint64_t>(clusters_per_block) * sectors_per_cluster;
    }
    uint32_t bitmap_len() const { return (clusters_per_block + 7) / 8; }
};

struct Metadata {
    uint64_t off = 0;
    uint32_t bytes_per_sector = 0;
    uint64_t partition_start_sector = 0;
    uint64_t partition_total_sectors = 0;
    std::string label;
    std::string description;
    uint8_t type_guid[16]{};
    uint8_t unique_guid[16]{};
};

struct VdbEntry {
    uint32_t reg_no = 0;
    uint64_t block_no = 0;
    uint64_t img_offset = 0;
    uint32_t old_size = 0;
    uint32_t new_size = 0;
    uint32_t crc = 0;
};

/// Read a standard record at a physical offset and verify its BRCrc32 with
/// the CRC field (bytes 8..12) zeroed.
bool load_record(const AdiFile& file, uint64_t off, Header* out,
                 std::vector<uint8_t>* raw) {
    const auto h = file.read_vec(off, kStdHdr);
    if (h.size() < kStdHdr) {
        return false;
    }
    const uint32_t size = u32(h, 4);
    if (size < kStdHdr || size > kMaxRecord || off + size > file.file_size()) {
        return false;
    }
    auto rec = file.read_vec(off, size);
    if (rec.size() < size) {
        return false;
    }
    std::vector<uint8_t> check = rec;
    std::fill(check.begin() + 8, check.begin() + 12, 0);
    if (br_crc32(check.data(), check.size()) != u32(h, 8)) {
        return false;
    }
    if (out) {
        *out = Header{off, u32(h, 0)};
    }
    if (raw) {
        *raw = std::move(rec);
    }
    return true;
}

bool is_standard_type(uint32_t t) {
    return t == kVolumeIndex || t == kDataBlockIndex || t == kMetadata ||
           t == kCompress || t == kEncrypt || t == kRegion;
}

std::vector<Header> scan_headers_range(const AdiFile& file, uint64_t from, uint64_t to) {
    std::vector<uint64_t> candidates;
    const uint64_t end = std::min<uint64_t>(to, file.file_size());
    std::vector<uint8_t> buf(kChunk + kOverlap);
    uint64_t at = from;
    while (at < end) {
        const size_t want =
            static_cast<size_t>(std::min<uint64_t>(kChunk + kOverlap, end - at));
        if (want <= kOverlap) {
            break;
        }
        file.read(at, buf.data(), want);
        const size_t limit = want - kOverlap;
        for (size_t i = 0; i + 4 <= limit; ++i) {
            if (is_standard_type(rd32(buf.data() + i))) {
                candidates.push_back(at + i);
            }
        }
        at += limit;
    }
    std::vector<Header> out;
    for (uint64_t off : candidates) {
        Header h;
        if (load_record(file, off, &h, nullptr)) {
            out.push_back(h);
        }
    }
    return out;
}

std::vector<Header> scan_headers(const AdiFile& file) {
    return scan_headers_range(file, 0, file.file_size());
}

bool parse_data_block_index(const Header& h, const std::vector<uint8_t>& raw,
                            DataBlockIndex* out) {
    if (h.rec_type != kDataBlockIndex || raw.size() < 0x24 || u32(raw, 0x18) != kVdbSize) {
        return false;
    }
    const uint32_t count = u32(raw, 0x10);
    const uint64_t refs_end = 0x24ull + static_cast<uint64_t>(count) * 0x10;
    if (refs_end > raw.size()) {
        return false;
    }
    DataBlockIndex idx;
    idx.off = h.off;
    idx.entry_count = u32(raw, 0x14);
    uint64_t total = 0;
    for (uint64_t p = 0x24; p < refs_end; p += 0x10) {
        DataBlockRef r;
        r.data_offset = u64(raw, static_cast<size_t>(p));
        r.data_size = u32(raw, static_cast<size_t>(p) + 8);
        r.entry_count = u32(raw, static_cast<size_t>(p) + 12);
        total += r.entry_count;
        idx.refs.push_back(r);
    }
    if (total > idx.entry_count) {
        return false;
    }
    *out = std::move(idx);
    return true;
}

bool parse_directory_index(const Header& h, const std::vector<uint8_t>& raw,
                           DirectoryIndex* out) {
    if (h.rec_type != kVolumeIndex || raw.size() < 0x14) {
        return false;
    }
    const uint32_t count = u32(raw, 0x10);
    const uint64_t end = 0x14ull + static_cast<uint64_t>(count) * 0x10;
    if (end > raw.size()) {
        return false;
    }
    DirectoryIndex dir;
    dir.off = h.off;
    for (uint64_t p = 0x14; p < end; p += 0x10) {
        dir.entries.push_back(DirEntry{u32(raw, static_cast<size_t>(p)),
                                       u64(raw, static_cast<size_t>(p) + 8)});
    }
    *out = std::move(dir);
    return true;
}

bool parse_region(const Header& h, const std::vector<uint8_t>& raw, Region* out) {
    if (h.rec_type != kRegion || raw.size() < 0x30) {
        return false;
    }
    auto v = [&](size_t i) { return u32(raw, 0x10 + i * 4); };
    Region r;
    r.off = h.off;
    r.reg_no = v(0);
    r.block_begin_sector = static_cast<uint64_t>(v(1)) |
                           (static_cast<uint64_t>(v(2)) << 32);
    r.total_sectors = static_cast<uint64_t>(v(3)) |
                      (static_cast<uint64_t>(v(4)) << 32);
    r.clusters_per_block = v(5);
    r.sectors_per_cluster = v(6);
    r.bytes_per_sector = v(7);
    if (!r.clusters_per_block || r.clusters_per_block > 4096 ||
        !r.sectors_per_cluster || r.bytes_per_sector < 512 ||
        r.bytes_per_sector > 4096) {
        return false;
    }
    *out = r;
    return true;
}

bool parse_metadata(const Header& h, const std::vector<uint8_t>& raw, Metadata* out) {
    if (h.rec_type != kMetadata || raw.size() < 0x28) {
        return false;
    }
    Metadata m;
    m.off = h.off;
    m.bytes_per_sector = u32(raw, 0x14);
    m.partition_start_sector = u64(raw, 0x18);
    m.partition_total_sectors = u64(raw, 0x20);
    m.label = txt(raw, 0x34, 0x7c);
    m.description = txt(raw, 0x12a, 0x46);
    auto copy_guid = [&](uint8_t* dst, size_t off) {
        if (off + 16 <= raw.size()) {
            std::copy(raw.begin() + static_cast<std::ptrdiff_t>(off),
                      raw.begin() + static_cast<std::ptrdiff_t>(off + 16), dst);
        }
    };
    copy_guid(m.type_guid, 0x172);
    copy_guid(m.unique_guid, 0x182);
    *out = std::move(m);
    return true;
}

bool parse_mode(const Header& h, const std::vector<uint8_t>& raw, uint32_t* out) {
    if ((h.rec_type != kCompress && h.rec_type != kEncrypt) || raw.size() < 0x18) {
        return false;
    }
    *out = u32(raw, 0x14);
    return true;
}

VdbEntry parse_vdb(const std::vector<uint8_t>& raw, size_t p) {
    VdbEntry e;
    e.reg_no = u32(raw, p);
    e.block_no = u64(raw, p + 4);
    e.img_offset = u64(raw, p + 0x0c);
    e.old_size = u32(raw, p + 0x14);
    e.new_size = u32(raw, p + 0x18);
    e.crc = u32(raw, p + 0x1c);
    return e;
}

bool shifted(uint64_t logical, int64_t delta, uint64_t* out) {
    if (delta >= 0) {
        const uint64_t d = static_cast<uint64_t>(delta);
        if (logical > UINT64_MAX - d) {
            return false;
        }
        *out = logical + d;
        return true;
    }
    // Magnitude of INT64_MIN without overflowing.
    const uint64_t d = static_cast<uint64_t>(-(delta + 1)) + 1;
    if (logical < d) {
        return false;
    }
    *out = logical - d;
    return true;
}

std::string hexstr(uint64_t v) {
    std::ostringstream o;
    o << "0x" << std::hex << v;
    return o.str();
}

struct Set {
    uint64_t volume_off = 0;
    uint64_t data_block_off = 0;
    int64_t delta = 0;
    uint32_t entry_count = 0;
    std::vector<Region> regions;
    std::vector<Metadata> metadata;
    bool have_compress = false;
    bool have_encrypt = false;
    uint32_t compress_mode = 0;
    uint32_t encrypt_mode = 0;
    std::vector<VdbEntry> entries;
};

std::vector<Set> build_sets(const AdiFile& file, const std::vector<Header>& headers) {
    std::vector<DataBlockIndex> data_blocks;
    for (const auto& h : headers) {
        if (h.rec_type != kDataBlockIndex) {
            continue;
        }
        std::vector<uint8_t> raw;
        if (!load_record(file, h.off, nullptr, &raw)) {
            continue;
        }
        DataBlockIndex idx;
        if (parse_data_block_index(h, raw, &idx)) {
            data_blocks.push_back(std::move(idx));
        } else {
            adi::debug_log() << "  warning: malformed CRC-valid 0x202 at " << hexstr(h.off)
                      << "; ignored; verify completeness\n";
        }
    }
    std::map<uint64_t, std::vector<size_t>> by_payload_end;
    for (size_t i = 0; i < data_blocks.size(); ++i) {
        for (const auto& r : data_blocks[i].refs) {
            by_payload_end[r.data_offset + r.data_size].push_back(i);
        }
    }
    uint32_t global_compress = 0;
    uint32_t global_encrypt = 0;
    bool have_global_compress = false;
    bool have_global_encrypt = false;
    for (const auto& h : headers) {
        if (h.rec_type != kCompress && h.rec_type != kEncrypt) {
            continue;
        }
        std::vector<uint8_t> raw;
        uint32_t mode = 0;
        if (!load_record(file, h.off, nullptr, &raw) || !parse_mode(h, raw, &mode)) {
            continue;
        }
        if (h.rec_type == kCompress && !have_global_compress) {
            global_compress = mode;
            have_global_compress = true;
        }
        if (h.rec_type == kEncrypt && !have_global_encrypt) {
            global_encrypt = mode;
            have_global_encrypt = true;
        }
    }

    std::vector<Set> sets;
    for (const auto& h : headers) {
        if (h.rec_type != kVolumeIndex) {
            continue;
        }
        std::vector<uint8_t> raw;
        if (!load_record(file, h.off, nullptr, &raw)) {
            continue;
        }
        DirectoryIndex dir;
        if (!parse_directory_index(h, raw, &dir)) {
            adi::debug_log() << "  warning: malformed CRC-valid 0x201 at " << hexstr(h.off)
                      << "; ignored; verify completeness\n";
            continue;
        }
        const DirEntry* db_entry = nullptr;
        size_t db_count = 0;
        for (const auto& e : dir.entries) {
            if (e.rec_type == kDataBlockIndex) {
                db_entry = &e;
                ++db_count;
            }
        }
        if (db_count != 1) {
            adi::debug_log() << "  warning: volume index " << hexstr(h.off)
                      << ": expected one 0x202 reference; skipped; verify output\n";
            continue;
        }
        const auto it = by_payload_end.find(db_entry->offset);
        if (it == by_payload_end.end()) {
            adi::debug_log() << "  warning: volume index " << hexstr(h.off)
                      << ": no matching 0x202; skipped; verify output\n";
            continue;
        }
        for (size_t mi : it->second) {
            const DataBlockIndex& dbi = data_blocks[mi];
            const int64_t delta = static_cast<int64_t>(dbi.off) -
                                  static_cast<int64_t>(db_entry->offset);
            Set set;
            set.volume_off = dir.off;
            set.data_block_off = dbi.off;
            set.delta = delta;
            set.entry_count = dbi.entry_count;
            bool ok = true;
            for (const auto& e : dir.entries) {
                if (e.rec_type == kDataBlockIndex) {
                    continue;
                }
                uint64_t phys = 0;
                if (!shifted(e.offset, delta, &phys)) {
                    ok = false;
                    break;
                }
                Header rh;
                std::vector<uint8_t> rraw;
                if (!load_record(file, phys, &rh, &rraw) || rh.rec_type != e.rec_type) {
                    ok = false;
                    break;
                }
                if (e.rec_type == kRegion) {
                    Region r;
                    if (!parse_region(rh, rraw, &r)) {
                        ok = false;
                        break;
                    }
                    set.regions.push_back(r);
                } else if (e.rec_type == kMetadata) {
                    Metadata m;
                    if (parse_metadata(rh, rraw, &m)) {
                        set.metadata.push_back(std::move(m));
                    } else {
                        adi::debug_log() << "  warning: malformed 0x102 at " << hexstr(phys)
                                  << "; ignored; verify metadata\n";
                    }
                } else if (e.rec_type == kCompress) {
                    uint32_t mode = 0;
                    if (parse_mode(rh, rraw, &mode)) {
                        set.compress_mode = mode;
                        set.have_compress = true;
                    } else {
                        adi::debug_log() << "  warning: malformed 0x105 at " << hexstr(phys)
                                  << "; mode unknown; verify output\n";
                    }
                } else if (e.rec_type == kEncrypt) {
                    uint32_t mode = 0;
                    if (parse_mode(rh, rraw, &mode)) {
                        set.encrypt_mode = mode;
                        set.have_encrypt = true;
                    } else {
                        adi::debug_log() << "  warning: malformed 0x106 at " << hexstr(phys)
                                  << "; mode unknown; verify output\n";
                    }
                } else {
                    adi::debug_log() << "  warning: unknown referenced record type " << hexstr(e.rec_type)
                              << " at " << hexstr(phys) << "; ignored; output needs verification\n";
                }
            }
            if (!ok || set.regions.empty()) {
                adi::debug_log() << "  warning: volume index " << hexstr(h.off)
                          << ": invalid, unreadable or checksum-invalid referenced record, or "
                             "missing regions; candidate skipped; verify output\n";
                continue;
            }
            if ((!set.have_compress && have_global_compress) ||
                (!set.have_encrypt && have_global_encrypt))
                adi::debug_log()
                    << "  warning: volume index " << hexstr(h.off)
                    << ": mode taken from an unassociated global record; verify applicability\n";
            if (!set.have_compress && have_global_compress) {
                set.compress_mode = global_compress;
                set.have_compress = true;
            }
            if (!set.have_encrypt && have_global_encrypt) {
                set.encrypt_mode = global_encrypt;
                set.have_encrypt = true;
            }
            for (const auto& ref : dbi.refs) {
                uint64_t phys = 0;
                const size_t want = std::min<size_t>(
                    ref.data_size, static_cast<size_t>(ref.entry_count) * kVdbSize);
                if (!shifted(ref.data_offset, delta, &phys) || want == 0 ||
                    phys + want > file.file_size()) {
                    ok = false;
                    break;
                }
                if (want != static_cast<size_t>(ref.entry_count) * kVdbSize || want % kVdbSize != 0)
                    adi::debug_log() << "  warning: VDB reference at " << hexstr(phys)
                              << ": truncated/misaligned table length; entries may be skipped; "
                                 "verify completeness\n";
                const auto table = file.read_vec(phys, want);
                if (table.size() < want) {
                    ok = false;
                    break;
                }
                for (size_t p = 0; p + kVdbSize <= want; p += kVdbSize) {
                    set.entries.push_back(parse_vdb(table, p));
                }
            }
            if (!ok || set.entries.empty()) {
                adi::debug_log() << "  warning: volume index " << hexstr(h.off)
                          << ": invalid or empty VDB table; candidate skipped; verify output\n";
                continue;
            }
            if (set.entries.size() != dbi.entry_count)
                adi::debug_log() << "  warning: VDB count differs from declared count/capacity; verify "
                             "completeness\n";
            sets.push_back(std::move(set));
        }
    }
    return sets;
}

/// Structural sanity gate for the tail scan. A set that passes is one the
/// parser could have produced from a complete record block: the declared VDB
/// count is what was read, every entry addresses stored bytes inside the image
/// set, and at least one entry is the first block of a region. A set that
/// fails sends the caller through the exhaustive scan, so a false negative
/// only costs time.
bool set_is_plausible(const AdiFile& file, const Set& set) {
    if (set.entries.empty() || set.regions.empty()) {
        return false;
    }
    if (set.entries.size() != set.entry_count || set.metadata.empty()) {
        return false;
    }
    uint64_t logical_end = 0;
    for (const auto& m : file.image_set().members()) {
        logical_end = std::max(logical_end, m.logical_start + m.data_length);
    }
    if (logical_end == 0) {
        return false;
    }
    bool first_block = false;
    for (const auto& e : set.entries) {
        if (e.old_size == 0 || e.new_size == 0) {
            return false;
        }
        if (e.img_offset > logical_end || e.new_size > logical_end - e.img_offset) {
            return false;
        }
        if (e.block_no == 0) {
            first_block = true;
        }
    }
    return first_block;
}

std::vector<Set> find_sets(const AdiFile& file) {
    // Reading the whole file to find a record block that is normally in the
    // last few kilobytes costs a full pass over the image (70 s for 70 GiB at
    // 1 GB/s) before the first output byte. Search the tail first and accept
    // it only when it yields exactly one complete, self-consistent record set;
    // otherwise fall back to the exhaustive scan, which is what older images
    // and unusual layouts get. ADI_EXTRACT_FULL_SCAN=1 forces that scan.
    if (std::getenv("ADI_EXTRACT_FULL_SCAN") == nullptr && file.file_size() > kTailWindow) {
        const auto headers =
            scan_headers_range(file, file.file_size() - kTailWindow, file.file_size());
        size_t indexes = 0;
        for (const auto& h : headers) {
            if (h.rec_type == kVolumeIndex) {
                ++indexes;
            }
        }
        std::vector<Set> sets = build_sets(file, headers);
        if (indexes == 1 && sets.size() == 1 && set_is_plausible(file, sets[0])) {
            adi::debug_log() << "  trace: record scan: last " << kTailWindow << " bytes of "
                             << file.file_size() << " (one 0x201, complete set)\n";
            return sets;
        }
        adi::debug_log() << "  trace: record scan: last " << kTailWindow << " bytes gave "
                         << indexes << " 0x201 record(s) and " << sets.size()
                         << " usable set(s); scanning the whole file\n";
    }
    adi::debug_log() << "  trace: record scan: whole file (" << file.file_size() << " bytes)\n";
    return build_sets(file, scan_headers(file));
}

}  // namespace

namespace {

std::string probe_volume_boot_1(const AdiFile& file, const std::vector<StdBlock>& blocks,
                                uint64_t volume_start);

std::string label_fs(const std::string& label) {
    std::string upper = label;
    std::transform(upper.begin(), upper.end(), upper.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return upper.find("ESP") != std::string::npos || upper.find("EFI") != std::string::npos
               ? "FAT32"
               : "NTFS";
}

/// Decode the block that stores the volume's first cluster and read its boot
/// sector. Empty string when that block is absent, undecodable, or does not
/// start with a recognisable boot sector.
std::string probe_volume_boot(const AdiFile& file, const std::vector<StdBlock>& blocks,
                              uint64_t volume_start) {
    try {
        return probe_volume_boot_1(file, blocks, volume_start);
    } catch (const std::exception&) {
        return {};   // a missing image-set member must not abort discovery
    }
}

std::string probe_volume_boot_1(const AdiFile& file, const std::vector<StdBlock>& blocks,
                                uint64_t volume_start) {
    const StdBlock* first = nullptr;
    for (const StdBlock& b : blocks) {
        if (b.block_no != 0 || b.base != volume_start || b.cluster == 0 || b.bitmap_len == 0) {
            continue;
        }
        if (!first || b.off < first->off) {
            first = &b;
        }
    }
    if (!first) {
        return {};
    }
    const auto comp = file.read_logical_vec(first->off, first->csize);
    if (comp.empty() && first->csize != 0) {
        return {};
    }
    const std::vector<BlockRec> none;
    Lz4Stream dec(file, none);
    const uint8_t* data = nullptr;
    size_t n = 0;
    if (first->csize == first->usize) {
        data = comp.data();
        n = comp.size();
    } else if (!dec.decode_buffer(comp.data(), comp.size(), first->usize, &data, &n)) {
        return {};
    }
    if (n != first->usize || n < first->bitmap_len + 512 || (data[0] & 1) == 0) {
        return {};
    }
    BootSector bs;
    if (!parse_boot_sector(data + first->bitmap_len, n - first->bitmap_len, &bs)) {
        return {};
    }
    return bs.fs;
}

std::pair<uint64_t, uint64_t> decode_and_check_1(const AdiFile& file, const StandardImage& s,
                                                 size_t index) {
    if (index >= s.blocks.size()) {
        return {0, 0};
    }
    const StdBlock& b = s.blocks[index];
    if (b.crc == 0) {
        return {0, 0};
    }
    const auto comp = file.read_logical_vec(b.off, b.csize);
    const std::vector<BlockRec> none;
    Lz4Stream dec(file, none);
    const uint8_t* data = nullptr;
    size_t n = 0;
    if (b.csize == b.usize) {
        data = comp.data();
        n = comp.size();
    } else if (!dec.decode_buffer(comp.data(), comp.size(), b.usize, &data, &n)) {
        return {0, 0};
    }
    if (n != b.usize) {
        return {0, 0};
    }
    return {1, br_crc32(data, n) == b.crc ? 0u : 1u};
}

/// An unreadable block (for example one that lives in a missing image-set
/// member) counts as unchecked, not as an error: `info` must not fail because a
/// sample could not be read.
std::pair<uint64_t, uint64_t> decode_and_check(const AdiFile& file, const StandardImage& s,
                                               size_t index) {
    try {
        return decode_and_check_1(file, s, index);
    } catch (const std::exception&) {
        return {0, 0};
    }
}

}  // namespace

std::pair<uint64_t, uint64_t> verify_standard_sample(const AdiFile& file,
                                                     const StandardImage& std_img, size_t k) {
    const size_t total = std_img.blocks.size();
    if (total == 0 || k == 0) {
        return {0, 0};
    }
    uint64_t checked = 0;
    uint64_t bad = 0;
    const size_t step = total <= k ? 1 : total / k;
    for (size_t i = 0; i < total && (total <= k ? true : checked + bad < k * 4); i += step) {
        const auto r = decode_and_check(file, std_img, i);
        checked += r.first;
        bad += r.second;
        if (total > k && (i + step) / step > k) {
            break;
        }
    }
    return {checked, bad};
}

std::optional<StandardImage> parse_standard(const AdiFile& file, std::ostream& progress) {
    const std::vector<Set> sets = find_sets(file);
    if (sets.empty()) {
        return std::nullopt;
    }
    adi::debug_log() << "  warning: output uses a reconstructed GPT/disk extent, not a verified copy of "
                 "the original partition table; verify layout and filesystem before use\n";
    StandardImage out;
    for (const Set& set : sets) {
        RecordSetInfo info;
        info.volume_index_off = set.volume_off;
        info.data_block_index_off = set.data_block_off;
        info.delta = set.delta;
        info.entry_count = set.entry_count;
        if ((set.have_compress && set.compress_mode > 1) ||
            (set.have_encrypt && set.encrypt_mode != 0))
            adi::debug_log() << "  warning: unsupported compression/encryption mode; extraction is not "
                         "verified/supported for this set\n";
        const bool have_meta = !set.metadata.empty();
        if (set.metadata.size() != 1)
            adi::debug_log() << "  warning: metadata missing or ambiguous at volume index "
                      << hexstr(set.volume_off)
                      << "; using first or default LBA 0/512-byte sectors; verify placement\n";
        if (have_meta &&
            (set.metadata[0].bytes_per_sector < 512 || set.metadata[0].bytes_per_sector > 4096))
            adi::debug_log() << "  warning: invalid metadata sector size; assuming 512 bytes; verify "
                         "placement\n";
        if (!set.have_compress || !set.have_encrypt)
            adi::debug_log() << "  warning: missing compression/encryption mode; assuming LZ4 for "
                         "compressed blocks and no encryption; verify output\n";
        if ((out.have_compress && set.have_compress && out.compress_mode != set.compress_mode) ||
            (out.have_encrypt && set.have_encrypt && out.encrypt_mode != set.encrypt_mode))
            adi::debug_log() << "  warning: conflicting volume modes; last mode retained; output needs "
                         "verification\n";
        const uint64_t bps = have_meta && set.metadata[0].bytes_per_sector >= 512 &&
                                     set.metadata[0].bytes_per_sector <= 4096
                                 ? set.metadata[0].bytes_per_sector
                                 : 512;
        if (bps != 512)
            adi::debug_log() << "  warning: non-512-byte metadata sectors with 512-byte output GPT "
                         "addressing; layout needs further verification\n";
        const uint64_t part_start =
            have_meta ? set.metadata[0].partition_start_sector : 0;
        const uint64_t part_sectors =
            have_meta ? set.metadata[0].partition_total_sectors : 0;
        const std::string label = have_meta ? set.metadata[0].label : std::string();
        const std::string description =
            have_meta ? set.metadata[0].description : std::string();
        uint64_t region_end = 0;
        for (const Region& r : set.regions) {
            region_end = std::max(region_end, r.block_begin_sector + r.total_sectors);
        }
        if (part_sectors < region_end)
            adi::debug_log() << "  warning: partition length absent/shorter than region extent; expanding "
                         "from region geometry; verify partition bounds\n";
        const uint64_t sectors =
            std::max<uint64_t>({part_sectors, region_end, 1});
        const uint32_t cluster = set.regions.empty()
                                     ? 512
                                     : static_cast<uint32_t>(set.regions[0].cluster());

        std::map<uint32_t, Region> region_map;
        for (const Region& r : set.regions) {
            if (region_map.count(r.reg_no))
                adi::debug_log() << "  warning: duplicate region " << r.reg_no
                          << "; last geometry retained; verify output\n";
            if (r.bytes_per_sector != bps)
                adi::debug_log()
                    << "  warning: region and metadata sector sizes differ; verify placement\n";
            region_map[r.reg_no] = r;
            std::ostringstream o;
            o << "region " << r.reg_no << ": LBA " << r.block_begin_sector << " + "
              << r.total_sectors << " sectors, " << r.clusters_per_block
              << " clusters/block x " << r.sectors_per_cluster
              << " sectors/cluster x " << r.bytes_per_sector << " B (0x109 @ "
              << hexstr(r.off) << ")";
            info.regions.push_back(o.str());
        }
        for (const Metadata& m : set.metadata) {
            std::ostringstream o;
            o << "metadata: LBA " << m.partition_start_sector << ", "
              << m.partition_total_sectors << " sectors, " << m.bytes_per_sector
              << " B/sector, label '" << m.label << "' '" << m.description
              << "' (0x102 @ " << hexstr(m.off) << ")";
            info.metadata.push_back(o.str());
        }
        out.sets.push_back(std::move(info));

        std::vector<uint32_t> region_clusters;
        for (const Region& r : set.regions) {
            region_clusters.push_back(static_cast<uint32_t>(r.cluster()));
        }
        std::sort(region_clusters.begin(), region_clusters.end());
        region_clusters.erase(std::unique(region_clusters.begin(), region_clusters.end()),
                              region_clusters.end());
        StdVolume vol;
        vol.label = label;
        vol.region_clusters = region_clusters;
        vol.part_name = label.empty() ? description : label;
        vol.lba = part_start;
        vol.sectors = sectors;
        vol.cluster = cluster;
        vol.blocks = 0;
        if (have_meta) {
            std::copy(set.metadata[0].type_guid, set.metadata[0].type_guid + 16,
                      vol.type_guid);
            std::copy(set.metadata[0].unique_guid, set.metadata[0].unique_guid + 16,
                      vol.unique_guid);
        }
        if (std::all_of(std::begin(vol.type_guid), std::end(vol.type_guid),
                        [](uint8_t b) { return b == 0; }) ||
            std::all_of(std::begin(vol.unique_guid), std::end(vol.unique_guid),
                        [](uint8_t b) { return b == 0; }))
            adi::debug_log() << "  warning: missing partition GUIDs; GPT uses a label-inferred type "
                         "and/or generated identity; verify partition metadata\n";
        if (set.have_compress) {
            out.have_compress = true;
            out.compress_mode = set.compress_mode;
        }
        if (set.have_encrypt) {
            out.have_encrypt = true;
            out.encrypt_mode = set.encrypt_mode;
        }
        const size_t set_block_start = out.blocks.size();
        for (const VdbEntry& e : set.entries) {
            const auto it = region_map.find(e.reg_no);
            if (it == region_map.end() || e.old_size == 0 || e.new_size == 0) {
                adi::debug_log()
                    << "  warning: VDB entry at logical " << hexstr(e.img_offset) << ", region "
                    << e.reg_no
                    << ": missing region or invalid sizes; skipped; output needs verification\n";
                ++out.skipped_regions;
                continue;
            }
            const Region& r = it->second;
            const uint64_t base =
                (part_start + r.block_begin_sector +
                 e.block_no * r.sectors_per_region()) *
                bps;
            StdBlock b;
            b.off = e.img_offset;
            b.reg_no = e.reg_no;
            b.block_no = e.block_no;
            b.usize = e.old_size;
            b.csize = e.new_size;
            b.crc = e.crc;
            b.base = base;
            b.cluster = static_cast<uint32_t>(r.cluster());
            b.bitmap_len = r.bitmap_len();
            b.clusters_per_block = r.clusters_per_block;
            const uint64_t block_sector = e.block_no * r.sectors_per_region();
            b.region_remaining = block_sector < r.total_sectors
                ? (r.total_sectors - block_sector) * bps : 0;
            out.blocks.push_back(b);
            ++vol.blocks;
        }
        // The volume's first cluster holds its boot sector, which names the real
        // filesystem. The label heuristic is only a fallback: it calls everything
        // NTFS unless the label says ESP/EFI, which is wrong for FAT cards.
        const std::vector<StdBlock> set_blocks(out.blocks.begin() + set_block_start,
                                               out.blocks.end());
        std::string fs = probe_volume_boot(file, set_blocks, part_start * bps);
        vol.fs_detected = !fs.empty();
        if (!vol.fs_detected) {
            adi::debug_log() << "  warning: volume at LBA " << part_start
                             << ": boot sector not recoverable; filesystem '"
                             << label_fs(label) << "' is inferred from the label; verify output\n";
            fs = label_fs(label);
        }
        vol.fs = fs;
        out.volumes.push_back(std::move(vol));
    }
    const auto unchecked = std::count_if(out.blocks.begin(), out.blocks.end(),
                                         [](const StdBlock &b) { return b.crc == 0; });
    if (unchecked)
        adi::debug_log() << "  warning: " << unchecked
                  << " VDB blocks have no decoded checksum; contents need verification\n";
    if (out.blocks.empty()) {
        return std::nullopt;
    }
    std::sort(out.blocks.begin(), out.blocks.end(),
              [](const StdBlock& a, const StdBlock& b) {
                  return a.base == b.base ? a.off < b.off : a.base < b.base;
              });
    uint64_t covered_end = 0;
    for (const auto &b : out.blocks) {
        if (b.base < covered_end)
            adi::debug_log() << "  warning: overlapping VDB block extents at output " << hexstr(b.base)
                      << "; write precedence needs verification\n";
        const uint64_t span = std::min<uint64_t>(
            b.region_remaining, static_cast<uint64_t>(b.clusters_per_block) * b.cluster);
        covered_end = std::max(covered_end, b.base + span);
    }
    uint64_t end = 0;
    for (const auto& v : out.volumes) {
        end = std::max(end, v.lba + v.sectors);
    }
    for (const auto& b : out.blocks) {
        const uint64_t tail = b.base + static_cast<uint64_t>(b.clusters_per_block) *
                                           b.cluster;
        end = std::max(end, (tail + 511) / 512);
    }
    out.disk_sectors = std::max<uint64_t>(end + 34, 68);
    progress << "  standard record path: " << out.sets.size() << " volume set(s), "
             << out.blocks.size() << " VDB entries\n";
    return out;
}

std::string cluster_label(const std::vector<uint32_t>& region_clusters, uint32_t fallback) {
    if (region_clusters.empty()) return std::to_string(fallback);
    if (region_clusters.size() == 1) return std::to_string(region_clusters[0]);
    std::string out = "mixed (";
    for (size_t k = 0; k < region_clusters.size(); ++k) {
        if (k) out += ", ";
        out += std::to_string(region_clusters[k]);
    }
    return out + ")";
}

void print_standard_info(const StandardImage& s, std::ostream& out, const AdiFile* file) {
    out << "\n[standard records]\n";
    out << "  volume record sets: " << s.sets.size() << "\n";
    for (size_t i = 0; i < s.sets.size(); ++i) {
        const auto& set = s.sets[i];
        out << "  set " << i << ": 0x201 @ " << hexstr(set.volume_index_off)
            << ", 0x202 @ " << hexstr(set.data_block_index_off)
            << ", delta " << hexstr(static_cast<uint64_t>(set.delta)) << ", "
            << set.entry_count << " VDB entries\n";
        for (const auto& line : set.regions) {
            out << "    " << line << "\n";
        }
        for (const auto& line : set.metadata) {
            out << "    " << line << "\n";
        }
    }
    out << "  modes:      compress "
        << (s.have_compress ? std::to_string(s.compress_mode) : "unknown")
        << ", encrypt "
        << (s.have_encrypt ? std::to_string(s.encrypt_mode) : "unknown") << "\n";
    uint64_t crcs = 0;
    for (const auto& b : s.blocks) {
        if (b.crc != 0) {
            ++crcs;
        }
    }
    out << "  crcs:       " << crcs << " blocks carry a BRCrc32 checksum\n";
    if (crcs != 0 && file != nullptr) {
        // info used to print the checksum count without ever testing one.
        const auto [checked, bad] = verify_standard_sample(*file, s, 16);
        out << "  verified:  " << checked << " of " << crcs << " decoded blocks checked, "
            << bad << (bad == 1 ? " mismatch, " : " mismatches, ")
            << (crcs > checked ? crcs - checked : 0)
            << " unchecked (reconstruct verifies every block)\n";
    }
    if (s.skipped_regions) {
        out << "  skipped:    " << s.skipped_regions
            << " VDB entries with no matching region\n";
    }
    out << "\n[volumes]\n";
    for (size_t i = 0; i < s.volumes.size(); ++i) {
        const auto& v = s.volumes[i];
        out << "  v" << i << " " << v.fs << (v.fs_detected ? "" : "?") << " lba " << v.lba
            << ", " << v.sectors << " sectors, cluster "
            << cluster_label(v.region_clusters, v.cluster) << ", " << v.blocks
            << " blocks, label '" << v.label << "'\n";
    }
    for (const auto& v : s.volumes) {
        if (!v.fs_detected) {
            out << "  ('?' = filesystem guessed from the label; its boot sector was not "
                   "recoverable)\n";
            break;
        }
    }
    out << "\n[raw image]\n";
    out << "  disk:      " << s.disk_sectors << " sectors\n";
    out << "  size:      " << s.disk_sectors * 512 << " bytes ("
        << std::fixed << std::setprecision(2)
        << (static_cast<double>(s.disk_sectors) * 512.0 / 1024.0 / 1024.0 / 1024.0)
        << " GiB)\n";
    uint64_t inversions = 0;
    for (size_t i = 1; i < s.blocks.size(); ++i) {
        if (s.blocks[i].base < s.blocks[i - 1].base) {
            ++inversions;
        }
    }
    out << "\n[plan]\n";
    out << "  blocks: " << s.blocks.size()
        << " in disk order: " << (inversions ? "no" : "yes") << "\n";
}

}  // namespace adi
