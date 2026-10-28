#include "diagnostics.hpp"
#include "codec.hpp"
#include <iostream>

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <map>
#include <ostream>
#include <utility>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifdef _WIN32
#include <windows.h>
#else
#include "win32_shim.hpp"
#endif

namespace adi {
namespace {

constexpr std::array<uint32_t, 256> make_br_table() {
    std::array<uint32_t, 256> t{};
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int k = 0; k < 8; ++k) {
            c = (c & 1u) ? ((c >> 1) ^ 0x82F63B78u) : (c >> 1);
        }
        t[i] = c;
    }
    return t;
}

uint16_t rd16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (p[1] << 8));
}

uint32_t rd32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t rd64(const uint8_t* p) {
    return static_cast<uint64_t>(rd32(p)) | (static_cast<uint64_t>(rd32(p + 4)) << 32);
}

std::string trim_ascii(const uint8_t* p, size_t n) {
    std::string s;
    for (size_t i = 0; i < n; ++i) {
        s.push_back(p[i] >= 0x20 && p[i] < 0x7f ? static_cast<char>(p[i]) : ' ');
    }
    while (!s.empty() && s.back() == ' ') {
        s.pop_back();
    }
    return s;
}

static_assert(sizeof(BlockRec) == 32, "BlockRec is cached as a raw array");

const uint8_t kPopcount[256] = {
    0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8};

constexpr size_t kRec = 32;
constexpr uint32_t kMaxUsize = 1u << 20;
constexpr uint32_t kMaxCsize = 16u << 20;

BlockRec parse_rec(const uint8_t* p) {
    BlockRec r;
    r.off = rd64(p);
    r.usize = rd32(p + 8);
    r.csize = rd32(p + 12);
    r.crc = rd32(p + 16);
    r.stream = rd32(p + 20);
    r.region = rd32(p + 24);
    return r;
}

bool plausible_rec(const uint8_t* p, uint64_t payload_span) {
    if (rd32(p + 28) != 0) {
        return false;
    }
    const uint32_t usize = rd32(p + 8);
    const uint32_t csize = rd32(p + 12);
    if (usize < 0x20 || usize > kMaxUsize || csize < 0x10 || csize > kMaxCsize) {
        return false;
    }
    if (rd32(p + 20) > 0xffff) {
        return false;
    }
    return rd64(p) < payload_span;
}

}  // namespace

uint32_t br_crc32(const uint8_t* p, size_t n) {
    static constexpr std::array<uint32_t, 256> kTable = make_br_table();
    uint32_t crc = 0;
    for (size_t i = 0; i < n; ++i) {
        crc = (crc >> 8) ^ kTable[(crc ^ p[i]) & 0xFFu];
    }
    return ~crc;
}

std::vector<BlockRec> scan_block_index(const AdiFile& file, std::ostream& progress) {
    const uint64_t start = file.payload_offset();
    const uint64_t end = file.payload_end();
    const uint64_t span = end - start;

    std::map<uint64_t, BlockRec> found;
    constexpr size_t kChunk = 32u << 20;
    constexpr size_t kOver = 2 * kRec;
    std::vector<uint8_t> buf(kChunk + kOver);
    uint64_t at = start;
    uint64_t next_note = start + (2ull << 30);
    while (at < end) {
        const size_t want = static_cast<size_t>(std::min<uint64_t>(kChunk + kOver, end - at));
        file.read(at, buf.data(), want);
        if (want <= kOver) {
            break;
        }
        const size_t limit = want - kOver;
        for (size_t i = 0; i < limit; ++i) {
            const uint8_t* p = buf.data() + i;
            if (rd32(p + 28) != 0 || !plausible_rec(p, span)) {
                continue;
            }
            const uint8_t* q = p + kRec;
            if (!plausible_rec(q, span)) {
                continue;
            }
            const BlockRec a = parse_rec(p);
            const BlockRec b = parse_rec(q);
            if (a.end() != b.off) {
                continue;
            }
            found.emplace(a.off, a);
            found.emplace(b.off, b);
        }
        at += limit;
        if (at >= next_note) {
            progress << "  index scan " << ((at - start) >> 30) << " GiB, " << found.size()
                     << " records\n";
            progress.flush();
            next_note += 2ull << 30;
        }
    }
    std::vector<BlockRec> out;
    out.reserve(found.size());
    uint64_t chain_end = 0;
    uint64_t dropped = 0;
    for (const auto& kv : found) {
        if (kv.second.off < chain_end) {
            ++dropped;
            continue;
        }
        chain_end = kv.second.end();
        out.push_back(kv.second);
    }
    if (dropped) {
        progress << "  dropped " << dropped << " overlapping records\n";
    }
    resolve_regions(out, progress);
    return out;
}

// The 32-byte window found by signature is a real VDB index entry read 12
// bytes late: its RegNo/BlockNo fields describe the *next* block, not the one
// at `off`. So block i's region/stream is the stored value from record i-1,
// and the very first block has no predecessor.
//
// The old implementation split the chain at gaps and then invented the
// "lowest free" region number for every run head. On a real multi-volume
// image those heads start at high block numbers, so inventing 0 made the
// resolved regions jump backwards by gigabytes. That produced a bogus
// out-of-order layout even for a perfectly ordered index. One global shift
// has no such discontinuity.
void resolve_regions(std::vector<BlockRec>& blocks, std::ostream& progress) {
    const std::vector<uint32_t> raw_stream = [&] {
        std::vector<uint32_t> v;
        v.reserve(blocks.size());
        for (const BlockRec& b : blocks) v.push_back(b.stream);
        return v;
    }();
    const std::vector<uint32_t> raw_region = [&] {
        std::vector<uint32_t> v;
        v.reserve(blocks.size());
        for (const BlockRec& b : blocks) v.push_back(b.region);
        return v;
    }();
    size_t gaps = 0;
    for (size_t i = 0; i < blocks.size(); ++i) {
        if (i == 0) {
            blocks[0].stream = 0;
            blocks[0].region = 0;
        } else {
            blocks[i].stream = raw_stream[i - 1];
            blocks[i].region = raw_region[i - 1];
            if (blocks[i - 1].end() != blocks[i].off) {
                ++gaps;
            }
        }
    }
    progress << "  regions resolved by global one-record shift (" << blocks.size()
             << " blocks, " << gaps << " chain gaps)\n";
}

constexpr uint64_t kCacheVersion = 4;
constexpr uint64_t kCacheMagic = 0x3249444d54534cull + kCacheVersion;

std::vector<BlockRec> block_index(const AdiFile& file, const std::string& cache,
                                  std::ostream& progress) {
    std::vector<BlockRec> out;
    std::ifstream in(cache, std::ios::binary);
    if (in) {
        uint64_t magic = 0;
        uint64_t n = 0;
        in.read(reinterpret_cast<char*>(&magic), sizeof(magic));
        in.read(reinterpret_cast<char*>(&n), sizeof(n));
        if (in && magic != kCacheMagic) {
            progress << "  ignoring stale index cache " << cache << "\n";
            n = 0;
        }
        if (in && n && n < (1ull << 28)) {
            out.resize(static_cast<size_t>(n));
            in.read(reinterpret_cast<char*>(out.data()),
                    static_cast<std::streamsize>(n * sizeof(BlockRec)));
            if (in) {
                progress << "  block index: " << out.size() << " records from " << cache << "\n";
                return out;
            }
        }
        out.clear();
    }
    out = scan_block_index(file, progress);
    std::ofstream save(cache, std::ios::binary | std::ios::trunc);
    if (save) {
        const uint64_t n = out.size();
        save.write(reinterpret_cast<const char*>(&kCacheMagic), sizeof(kCacheMagic));
        save.write(reinterpret_cast<const char*>(&n), sizeof(n));
        save.write(reinterpret_cast<const char*>(out.data()),
                   static_cast<std::streamsize>(n * sizeof(BlockRec)));
    }
    return out;
}

Lz4Stream::Lz4Stream(const AdiFile& file, const std::vector<BlockRec>& blocks)
    : file_(file), blocks_(blocks), in_(kInBuf), out_(kHistory + kWork) {}

bool Lz4Stream::decode_buffer(const uint8_t* src, size_t n, const uint8_t** out,
                              size_t* out_n) {
    *out = nullptr;
    *out_n = 0;
    // Fresh state: no 64 KiB history from a previous block.
    std::fill(out_.begin(), out_.end(), 0);
    base_ = 0;
    len_ = 0;
    cur_ = 0;
    produced_ = 0;
    error_.clear();
    in_.assign(std::max(n, kInBuf), 0);
    std::memcpy(in_.data(), src, n);
    in_base_ = 0;
    in_have_ = n;
    in_used_ = 0;
    in_end_ = n;  // fed == in_end_, so in_avail() never touches the file
    while (in_pos() < in_end_) {
        if (!step()) {
            break;
        }
    }
    if (!error_.empty()) {
        return false;
    }
    *out = out_.data() + base_;
    *out_n = len_ - base_;
    return true;
}

void Lz4Stream::fail(const char* what) {
    if (error_.empty()) {
        error_ = what;
        error_in_pos_ = in_pos();
        error_out_pos_ = produced_;
    }
}

bool Lz4Stream::next_block() {
    if (blk_ != static_cast<size_t>(-1)) {
        const uint64_t got = produced_ - block_out_start_;
        if (got != blocks_[blk_].usize) {
            ++bad_blocks_;
        }
    }
    const size_t prev = blk_;
    ++blk_;
    if (blk_ >= blocks_.size()) {
        eos_ = true;
        return false;
    }
    const BlockRec& b = blocks_[blk_];
    if (prev != static_cast<size_t>(-1) && blocks_[prev].end() != b.off) {
        base_ = 0;
        len_ = 0;
        cur_ = 0;
    }
    // BlockRec::off is a VDB ImgOffset, i.e. an image-set LOGICAL offset.
    // The old code added payload_offset() here, which is only correct for a
    // single-member image with DataOffInSet == 0.
    in_base_ = b.off;
    in_end_ = in_base_ + b.csize;
    in_have_ = 0;
    in_used_ = 0;
    block_out_start_ = produced_;
    return true;
}

bool Lz4Stream::in_avail(size_t n) {
    if (in_have_ - in_used_ >= n) {
        return true;
    }
    const size_t left = in_have_ - in_used_;
    if (left && in_used_) {
        std::memmove(in_.data(), in_.data() + in_used_, left);
    }
    in_base_ += in_used_;
    in_used_ = 0;
    in_have_ = left;
    const uint64_t fed = in_base_ + in_have_;
    if (fed < in_end_) {
        const size_t want =
            static_cast<size_t>(std::min<uint64_t>(in_.size() - in_have_, in_end_ - fed));
        file_.read_logical(fed, in_.data() + in_have_, want);
        in_have_ += want;
    }
    return in_have_ - in_used_ >= n;
}

bool Lz4Stream::in_byte(uint8_t* out) {
    if (!in_avail(1)) {
        return false;
    }
    *out = in_[in_used_++];
    return true;
}

bool Lz4Stream::in_copy(uint8_t* dst, size_t n) {
    while (n) {
        if (!in_avail(1)) {
            return false;
        }
        const size_t chunk = std::min(n, in_have_ - in_used_);
        std::memcpy(dst, in_.data() + in_used_, chunk);
        in_used_ += chunk;
        dst += chunk;
        n -= chunk;
    }
    return true;
}

void Lz4Stream::reserve_out(size_t extra) {
    if (len_ + extra > out_.size()) {
        out_.resize(len_ + extra + kWork);
    }
}

bool Lz4Stream::step() {
    uint8_t token = 0;
    if (!in_byte(&token)) {
        return false;
    }
    size_t lit = token >> 4;
    if (lit == 15) {
        uint8_t b = 0;
        do {
            if (!in_byte(&b)) {
                fail("truncated literal length");
                return false;
            }
            lit += b;
        } while (b == 255);
    }
    if (lit) {
        reserve_out(lit);
        if (!in_copy(out_.data() + len_, lit)) {
            fail("truncated literals");
            return false;
        }
        len_ += lit;
        produced_ += lit;
    }
    if (in_pos() >= in_end_) {
        return true;
    }
    uint8_t lo = 0;
    uint8_t hi = 0;
    if (!in_byte(&lo) || !in_byte(&hi)) {
        fail("truncated match offset");
        return false;
    }
    const size_t off = static_cast<size_t>(lo) | (static_cast<size_t>(hi) << 8);
    if (off == 0 || off > len_) {
        fail("match offset outside window");
        return false;
    }
    size_t mlen = token & 15;
    if (mlen == 15) {
        uint8_t b = 0;
        do {
            if (!in_byte(&b)) {
                fail("truncated match length");
                return false;
            }
            mlen += b;
        } while (b == 255);
    }
    mlen += 4;
    reserve_out(mlen);
    uint8_t* dst = out_.data() + len_;
    const uint8_t* src = dst - off;
    for (size_t i = 0; i < mlen; ++i) {
        dst[i] = src[i];
    }
    len_ += mlen;
    produced_ += mlen;
    return true;
}

const BlockRec* Lz4Stream::next_chunk(const uint8_t** data, size_t* size) {
    *data = nullptr;
    *size = 0;
    if (eos_ || !error_.empty() || !next_block()) {
        return nullptr;
    }
    const size_t keep = std::min(len_, kHistory);
    if (len_ > keep) {
        std::memmove(out_.data(), out_.data() + len_ - keep, keep);
    }
    base_ = keep;
    len_ = keep;
    cur_ = keep;
    while (in_pos() < in_end_) {
        if (!step()) {
            break;
        }
    }
    *data = out_.data() + base_;
    *size = len_ - base_;
    return &blocks_[blk_];
}

size_t Lz4Stream::read(uint8_t* dst, size_t max) {
    size_t done = 0;
    while (done < max) {
        if (cur_ >= len_) {
            const uint8_t* p = nullptr;
            size_t n = 0;
            if (!next_chunk(&p, &n)) {
                break;
            }
            if (n == 0) {
                continue;
            }
        }
        const size_t n = std::min(max - done, len_ - cur_);
        if (dst) {
            std::memcpy(dst + done, out_.data() + cur_, n);
        }
        cur_ += n;
        done += n;
    }
    return done;
}

bool parse_boot_sector(const uint8_t* p, size_t n, BootSector* out) {
    if (n < 512) {
        return false;
    }
    if (p[0] != 0xeb && p[0] != 0xe9) {
        return false;
    }
    if (rd16(p + 510) != 0xaa55) {
        return false;
    }
    const uint32_t bps = rd16(p + 11);
    if (bps != 512 && bps != 1024 && bps != 2048 && bps != 4096) {
        return false;
    }
    const uint32_t spc = p[13];
    if (spc == 0 || (spc & (spc - 1)) != 0 || spc > 128) {
        return false;
    }
    out->bytes_per_sector = bps;
    out->sectors_per_cluster = spc;
    out->hidden_sectors = rd32(p + 28);
    out->label = trim_ascii(p + 3, 8);

    if (std::memcmp(p + 3, "NTFS    ", 8) == 0) {
        out->fs = "NTFS";
        out->total_sectors = rd64(p + 40);
        out->mft_cluster = rd64(p + 48);
        return true;
    }
    if (std::memcmp(p + 3, "-FVE-FS-", 8) == 0) {
        out->fs = "BitLocker";
        out->total_sectors = rd64(p + 40);
        return true;
    }
    const uint32_t reserved = rd16(p + 14);
    const uint32_t fats = p[16];
    const uint32_t root_entries = rd16(p + 17);
    const bool fat32 = rd16(p + 22) == 0;
    const uint64_t fat_sectors = fat32 ? rd32(p + 36) : rd16(p + 22);
    if (reserved && fats && fat_sectors) {
        out->data_start = (uint64_t(reserved) + fats * fat_sectors) * bps +
                          uint64_t(root_entries) * 32;
    }
    if (fat32 && std::memcmp(p + 82, "FAT32   ", 8) == 0) {
        out->fs = "FAT32";
        out->total_sectors = rd16(p + 19) ? rd16(p + 19) : rd32(p + 32);
        out->label = trim_ascii(p + 71, 11);
        return true;
    }
    if (std::memcmp(p + 54, "FAT16   ", 8) == 0 || std::memcmp(p + 54, "FAT12   ", 8) == 0 ||
        std::memcmp(p + 54, "FAT     ", 8) == 0) {
        out->fs = trim_ascii(p + 54, 8);
        out->total_sectors = rd16(p + 19) ? rd16(p + 19) : rd32(p + 32);
        out->label = trim_ascii(p + 43, 11);
        return true;
    }
    if (std::memcmp(p + 3, "EXFAT   ", 8) == 0) {
        out->fs = "exFAT";
        return true;
    }
    return false;
}

bool lznt1_decompress(const uint8_t* src, size_t src_n, uint8_t* dst, size_t dst_n,
                      size_t* out_n) {
    using RtlDecompressBufferFn = LONG(WINAPI*)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG);
    static RtlDecompressBufferFn fn = []() -> RtlDecompressBufferFn {
        HMODULE h = GetModuleHandleW(L"ntdll.dll");
        return h ? reinterpret_cast<RtlDecompressBufferFn>(
                       GetProcAddress(h, "RtlDecompressBuffer"))
                 : nullptr;
    }();
    if (!fn) {
        return false;
    }
    ULONG produced = 0;
    const LONG st = fn(2 /* COMPRESSION_FORMAT_LZNT1 */, reinterpret_cast<PUCHAR>(dst),
                       static_cast<ULONG>(dst_n),
                       reinterpret_cast<PUCHAR>(const_cast<uint8_t*>(src)),
                       static_cast<ULONG>(src_n), &produced);
    if (st < 0) {
        return false;
    }
    if (out_n) {
        *out_n = produced;
    }
    return true;
}

bool split_block(const uint8_t* p, uint32_t usize, uint32_t cluster_hint, BlockLayout* out) {
    // All callers have already verified that the buffer holds exactly `usize`
    // decoded bytes, so `usize` is also the number of readable bytes here.
    if (usize == 1 + kRegion) {
        out->hdr = 1;
        out->cluster = cluster_hint ? cluster_hint : 512;
        out->units = kRegion / out->cluster;
        out->all_present = true;
        return true;
    }
    // Real images use 32 KiB clusters for sparse C: regions (2 MiB / 64 SPC).
    // Cover the full power-of-two range so a 0x109 geometry of 32768 or 65536
    // is not silently dropped as an "unrecognised header".
    static const uint32_t kSizes[] = {512,   1024,  2048,  4096,
                                      8192,  16384, 32768, 65536};
    for (const uint32_t cluster : kSizes) {
        if (cluster_hint && cluster != cluster_hint) {
            continue;
        }
        const uint32_t clusters_per_region = kRegion / cluster;
        const uint32_t hdr = (clusters_per_region + 7) / 8;
        if (hdr == 0 || hdr > usize) {
            continue;
        }
        uint32_t pop = 0;
        for (uint32_t i = 0; i < hdr; ++i) {
            pop += kPopcount[p[i]];
        }
        // Bits beyond clusters_per_region are padding; ignore them.
        const uint32_t spare = std::min<uint32_t>(hdr * 8 - clusters_per_region, 7);
        if (spare) {
            const uint8_t last = static_cast<uint8_t>(p[hdr - 1] & (0xFFu >> spare));
            pop = pop - kPopcount[p[hdr - 1]] + kPopcount[last];
        }
        if (usize == hdr + pop * cluster) {
            out->hdr = hdr;
            out->cluster = cluster;
            out->units = pop;
            out->all_present = false;
            return true;
        }
    }
    return false;
}

namespace {

class MarkerSink {
public:
    explicit MarkerSink(ScanResult* out) : r_(out) {}

    void scan(const uint8_t* p, size_t n, const BlockRec& b, uint32_t unit, uint32_t cluster) {
        const uint64_t base = region_offset(b.region) + uint64_t(unit) * cluster;
        for (size_t i = 0; i + 512 <= n; i += 512) {
            const uint8_t* d = p + i;
            if (std::memcmp(d, "EFI PART", 8) == 0) {
                ++r_->gpt_headers;
                add("GPT", base + i, coord(b, unit));
                continue;
            }
            if (d[510] == 0x55 && d[511] == 0xaa) {
                ++r_->sector_marks;
            }
            BootSector bs;
            if ((d[0] == 0xeb || d[0] == 0xe9) && parse_boot_sector(d, n - i, &bs)) {
                bs.stream_off = base + i;
                bs.stream = b.stream;
                bs.region = b.region;
                bs.unit = unit;
                if (r_->boot_sectors.size() < 256) {
                    r_->boot_sectors.push_back(bs);
                }
            }
        }
        for (size_t i = 0; i + 8 <= n; i += 8) {
            if (std::memcmp(p + i, "FILE", 4) == 0) {
                const uint16_t usa = rd16(p + i + 4);
                const uint16_t usc = rd16(p + i + 6);
                if ((usa == 0x2a || usa == 0x30 || usa == 0x38) && usc >= 2 && usc <= 16) {
                    ++r_->mft_records;
                    if (r_->mft_records <= 8) {
                        add("MFT", base + i, coord(b, unit));
                    }
                }
            } else if (std::memcmp(p + i, "INDX", 4) == 0 && rd16(p + i + 4) == 0x28) {
                ++r_->index_buffers;
            }
        }
    }

private:
    static std::string coord(const BlockRec& b, uint32_t unit) {
        return "stream " + std::to_string(b.stream) + " region " + std::to_string(b.region) +
               " unit " + std::to_string(unit);
    }
    void add(const char* kind, uint64_t off, std::string detail) {
        if (r_->markers.size() < 256) {
            r_->markers.push_back({kind, off, std::move(detail)});
        }
    }

    ScanResult* r_;
};

}  // namespace

ScanResult scan_payload(const AdiFile& file, const std::vector<BlockRec>& blocks,
                        uint64_t max_out, std::ostream& progress) {
    ScanResult r;
    r.blocks = blocks.size();
    for (size_t i = 1; i < blocks.size(); ++i) {
        if (blocks[i - 1].end() != blocks[i].off) {
            ++r.gaps;
        }
    }
    Lz4Stream st(file, blocks);
    MarkerSink sink(&r);

    const BlockRec* b = nullptr;
    const uint8_t* data = nullptr;
    size_t n = 0;
    uint64_t prev_end = 0;
    uint32_t cluster = 0;
    uint64_t next_note = 1ull << 30;
    while ((b = st.next_chunk(&data, &n)) != nullptr) {
        if (b->off != prev_end) {
            cluster = 0;
        }
        prev_end = b->end();
        if (n != b->usize) {
            adi::debug_log() << "  warning: block at logical " << b->off
                      << ": decoded size mismatch; skipped during discovery; verify output\n";
            ++r.short_blocks;
            continue;
        }
        if (b->crc != 0) {
            ++r.crc_checked;
            if (!block_crc_ok(*b, data, n)) {
                adi::debug_log() << "  warning: block at logical " << b->off
                          << ": checksum mismatch; skipped during discovery; verify output\n";
                ++r.crc_bad;
                ++r.odd_blocks;
                continue;
            }
        }
        BlockLayout lay;
        if (!split_block(data, b->usize, cluster, &lay)) {
            adi::debug_log() << "  warning: block at logical " << b->off
                      << ": unrecognised layout; skipped during discovery; verify output\n";
            ++r.odd_blocks;
            continue;
        }
        cluster = lay.cluster;
        uint32_t slot = 0;
        for (uint32_t u = 0; u < kRegion / lay.cluster && slot < lay.units; ++u) {
            if (!unit_present(data, lay, u)) {
                continue;
            }
            const size_t src = size_t(lay.hdr) + size_t(slot) * lay.cluster;
            if (src > n || lay.cluster > n - src) {
                adi::debug_log() << "  warning: truncated cluster data at logical " << b->off
                          << "; discovery incomplete; verify output\n";
                break;
            }
            sink.scan(data + src, lay.cluster, *b, u, lay.cluster);
            ++slot;
        }
        if (st.out_pos() >= next_note) {
            progress << "  ... " << (st.out_pos() >> 30) << " GiB out, block "
                     << st.block_index() << "/" << blocks.size() << ", "
                     << r.boot_sectors.size() << " boot sectors, " << st.bad_blocks()
                     << " size mismatches\n";
            progress.flush();
            next_note += 1ull << 30;
        }
        if (max_out && st.out_pos() >= max_out) {
            break;
        }
    }

    for (const auto& blk : blocks) {
        r.in_bytes += blk.csize;
    }
    r.out_bytes = st.out_pos();
    r.bad_blocks = st.bad_blocks();
    r.clean = st.ok() && r.bad_blocks == 0 && r.crc_bad == 0;
    if (!r.clean)
        adi::debug_log() << "  warning: payload scan incomplete or unverified; " << r.bad_blocks
                  << " size failures, " << r.crc_bad << " checksum failures; verify output\n";
    if (!st.ok()) {
        r.error = st.error();
        r.error_in_pos = st.error_in_pos();
        r.error_out_pos = st.error_out_pos();
    }
    return r;
}

}  // namespace adi
