#pragma once

#include "adi_file.hpp"

#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <string>
#include <vector>

namespace adi {

struct BlockRec {
    uint64_t off = 0;
    uint32_t usize = 0;
    uint32_t csize = 0;
    uint32_t crc = 0;
    uint32_t stream = 0;
    uint32_t region = 0;

    uint64_t end() const { return off + csize; }
};

constexpr uint32_t kRegion = 256 * 1024;

struct BlockLayout {
    uint32_t hdr = 0;
    uint32_t cluster = 0;
    uint32_t units = 0;
    // usize == 1 + kRegion: the bitmap is a single "all present" marker byte,
    // not a real 1-byte bitmap. A genuine 1-byte bitmap (32 KiB clusters)
    // must still be read bit by bit.
    bool all_present = false;
};

bool split_block(const uint8_t* p, uint32_t usize, uint32_t cluster_hint, BlockLayout* out);

/// AOMEI's Encrypt.dll!BRCrc32: CRC32C/Castagnoli, zero seed, final inversion.
/// BlockRec::crc stores it over the *decoded* `usize` bytes of a block.
uint32_t br_crc32(const uint8_t* p, size_t n);

inline bool block_crc_ok(const BlockRec& b, const uint8_t* p, size_t n) {
    // A zero field means no checksum was written (our fixtures and some
    // images); we cannot distinguish that from a real zero CRC.
    return b.crc == 0 || br_crc32(p, n) == b.crc;
}

inline bool unit_present(const uint8_t* p, const BlockLayout& lay, uint32_t u) {
    if (lay.all_present) {
        return true;
    }
    const uint32_t idx = u >> 3;
    return idx < lay.hdr && (p[idx] & (1u << (u & 7))) != 0;
}

inline uint64_t region_offset(uint32_t region) {
    return uint64_t(region) * kRegion;
}

void resolve_regions(std::vector<BlockRec>& blocks, std::ostream& progress);

std::vector<BlockRec> scan_block_index(const AdiFile& file, std::ostream& progress);

std::vector<BlockRec> block_index(const AdiFile& file, const std::string& cache,
                                  std::ostream& progress);

class Lz4Stream {
public:
    Lz4Stream(const AdiFile& file, const std::vector<BlockRec>& blocks);

    const BlockRec* next_chunk(const uint8_t** data, size_t* size);
    size_t read(uint8_t* dst, size_t max);

    /// Decode one self-contained compressed block from memory, with a fresh
    /// LZ4 window. Real AOMEI VDB blocks never reference another block's
    /// output, so the standard record path uses this instead of next_chunk().
    ///
    /// `limit` is the block's declared decoded size (VDB `OldSize`). A single
    /// match-length extension byte encodes 255 output bytes, so without the
    /// ceiling a few hundred kilobytes of crafted input can request gigabytes
    /// of allocation. Exceeding `limit` fails like any other decode error.
    bool decode_buffer(const uint8_t* src, size_t n, size_t limit, const uint8_t** out,
                       size_t* out_n);

    uint64_t out_pos() const { return produced_; }
    size_t block_index() const { return blk_; }
    uint64_t bad_blocks() const { return bad_blocks_; }
    bool ok() const { return error_.empty(); }
    const std::string& error() const { return error_; }
    uint64_t error_in_pos() const { return error_in_pos_; }
    uint64_t error_out_pos() const { return error_out_pos_; }

private:
    static constexpr size_t kHistory = 64 * 1024;
    static constexpr size_t kWork = 1024 * 1024;
    static constexpr size_t kInBuf = 4 * 1024 * 1024;

    bool step();
    bool next_block();
    bool in_avail(size_t n);
    bool in_byte(uint8_t* out);
    bool in_copy(uint8_t* dst, size_t n);
    bool ensure_out(size_t extra);
    void fail(const char* what);
    uint64_t in_pos() const { return in_base_ + in_used_; }

    const AdiFile& file_;
    const std::vector<BlockRec>& blocks_;
    size_t blk_ = static_cast<size_t>(-1);
    uint64_t in_end_ = 0;
    uint64_t block_out_start_ = 0;
    uint64_t bad_blocks_ = 0;
    /// Ceiling for this block's output; reset per block and per decode_buffer call.
    size_t limit_ = static_cast<size_t>(-1);

    std::vector<uint8_t> in_;
    uint64_t in_base_ = 0;
    size_t in_have_ = 0;
    size_t in_used_ = 0;

    std::vector<uint8_t> out_;
    size_t base_ = 0;
    size_t len_ = 0;
    size_t cur_ = 0;
    uint64_t produced_ = 0;

    bool eos_ = false;
    std::string error_;
    uint64_t error_in_pos_ = 0;
    uint64_t error_out_pos_ = 0;
};

struct BootSector {
    uint64_t stream_off = 0;
    uint32_t stream = 0;
    uint32_t region = 0;
    uint32_t unit = 0;
    uint64_t data_start = 0;
    uint32_t bytes_per_sector = 0;
    uint32_t sectors_per_cluster = 0;
    uint64_t total_sectors = 0;
    uint64_t hidden_sectors = 0;
    uint64_t mft_cluster = 0;
    std::string fs;
    std::string label;
};

struct Marker {
    std::string kind;
    uint64_t stream_off = 0;
    std::string detail;
};

struct ScanResult {
    uint64_t blocks = 0;
    uint64_t index_bytes = 0;
    uint64_t in_bytes = 0;
    uint64_t out_bytes = 0;
    uint64_t bad_blocks = 0;
    uint64_t short_blocks = 0;
    uint64_t odd_blocks = 0;
    uint64_t crc_checked = 0;
    uint64_t crc_bad = 0;
    uint64_t gaps = 0;
    bool clean = false;
    std::string error;
    uint64_t error_in_pos = 0;
    uint64_t error_out_pos = 0;
    std::vector<Marker> markers;
    std::vector<BootSector> boot_sectors;
    uint64_t gpt_headers = 0;
    uint64_t mft_records = 0;
    uint64_t index_buffers = 0;
    uint64_t sector_marks = 0;
};

ScanResult scan_payload(const AdiFile& file, const std::vector<BlockRec>& blocks,
                        uint64_t max_out, std::ostream& progress);

bool parse_boot_sector(const uint8_t* p, size_t n, BootSector* out);

bool lznt1_decompress(const uint8_t* src, size_t src_n, uint8_t* dst, size_t dst_n,
                      size_t* out_n);

}  // namespace adi
