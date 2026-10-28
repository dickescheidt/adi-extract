#pragma once

#include "adi_file.hpp"
#include "codec.hpp"
#include "records.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace adi {

struct Partition {
    uint32_t index = 0;
    uint64_t first_lba = 0;
    uint64_t last_lba = 0;
    std::string type_guid;
    std::string name;
    std::string fs_guess;
};

struct DiskGeometry {
    uint32_t sector_size = 512;
    uint64_t sector_count = 0;
    std::string partition_style;
    std::vector<Partition> partitions;
};

struct Volume {
    size_t first = 0;
    size_t last = 0;
    uint32_t cluster = 512;
    uint64_t data_base = 0;
    uint64_t lba = 0;
    uint64_t sectors = 0;
    uint64_t stored = 0;
    std::string fs;
    std::string label;
    /// Recovered from a 0x102 volume-metadata record (zero => guess).
    uint8_t type_guid[16]{};
    uint8_t unique_guid[16]{};
    /// UTF-16 GPT partition name recovered from 0x102 (empty => guess).
    std::string part_name;
};

struct SectorMap {
    std::string source;
    uint32_t sector_size = 512;
    uint64_t disk_sectors = 0;
    std::vector<Volume> volumes;

    // Scan-based layout. When the decompressed block stream is a whole-disk
    // coordinate space, every cluster lands at (stream offset + origin).
    // The legacy layout derives offsets from one volume per index-chain run.
    bool passthrough = false;
    uint64_t origin = 0;
    // Set when the stream already contains the disk's own MBR/GPT at LBA 0,
    // in which case write_gpt() must not overwrite it.
    bool native_table = false;
};

DiskGeometry inspect_image(const std::filesystem::path& img_path);

SectorMap discover_map(const AdiFile& file, const std::vector<BlockRec>& blocks,
                       const std::filesystem::path& out_csv);

uint64_t reconstruct_image(const AdiFile& file, const std::vector<BlockRec>& blocks,
                           const SectorMap& map, const std::filesystem::path& out_img,
                           uint64_t max_bytes = 0);

/// Reconstruct from CRC-valid standard records: exact 0x109 geometry, 0x102
/// disk placement, and image-set logical reads for every stored block.
uint64_t reconstruct_standard(const AdiFile& file, const StandardImage& std_img,
                              const std::filesystem::path& out_img);

}  // namespace adi
