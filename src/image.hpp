#pragma once

#include "adi_file.hpp"
#include "codec.hpp"

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

}  // namespace adi
