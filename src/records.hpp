#pragma once

#include <cstdint>
#include <iosfwd>
#include <optional>
#include <string>
#include <vector>

namespace adi {

class AdiFile;

/// One real 0x20-byte VDB entry with its exact output placement.
struct StdBlock {
    uint64_t off = 0;  // ImgOffset — an image-set LOGICAL offset
    uint32_t reg_no = 0;
    uint64_t block_no = 0;
    uint32_t usize = 0;
    uint32_t csize = 0;
    uint32_t crc = 0;
    uint64_t base = 0;  // absolute byte offset of this block's region in the disk image
    uint32_t cluster = 0;
    uint32_t bitmap_len = 0;
    uint32_t clusters_per_block = 0;
    uint64_t region_remaining = 0;
};

struct StdVolume {
    std::string label;
    std::string fs;
    std::string part_name;
    uint64_t lba = 0;
    uint64_t sectors = 0;
    uint32_t cluster = 512;
    uint8_t type_guid[16]{};
    uint8_t unique_guid[16]{};
    size_t blocks = 0;
};

struct RecordSetInfo {
    uint64_t volume_index_off = 0;
    uint64_t data_block_index_off = 0;
    int64_t delta = 0;
    uint32_t entry_count = 0;
    std::vector<std::string> regions;
    std::vector<std::string> metadata;
};

struct StandardImage {
    std::vector<StdBlock> blocks;
    std::vector<StdVolume> volumes;
    std::vector<RecordSetInfo> sets;
    uint64_t disk_sectors = 0;
    uint64_t skipped_regions = 0;
    bool have_compress = false;
    bool have_encrypt = false;
    uint32_t compress_mode = 0;
    uint32_t encrypt_mode = 0;
};

/// Discover CRC-valid 0x201 volume indexes and resolve their 0x202 VDB table,
/// 0x109 regions, 0x102 metadata and 0x105/0x106 modes. Returns nullopt when
/// the image has no standard record sets (synthetic/older images).
std::optional<StandardImage> parse_standard(const AdiFile& file, std::ostream& progress);

void print_standard_info(const StandardImage& std_img, std::ostream& out);

}  // namespace adi
