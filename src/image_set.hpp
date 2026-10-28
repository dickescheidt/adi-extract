#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

namespace adi {

struct ImageSetMemberInfo {
    std::filesystem::path path;
    uint64_t logical_start = 0;
    uint64_t data_length = 0;
    uint64_t header_size = 0;
};

struct ContainerFields {
    uint64_t file_size = 0;
    uint64_t header_size = 0;
    uint64_t tail_size = 0;
    uint64_t data_offset_in_set = 0;
    uint64_t data_length_in_set = 0;
    bool has_image_set = false;
    bool header_crc_valid = false;
    bool tail_crc_valid = false;
    uint32_t header_checksum = 0;
    uint32_t tail_checksum = 0;
    std::string name;
    std::string comment;
};

/// Read only the framing fields of a BIFH/BIFT container. Used for every
/// member of a split image set; the primary member is also parsed by AdiFile.
ContainerFields parse_container_fields(const std::filesystem::path& path);

/// AOMEI's `m_pImgSet->ReadData`: logical offsets are NOT file offsets.
/// For the member covering [DataOffInSet, +DataLenInSet), the physical read is
/// `header_size + (logical - DataOffInSet)` inside that member's own file.
/// Reads may span two adjacent members.
class ImageSet {
public:
    static ImageSet from_paths(const std::vector<std::filesystem::path>& paths);

    void read(uint64_t logical, void* dst, size_t n) const;
    std::vector<uint8_t> read_vec(uint64_t logical, size_t n) const;

    const std::vector<ImageSetMemberInfo>& members() const { return members_; }

private:
    struct State {
        ImageSetMemberInfo info;
        std::shared_ptr<std::ifstream> file;
    };
    std::vector<State> state_;
    std::vector<ImageSetMemberInfo> members_;
};

/// Colon-separated list of extra `.adi` member paths from an env var.
std::vector<std::filesystem::path> extra_member_paths(const char* var);

}  // namespace adi
