#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace adi {

constexpr char kMagicHead[4] = {'B', 'I', 'F', 'H'};
constexpr char kMagicTail[4] = {'B', 'I', 'F', 'T'};
constexpr uint32_t kHeaderCommentOff = 0x44;
constexpr uint32_t kHeaderFilenameOff = 0x454;

struct Guid {
    uint8_t bytes[16]{};

    std::string to_string() const;
};

struct Header {
    char magic[4]{};
    uint32_t size = 0;
    uint32_t checksum = 0;
    Guid guid_a;
    Guid guid_b;
    std::string comment;
    std::string filename;
};

struct Footer {
    char magic[4]{};
    uint32_t size = 0;
    uint32_t checksum = 0;
    uint64_t offset_a = 0;
    uint64_t offset_b = 0;
    uint32_t field_a = 0;
    uint32_t field_b = 0;
    Guid guid_a;
    Guid guid_b;
    std::string comment;
    std::string filename;
};

class AdiFile {
public:
    explicit AdiFile(std::filesystem::path path);
    ~AdiFile();

    AdiFile(const AdiFile&) = delete;
    AdiFile& operator=(const AdiFile&) = delete;

    const std::filesystem::path& path() const { return path_; }
    uint64_t file_size() const { return file_size_; }
    const Header& header() const { return header_; }
    const Footer& footer() const { return footer_; }
    uint64_t payload_offset() const { return header_.size; }
    uint64_t payload_end() const;

    void read(uint64_t offset, void* dst, size_t n) const;
    std::vector<uint8_t> read_vec(uint64_t offset, size_t n) const;

    void print_info() const;

private:
    void parse_header();
    void parse_footer();

    std::filesystem::path path_;
    void* handle_ = nullptr;
    uint64_t file_size_ = 0;
    Header header_{};
    Footer footer_{};
};

std::string utf16le_z(const uint8_t* data, size_t nbytes);
uint32_t crc32_ieee(const uint8_t* data, size_t n, uint32_t seed = 0);

}  // namespace adi
