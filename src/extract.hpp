#pragma once

#include "image.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace adi {

struct ExtractStats {
    uint64_t files = 0;
    uint64_t dirs = 0;
    uint64_t bytes = 0;
    uint32_t partitions = 0;
    uint64_t skipped = 0;
    std::string method;
    std::string notes;
};

ExtractStats extract_from_image(const std::filesystem::path& img_path,
                                const DiskGeometry& geo,
                                const std::filesystem::path& out_dir);

struct VerifyResult {
    uint64_t checks = 0;
    uint64_t ok = 0;
    std::vector<std::string> lines;

    bool clean() const { return checks != 0 && ok == checks; }
};

VerifyResult verify_image(const std::filesystem::path& img_path, const DiskGeometry& geo);

}  // namespace adi
