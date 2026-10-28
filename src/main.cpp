#include "diagnostics.hpp"
#include "adi_file.hpp"
#include "codec.hpp"
#include "extract.hpp"
#include "image.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

void usage() {
    std::cerr << "adi-extract — recover files from an AOMEI Backupper .adi disk image\n\n"
              << "Usage:\n"
              << "  adi-extract info        <file.adi>\n"
              << "  adi-extract scan        <file.adi> [report.txt] [max_out]\n"
              << "  adi-extract reconstruct <file.adi> <disk.img> [max_bytes]\n"
              << "  adi-extract verify      <disk.img>\n"
              << "  adi-extract extract     <file.adi> <outdir>\n\n"
              << "--debug enables extended format-audit diagnostics on stderr.\n"
              << "Sizes accept suffixes: 512M, 4G\n"
              << "Split image sets: set ADI_EXTRACT_MEMBERS to a colon-separated\n"
              << "list of additional .adi member files.\n";
}

uint64_t parse_size(const std::string& s) {
    char* endp = nullptr;
    uint64_t v = std::strtoull(s.c_str(), &endp, 0);
    if (endp && *endp) {
        switch (*endp) {
            case 'k':
            case 'K':
                v <<= 10;
                break;
            case 'm':
            case 'M':
                v <<= 20;
                break;
            case 'g':
            case 'G':
                v <<= 30;
                break;
            default:
                break;
        }
    }
    return v;
}

std::string hex(uint64_t v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(v));
    return buf;
}

struct StreamStat {
    uint64_t blocks = 0;
    uint32_t min_region = 0xffffffff;
    uint32_t max_region = 0;
    uint64_t usize = 0;
    uint64_t csize = 0;
};

std::map<uint32_t, StreamStat> stream_stats(const std::vector<adi::BlockRec>& blocks) {
    std::map<uint32_t, StreamStat> m;
    for (const auto& b : blocks) {
        auto& s = m[b.stream];
        ++s.blocks;
        s.min_region = std::min(s.min_region, b.region);
        s.max_region = std::max(s.max_region, b.region);
        s.usize += b.usize;
        s.csize += b.csize;
    }
    return m;
}

void write_index_summary(std::ostream& out, const std::vector<adi::BlockRec>& blocks) {
    out << "\n[block index]\n"
        << "  records:   " << blocks.size() << "\n";
    if (blocks.empty()) {
        return;
    }
    uint64_t gaps = 0;
    uint64_t covered = 0;
    for (size_t i = 0; i < blocks.size(); ++i) {
        covered += blocks[i].csize;
        if (i && blocks[i - 1].end() != blocks[i].off) {
            ++gaps;
        }
    }
    uint64_t crcs = 0;
    for (const auto& b : blocks) {
        if (b.crc != 0) {
            ++crcs;
        }
    }
    out << "  first off: " << hex(blocks.front().off) << "\n"
        << "  last end:  " << hex(blocks.back().end()) << "\n"
        << "  covered:   " << covered << " compressed bytes\n"
        << "  crcs:      " << crcs << " records carry a BRCrc32 checksum\n"
        << "  gaps:      " << gaps << " (metadata regions between block runs)\n";
    for (const auto& kv : stream_stats(blocks)) {
        out << "  stream " << kv.first << ": " << kv.second.blocks << " blocks, regions "
            << kv.second.min_region << ".." << kv.second.max_region << ", "
            << kv.second.usize << " uncompressed, " << kv.second.csize << " compressed\n";
    }
}

void write_scan_report(const adi::ScanResult& r, const std::vector<adi::BlockRec>& blocks,
                       const fs::path& path, const adi::AdiFile& file) {
    std::ofstream out(path, std::ios::trunc);
    out << "adi-extract scan report\n"
        << "source:            " << file.path().string() << "\n"
        << "payload offset:    " << hex(file.payload_offset()) << "\n"
        << "payload end:       " << hex(file.payload_end()) << "\n";
    write_index_summary(out, blocks);
    out << "\n[decode]\n"
        << "  compressed:      " << r.in_bytes << "\n"
        << "  decompressed:    " << r.out_bytes << "\n";
    if (r.in_bytes) {
        out << "  ratio:           " << std::fixed << std::setprecision(3)
            << (double(r.out_bytes) / double(r.in_bytes)) << "\n";
    }
    out << "  size mismatches: " << r.bad_blocks << "\n"
        << "  short blocks:    " << r.short_blocks << "\n"
        << "  odd headers:     " << r.odd_blocks << "\n"
        << "  BRCrc32 checked: " << r.crc_checked << "\n"
        << "  BRCrc32 bad:     " << r.crc_bad << "\n"
        << "  clean:           " << (r.clean ? "yes" : "no") << "\n";
    if (!r.error.empty()) {
        out << "\n[break]\n"
            << "  reason:        " << r.error << "\n"
            << "  adi offset:    " << hex(r.error_in_pos) << "\n"
            << "  stream offset: " << hex(r.error_out_pos) << "\n";
    }
    out << "\n[counts]\n"
        << "  GPT headers:   " << r.gpt_headers << "\n"
        << "  MFT records:   " << r.mft_records << "\n"
        << "  INDX buffers:  " << r.index_buffers << "\n"
        << "  55AA @512:     " << r.sector_marks << "\n"
        << "  boot sectors:  " << r.boot_sectors.size() << "\n";
    out << "\n[boot sectors]\n";
    for (const auto& b : r.boot_sectors) {
        out << "  " << hex(b.stream_off) << "  stream " << b.stream << " region " << b.region
            << " unit " << b.unit << "  " << b.fs << "  bps=" << b.bytes_per_sector
            << " spc=" << b.sectors_per_cluster << " total=" << b.total_sectors
            << " hidden=" << b.hidden_sectors;
        if (b.mft_cluster) {
            out << " mft_lcn=" << b.mft_cluster;
        }
        if (!b.label.empty()) {
            out << " label='" << b.label << "'";
        }
        out << "\n";
    }
    out << "\n[markers]\n";
    for (const auto& m : r.markers) {
        out << "  " << hex(m.stream_off) << "  " << m.kind << "  " << m.detail << "\n";
    }
}

}  // namespace

int main(int argc, char** argv) {
    int kept = 1;
    bool options = true;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (options && arg == "--") {
            options = false;
        } else if (options && arg == "--debug") {
            adi::debug_diagnostics = true;
        } else {
            argv[kept++] = argv[i];
        }
    }
    argc = kept;
    argv[argc] = nullptr;
    if (argc < 3) {
        usage();
        return 2;
    }
    const std::string cmd = argv[1];
    try {
        const std::string cache = argc > 2 ? std::string(argv[2]) + ".index" : std::string();
        if (cmd == "info") {
            adi::debug_log() << "warning: info does not verify all decoded block contents/checksums; use "
                         "extraction diagnostics and independent filesystem checks\n";
            adi::AdiFile file(argv[2], adi::extra_member_paths("ADI_EXTRACT_MEMBERS"));
            file.print_info();
            if (std::getenv("ADI_EXTRACT_LEGACY_ONLY") == nullptr) {
                if (auto std_img = adi::parse_standard(file, std::cout)) {
                    adi::print_standard_info(*std_img, std::cout);
                    return 0;
                }
            }
            std::cout << "\nno standard record sets; using legacy signature scan\n";
            adi::debug_log() << "warning: no standard record sets; using legacy signature scan; inferred "
                         "geometry and placement need verification\n";
            auto blocks = adi::block_index(file, cache, std::cout);
            write_index_summary(std::cout, blocks);
            return 0;
        }
        if (cmd == "scan") {
            adi::AdiFile file(argv[2], adi::extra_member_paths("ADI_EXTRACT_MEMBERS"));
            const fs::path report = argc > 3 ? fs::path(argv[3]) : fs::path("scan.txt");
            const uint64_t max_out = argc > 4 ? parse_size(argv[4]) : 0;
            file.print_info();
            std::cout << "\nscanning block index...\n";
            auto blocks = adi::block_index(file, cache, std::cout);
            write_index_summary(std::cout, blocks);
            std::cout << "\ndecoding payload";
            if (max_out) {
                std::cout << ", stopping after " << max_out << " bytes";
            }
            std::cout << "\n";
            auto r = adi::scan_payload(file, blocks, max_out, std::cout);
            write_scan_report(r, blocks, report, file);
            std::cout << "\ndecompressed " << r.out_bytes << " bytes, " << r.bad_blocks
                      << " size mismatches\n"
                      << "boot sectors " << r.boot_sectors.size() << ", MFT records "
                      << r.mft_records << ", GPT headers " << r.gpt_headers << "\n"
                      << "report -> " << report.string() << "\n";
            if (!r.error.empty()) {
                std::cout << "break: " << r.error << " at adi " << hex(r.error_in_pos)
                          << ", stream " << hex(r.error_out_pos) << "\n";
            }
            return r.out_bytes ? 0 : 1;
        }
        if (cmd == "verify") {
            const fs::path img = argv[2];
            auto geo = adi::inspect_image(img);
            std::cout << "partition style: " << geo.partition_style << ", "
                      << geo.partitions.size() << " partitions\n";
            auto v = adi::verify_image(img, geo);
            for (const auto& l : v.lines) {
                std::cout << "  " << l << "\n";
            }
            const double pct = v.checks ? 100.0 * double(v.ok) / double(v.checks) : 0.0;
            std::cout << v.ok << "/" << v.checks << " self-locating structures in place ("
                      << std::fixed << std::setprecision(2) << pct << "%)\n";
            return v.clean() ? 0 : 1;
        }
        if (cmd == "reconstruct" || cmd == "extract") {
            if (argc < 4) {
                usage();
                return 2;
            }
            adi::AdiFile file(argv[2], adi::extra_member_paths("ADI_EXTRACT_MEMBERS"));
            const bool full = cmd == "extract";
            const fs::path outdir = full ? fs::path(argv[3]) : fs::path(argv[3]).parent_path();
            const fs::path img = full ? outdir / "disk.img" : fs::path(argv[3]);
            const uint64_t cap = (!full && argc > 4) ? parse_size(argv[4]) : 0;
            if (!outdir.empty()) {
                fs::create_directories(outdir);
            }

            uint64_t written = 0;
            if (full && fs::exists(img) && fs::file_size(img) > 0) {
                std::cout << "reusing " << img.string() << "\n";
                written = fs::file_size(img);
            } else {
                bool standard = false;
                if (std::getenv("ADI_EXTRACT_LEGACY_ONLY") == nullptr) {
                    if (auto std_img = adi::parse_standard(file, std::cout)) {
                        std::cout << "map: standard 0x201/0x202/0x109 records, disk "
                                  << std_img->disk_sectors << " sectors, "
                                  << std_img->volumes.size() << " volumes\n";
                        for (size_t i = 0; i < std_img->volumes.size(); ++i) {
                            const auto& v = std_img->volumes[i];
                            std::cout << "  v" << i << " lba " << v.lba << " sectors "
                                      << v.sectors << " cluster " << v.cluster
                                      << " blocks " << v.blocks << " label '"
                                      << v.label << "'\n";
                        }
                        written = adi::reconstruct_standard(file, *std_img, img);
                        standard = true;
                    }
                }
                if (!standard) {
                    std::cout << "no standard record sets; using legacy signature scan\n";
                    adi::debug_log() << "warning: no standard record sets; using legacy signature scan; "
                                 "inferred geometry and placement need verification\n";
                    auto blocks = adi::block_index(file, cache, std::cout);
                    auto map = adi::discover_map(file, blocks, outdir / "map.csv");
                    std::cout << "map: " << map.source << "\ndisk " << map.disk_sectors
                              << " sectors (" << (map.disk_sectors / 2097152) << " GiB), "
                              << map.volumes.size() << " volumes\n";
                    for (size_t i = 0; i < map.volumes.size(); ++i) {
                        const auto& v = map.volumes[i];
                        std::cout << "  v" << i << " " << (v.fs.empty() ? "raw" : v.fs)
                                  << " lba " << v.lba << " sectors " << v.sectors
                                  << " cluster " << v.cluster << " data_base "
                                  << v.data_base << " blocks "
                                  << (v.last - v.first + 1);
                        if (!v.label.empty()) {
                            std::cout << " label '" << v.label << "'";
                        }
                        std::cout << "\n";
                    }
                    written = adi::reconstruct_image(file, blocks, map, img, cap);
                }
                std::cout << "wrote " << written << " bytes -> " << img.string() << "\n";
            }
            auto geo = adi::inspect_image(img);
            std::cout << "partition style: " << geo.partition_style << ", "
                      << geo.partitions.size() << " partitions\n";
            for (const auto& p : geo.partitions) {
                std::cout << "  p" << p.index << " lba " << p.first_lba << ".." << p.last_lba
                          << "  " << p.type_guid << "  " << p.name << "\n";
            }
            if (!full) {
                return written ? 0 : 1;
            }
            auto stats = adi::extract_from_image(img, geo, outdir);
            std::cout << "extracted " << stats.files << " files, " << stats.dirs
                      << " dirs, " << stats.bytes << " bytes via " << stats.method << "\n";
            if (stats.skipped) {
                std::cout << stats.skipped << " entries skipped, see report.txt\n";
            }
            return stats.files ? 0 : 1;
        }
        usage();
        return 2;
    } catch (const std::exception& ex) {
        std::cerr << "error: " << ex.what() << "\n";
        return 1;
    }
}
