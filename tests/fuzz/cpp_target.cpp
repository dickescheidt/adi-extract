// Private standard-record parsers are deliberately included in this TU only.
#include "../../src/records.cpp"
#include <unistd.h>

namespace {
std::filesystem::path scratch() {
    return std::filesystem::temp_directory_path() /
           ("adi-cpp-fuzz-" + std::to_string(getpid()) + ".adi");
}
void write_file(const std::vector<uint8_t>& bytes) {
    std::ofstream f(scratch(), std::ios::binary);
    f.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
}
struct Decoder {
    std::vector<adi::BlockRec> none;
    std::unique_ptr<adi::AdiFile> file;
    std::unique_ptr<adi::Lz4Stream> decoder;
    Decoder() {
        std::vector<uint8_t> bytes(0x40 + 64 + 16, 0);
        std::memcpy(bytes.data(), "BIFH", 4);
        bytes[4] = 0x40;
        bytes[bytes.size() - 8] = 16;
        std::memcpy(bytes.data() + bytes.size() - 4, "BIFT", 4);
        write_file(bytes);
        file = std::make_unique<adi::AdiFile>(scratch());
        decoder = std::make_unique<adi::Lz4Stream>(*file, none);
    }
    ~Decoder() {
        decoder.reset();
        file.reset();
        std::filesystem::remove(scratch());
    }
};
}  // namespace
namespace adi {
namespace {
void fuzz_records_cpp(const std::vector<uint8_t>& raw) {
    const size_t size = raw.size();
    for (auto kind : {0x201u, 0x202u, 0x102u, 0x105u, 0x106u, 0x109u}) {
        const Header h{0, kind};
        adi::DirectoryIndex dir;
        adi::DataBlockIndex idx;
        adi::Metadata meta;
        adi::Region region;
        uint32_t mode = 0;
        adi::parse_directory_index(h, raw, &dir);
        adi::parse_data_block_index(h, raw, &idx);
        adi::parse_metadata(h, raw, &meta);
        adi::parse_region(h, raw, &region);
        adi::parse_mode(h, raw, &mode);
    }
    if (size >= 32)
        adi::parse_vdb(raw, 0);
    if (size >= 16) {
        uint64_t result = 0;
        adi::shifted(adi::u64(raw, 0), static_cast<int64_t>(adi::u64(raw, 8)), &result);
    }
}
}  // namespace
}  // namespace adi
namespace adi {
namespace {
void fuzz_legacy_cpp(const uint8_t* data, size_t size) {
    // Valid 0x40-byte BIFH header, fuzz payload, 16-byte BIFT footer. This is
    // the history-aware chained decoder used by the legacy signature path.
    std::vector<uint8_t> bytes(0x40, 0);
    std::memcpy(bytes.data(), "BIFH", 4);
    bytes[4] = 0x40;
    bytes.insert(bytes.end(), data, data + size);
    const size_t footer = bytes.size();
    bytes.resize(footer + 16, 0);
    bytes[footer + 8] = 16;
    std::memcpy(bytes.data() + footer + 12, "BIFT", 4);
    write_file(bytes);
    adi::AdiFile image(scratch());
    std::vector<adi::BlockRec> blocks(1);
    blocks[0].off = 0x40;
    blocks[0].csize = static_cast<uint32_t>(size);
    blocks[0].usize = static_cast<uint32_t>(size);
    adi::Lz4Stream decoder(image, blocks);
    uint8_t sink[8192];
    for (int i = 0; i < 64; ++i) {
        const uint8_t* chunk = nullptr;
        size_t n = 0;
        if (!decoder.next_chunk(&chunk, &n))
            break;
        decoder.read(sink, sizeof(sink));
    }
    std::filesystem::remove(scratch());
}
}  // namespace
}  // namespace adi

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
#if defined(FUZZ_CODEC)
    if (size > 4096)
        return 0;
    static Decoder state;
    const uint8_t* decoded = nullptr;
    size_t n = 0;
    state.decoder->decode_buffer(data, size, 1u << 20, &decoded, &n);
    adi::BlockLayout lay;
    adi::split_block(data, static_cast<uint32_t>(size), 0, &lay);
#elif defined(FUZZ_RECORDS)
    if (size > 4096)
        return 0;
    const std::vector<uint8_t> raw(data, data + size);
    adi::fuzz_records_cpp(raw);
#elif defined(FUZZ_LEGACY)
    if (size > 4096)
        return 0;
    try {
        adi::fuzz_legacy_cpp(data, size);
    } catch (const std::exception&) {
        std::filesystem::remove(scratch());
    }
#else
    if (size > 65536)
        return 0;
    std::vector<uint8_t> raw(data, data + size);
    for (size_t at = 0; at + 16 <= size; ++at) {
        const auto kind = adi::u32(raw, at);
        const size_t len = adi::u32(raw, at + 4);
        if (adi::is_standard_type(kind) && len >= 16 && len <= 4096 && len <= size - at) {
            std::fill(raw.begin() + static_cast<ptrdiff_t>(at + 8),
                      raw.begin() + static_cast<ptrdiff_t>(at + 12), 0);
            const auto crc = adi::br_crc32(raw.data() + at, len);
            for (size_t i = 0; i < 4; ++i)
                raw[at + 8 + i] = static_cast<uint8_t>(crc >> (8 * i));
        }
    }
    write_file(raw);
    try {
        adi::AdiFile image(scratch());
        std::ostringstream out;
        adi::parse_standard(image, out);
    } catch (const std::exception&) { /* malformed input is an expected error */
    }
    std::filesystem::remove(scratch());
#endif
    return 0;
}
