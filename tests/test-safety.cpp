// Safety regression tests. Include extract.cpp so the anonymous-namespace
// parsers are reachable, then build the whole thing under ASan+UBSan.
// Crafted MFT/FAT records below exercise the bounds and arithmetic bugs that
// the synthetic .adi images never reach.

#include "../src/extract.cpp"
#include "../src/text.hpp"

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

using namespace adi;

static void put16(uint8_t* p, uint16_t v) {
    p[0] = uint8_t(v);
    p[1] = uint8_t(v >> 8);
}
static void put32(uint8_t* p, uint32_t v) {
    for (int i = 0; i < 4; ++i) p[i] = uint8_t(v >> (8 * i));
}

static void test_text_helpers() {
    // "A" + U+1F600 (surrogate pair) + "BC", UTF-16LE.
    const uint8_t u16[] = {0x41, 0x00, 0x3d, 0xd8, 0x00, 0xde,
                           0x42, 0x00, 0x43, 0x00};
    const size_t units = sizeof(u16) / 2;

    // Allocate EXACTLY the bytes the format provides: any over-read is an
    // ASan error. The old reinterpret_cast<const wchar_t*> read 2x this.
    auto exact = std::make_unique<uint8_t[]>(sizeof(u16));
    std::memcpy(exact.get(), u16, sizeof(u16));
    const std::string utf8 = text::utf16le_to_utf8(exact.get(), units);
    assert(utf8 == "A\xF0\x9F\x98\x80" "BC");
    const std::wstring wide = text::utf16le_to_wstring(exact.get(), units);
    assert(wide.size() == 4);  // A, emoji, B, C (surrogate pair combined)
    assert(text::wstring_to_utf8(wide.data(), wide.size()) == utf8);
    assert(text::utf8_to_wstring(utf8.data(), utf8.size()) == wide);

    // Lone surrogates become U+FFFD rather than reading past the buffer.
    const uint8_t lone[] = {0x3d, 0xd8, 0x41, 0x00, 0x00, 0xde};
    auto lonebuf = std::make_unique<uint8_t[]>(sizeof(lone));
    std::memcpy(lonebuf.get(), lone, sizeof(lone));
    const std::string bad = text::utf16le_to_utf8(lonebuf.get(), 3);
    assert(bad == "\xEF\xBF\xBD" "A" "\xEF\xBF\xBD");

    // Truncated / overlong / out-of-range UTF-8 must not loop or over-read.
    const char malformed[] = {'a', char(0xf0), char(0x9f), char(0xc0), char(0x80),
                              char(0xf5), char(0x80), char(0x80), char(0x80)};
    auto bad8 = std::make_unique<char[]>(sizeof(malformed));
    std::memcpy(bad8.get(), malformed, sizeof(malformed));
    const auto cps = text::utf8_to_codepoints(bad8.get(), sizeof(malformed));
    assert(cps.size() >= 4 && cps[0] == 'a');
    for (uint32_t cp : cps) assert(cp <= 0x10ffffu);
}

static void test_shim_conversions() {
    const wchar_t* w = L"Grüße \U0001F600";
    const int need = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    assert(need > 0);
    std::string s(size_t(need), '\0');
    assert(WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), need, nullptr, nullptr) == need);
    assert(s.find("Gr") == 0);
    // A too-small destination must fail cleanly, never overflow.
    char tiny[2] = {};
    assert(WideCharToMultiByte(CP_UTF8, 0, w, -1, tiny, 2, nullptr, nullptr) == 0);
    assert(WideCharToMultiByte(CP_UTF8, 0, nullptr, 0, tiny, 2, nullptr, nullptr) == 0);

    const int wn = MultiByteToWideChar(CP_UTF8, 0, s.data(), -1, nullptr, 0);
    assert(wn > 0);
    std::wstring back(size_t(wn), L'\0');
    assert(MultiByteToWideChar(CP_UTF8, 0, s.data(), -1, back.data(), wn) == wn);
    wchar_t tinyw[1] = {};
    assert(MultiByteToWideChar(CP_UTF8, 0, s.data(), -1, tinyw, 1) == 0);
    assert(MultiByteToWideChar(CP_UTF8, 0, nullptr, 0, tinyw, 1) == 0);

    // UNC prefix must be handled before the short \\?\ prefix.
    assert(win32_shim_detail::normalize("\\\\?\\UNC\\server\\share\\x") ==
           "//server/share/x");
    assert(win32_shim_detail::normalize("\\\\?\\C:\\x") == "C:/x");
    assert(win32_shim_detail::narrow_path(L"/tmp/café") == "/tmp/café");
}

static std::vector<uint8_t> mft_record() {
    std::vector<uint8_t> rec(1024, 0);
    std::memcpy(rec.data(), "FILE", 4);
    put16(rec.data() + 0x14, 0x30);            // first attribute offset
    put32(rec.data() + 0x18, uint32_t(rec.size()));  // used size
    return rec;
}

static void write_filename_attr(std::vector<uint8_t>& rec, const uint16_t* name,
                                size_t units) {
    uint8_t* a = rec.data() + 0x30;
    put32(a, 0x30);              // $FILE_NAME
    put32(a + 4, 0x18 + 0x60);  // attribute length
    a[8] = 0;                   // resident
    a[9] = 0;                   // unnamed
    put32(a + 0x10, 0x60);      // value length
    put16(a + 0x14, 0x18);      // value offset
    uint8_t* v = a + 0x18;
    v[0x40] = uint8_t(units);
    v[0x41] = 3;                // POSIX name space
    for (size_t i = 0; i < units; ++i) put16(v + 0x42 + 2 * i, name[i]);
}

static void test_mft_bounds() {
    {
        auto rec = mft_record();
        const uint16_t name[] = {0x41, 0xd83d, 0xde00, 0x42, 0x43};
        write_filename_attr(rec, name, 5);
        const NameInfo ni = read_name(rec);
        assert(ni.space == 3);
        assert(ni.name.size() == 4);  // A, U+1F600, B, C
        assert(static_cast<uint32_t>(ni.name[1]) == 0x1f600u);
    }
    {
        // Attribute length near UINT32_MAX: `p + len` pointer overflow.
        auto rec = mft_record();
        put32(rec.data() + 0x34, 0xfffffff0u);
        (void)read_name(rec);
        (void)read_attr(NtfsVolume{}, rec, 0x80, true);
    }
    {
        // voff + vlen wraps to a small value in uint32 arithmetic.
        auto rec = mft_record();
        uint8_t* a = rec.data() + 0x30;
        put32(a, 0x30);
        put32(a + 4, 0x70);
        a[8] = 0;
        put32(a + 0x10, 0xfffffff0u);  // vlen
        put16(a + 0x14, 0x18);         // voff
        (void)read_name(rec);
        (void)read_attr(NtfsVolume{}, rec, 0x30, true);
    }
    {
        // First-attribute offset beyond the record.
        auto rec = mft_record();
        put16(rec.data() + 0x14, 0xffff);
        (void)read_name(rec);
        (void)read_attr(NtfsVolume{}, rec, 0x80, true);
    }
    {
        // Tiny record: no 0x1c bytes to read.
        std::vector<uint8_t> rec(8, 0);
        (void)read_name(rec);
        (void)read_attr(NtfsVolume{}, rec, 0x80, true);
    }
}

static void test_runs_and_fixup() {
    {
        // noff=8 with the sign bit set: old code left-shifted a negative
        // int64_t, which is UB and UBSan reports.
        uint8_t buf[16] = {};
        buf[0] = 0x81;                 // nlen=1, noff=8
        buf[1] = 0x10;                 // count = 16
        for (int i = 0; i < 8; ++i) buf[2 + i] = uint8_t(i);
        buf[9] = 0x80;                 // negative offset
        std::vector<Run> runs;
        assert(parse_runs(buf, buf + sizeof(buf), &runs));
        assert(runs.size() == 1 && runs[0].count == 16 && runs[0].sparse == false);
    }
    {
        uint8_t zero[4] = {0x10, 0, 0, 0};  // nlen=1, noff=0, count=0
        std::vector<Run> runs;
        assert(!parse_runs(zero, zero + sizeof(zero), &runs));  // zero-length rejected
    }
    {
        NtfsVolume vol;
        std::vector<uint8_t> rec(1024, 0);
        put16(rec.data() + 4, 0xffff);  // usa
        put16(rec.data() + 6, 0xffff);  // usc
        vol.fixup(rec.data(), rec.size());
        put16(rec.data() + 4, 1000);
        put16(rec.data() + 6, 100);
        vol.fixup(rec.data(), rec.size());
        vol.sector_size = 0;           // must not divide by zero
        vol.fixup(rec.data(), rec.size());
    }
    {
        // A huge sparse run must neither hang nor write past the buffer.
        NtfsVolume vol;
        vol.cluster_size = 4096;
        std::vector<Run> runs(1);
        runs[0].vcn = 0;
        runs[0].count = UINT64_MAX / 2;
        runs[0].sparse = true;
        uint8_t buf[64] = {};
        assert(vol.read_runs(runs, 0, buf, sizeof(buf)));
    }
}

// --- VDB cross-check regressions ------------------------------------------

static void test_cluster_label() {
    assert(cluster_label({}, 4096) == "4096");
    assert(cluster_label({4096}, 512) == "4096");
    assert(cluster_label({4096, 32768}, 4096) == "mixed (4096, 32768)");
    std::cout << "  cluster sizes: mixed-region line\n";
}

static void test_br_crc32() {
    // AOMEI Encrypt.dll!BRCrc32 is CRC32C, not zlib's CRC32.
    const uint8_t* empty = reinterpret_cast<const uint8_t*>("");
    const uint8_t* digits = reinterpret_cast<const uint8_t*>("123456789");
    const uint8_t* aomei = reinterpret_cast<const uint8_t*>("AOMEI");
    assert(br_crc32(empty, 0) == 0xFFFFFFFFu);
    assert(br_crc32(digits, 9) == 0xA71C05DFu);
    assert(br_crc32(aomei, 5) == 0xEB000F91u);

    std::vector<uint8_t> data = {'a', 'b', 'c'};
    BlockRec b;
    assert(block_crc_ok(b, data.data(), data.size()));  // crc == 0 -> unchecked
    b.crc = br_crc32(data.data(), data.size());
    assert(block_crc_ok(b, data.data(), data.size()));
    b.crc ^= 1u;
    assert(!block_crc_ok(b, data.data(), data.size()));
}

static void test_resolve_regions() {
    // Six blocks in three chain runs with strictly increasing raw regions.
    // A VDB entry's BlockNo describes the *next* block, so the correct result
    // is one global one-record shift. Chain gaps must NOT reset a run head to
    // the lowest free region number (that used to invent huge backward jumps).
    std::vector<BlockRec> blocks(6);
    for (size_t i = 0; i < blocks.size(); ++i) {
        blocks[i].off = 4096 * i + (i / 2) * 128;
        blocks[i].csize = 4096;
        blocks[i].region = 100000 + static_cast<uint32_t>(i);
        blocks[i].stream = 0;
    }
    std::ostringstream progress;
    resolve_regions(blocks, progress);
    assert(blocks[0].region == 0);
    for (size_t i = 1; i < blocks.size(); ++i) {
        assert(blocks[i].region == 100000 + static_cast<uint32_t>(i - 1));
        assert(blocks[i].region > blocks[i - 1].region);
    }
}

static void test_split_block_32k() {
    // A real sparse C: region uses 32 KiB clusters: a 1-byte bitmap followed
    // by only the present clusters. hdr == 1 is NOT "all units present".
    std::vector<uint8_t> buf(1 + 3 * 32768, 0x5A);
    buf[0] = 0x49;  // bits 0, 3, 6
    BlockLayout lay;
    assert(split_block(buf.data(), static_cast<uint32_t>(buf.size()), 32768, &lay));
    assert(lay.hdr == 1 && lay.cluster == 32768 && lay.units == 3);
    assert(!lay.all_present);
    assert(unit_present(buf.data(), lay, 0));
    assert(!unit_present(buf.data(), lay, 1));
    assert(!unit_present(buf.data(), lay, 2));
    assert(unit_present(buf.data(), lay, 3));
    assert(!unit_present(buf.data(), lay, 5));
    assert(unit_present(buf.data(), lay, 6));
    assert(!unit_present(buf.data(), lay, 7));
    assert(!unit_present(buf.data(), lay, 8));  // beyond the bitmap

    std::vector<uint8_t> one(1 + 32768, 0x00);
    one[0] = 0x01;
    assert(split_block(one.data(), static_cast<uint32_t>(one.size()), 32768, &lay));
    assert(!lay.all_present && lay.units == 1);
    assert(unit_present(one.data(), lay, 0));
    assert(!unit_present(one.data(), lay, 1));

    // usize == 1 + kRegion really is the "all present" shorthand.
    std::vector<uint8_t> all(1 + kRegion, 0x11);
    all[0] = 0x01;
    assert(split_block(all.data(), static_cast<uint32_t>(all.size()), 0, &lay));
    assert(lay.all_present && lay.units == kRegion / lay.cluster);
    assert(unit_present(all.data(), lay, 7));
}

// --- Standard records / image-set translation -----------------------------

static void putbytes(std::vector<uint8_t>& b, size_t off, const void* p, size_t n) {
    if (off + n > b.size()) {
        b.resize(off + n, 0);
    }
    std::memcpy(b.data() + off, p, n);
}

static void test_container_fields_and_members() {
    // A real-size BIFH/BIFT pair with DataOffInSet/DataLenInSet and valid
    // BRCrc32 in both framing records.
    const uint32_t head_size = 0x65c;
    const uint32_t tail_size = 0x674;
    const uint64_t payload = 0x800;
    std::vector<uint8_t> image(head_size + payload + tail_size, 0);
    std::memcpy(image.data(), "BIFH", 4);
    std::vector<uint8_t> head(image.begin(), image.begin() + head_size);
    put32(head.data() + 4, head_size);
    head[8] = head[9] = head[10] = head[11] = 0;
    put32(head.data() + 8, br_crc32(head.data(), head.size()));
    std::copy(head.begin(), head.end(), image.begin());

    std::vector<uint8_t> tail(tail_size, 0);
    const uint64_t data_len = 0x500;
    const uint64_t data_off = 0x1000;
    putbytes(tail, 0x620, &data_len, 8);
    putbytes(tail, 0x628, &data_off, 8);
    put32(tail.data() + tail_size - 8, tail_size);
    std::memcpy(tail.data() + tail_size - 4, "BIFT", 4);
    std::fill(tail.begin() + tail_size - 12, tail.begin() + tail_size - 8, 0);
    put32(tail.data() + tail_size - 12, br_crc32(tail.data(), tail.size()));
    std::copy(tail.begin(), tail.end(), image.begin() + head_size + payload);

    const auto dir = std::filesystem::temp_directory_path();
    const auto path = dir / "adi-extract-safety-member.adi";
    { std::ofstream f(path, std::ios::binary);
      f.write(reinterpret_cast<const char*>(image.data()),
              static_cast<std::streamsize>(image.size())); }
    const auto f = parse_container_fields(path);
    assert(f.header_size == head_size && f.tail_size == tail_size);
    assert(f.has_image_set);
    assert(f.data_offset_in_set == data_off && f.data_length_in_set == data_len);
    assert(f.header_crc_valid && f.tail_crc_valid);

    // The physical read for a logical offset must add BIFH.size.
    const auto set = ImageSet::from_paths({path});
    assert(set.members().size() == 1);
    const auto at = set.read_vec(data_off + 0x10, 8);
    assert(at.size() == 8);
    (void)at;
    // An offset outside the member's logical range is an error, not a raw seek.
    bool threw = false;
    try {
        (void)set.read_vec(data_off + data_len + 1, 4);
    } catch (const std::exception&) {
        threw = true;
    }
    assert(threw);
    std::filesystem::remove(path);

    setenv("ADI_EXTRACT_SAFETY_MEMBERS", "/tmp/a.adi:/tmp/b.adi", 1);
    const auto parts = extra_member_paths("ADI_EXTRACT_SAFETY_MEMBERS");
    assert(parts.size() == 2 && parts[0] == "/tmp/a.adi" && parts[1] == "/tmp/b.adi");
    unsetenv("ADI_EXTRACT_SAFETY_MEMBERS");
    assert(extra_member_paths("ADI_EXTRACT_SAFETY_MEMBERS").empty());
}

static void test_lz4_decode_buffer() {
    // Token 0x40 = 4 literals, then the four bytes. decode_buffer must work
    // with a fresh window and no backing block chain.
    const uint8_t comp[] = {0x40, 'A', 'B', 'C', 'D'};
    const std::vector<adi::BlockRec> none;
    // No AdiFile is needed: decode_buffer never reads from the file. We still
    // need an object, so reuse the temp container from the previous test.
    const auto dir = std::filesystem::temp_directory_path();
    const auto path = dir / "adi-extract-safety-stub.adi";
    std::vector<uint8_t> stub(0x40 + 64 + 16, 0);
    std::memcpy(stub.data(), "BIFH", 4);
    put32(stub.data() + 4, 0x40);
    put32(stub.data() + 0x40 + 64 + 8, 16);
    std::memcpy(stub.data() + 0x40 + 64 + 12, "BIFT", 4);
    { std::ofstream f(path, std::ios::binary);
      f.write(reinterpret_cast<const char*>(stub.data()),
              static_cast<std::streamsize>(stub.size())); }
    adi::AdiFile file(path);
    adi::Lz4Stream dec(file, none);
    const uint8_t* out = nullptr;
    size_t n = 0;
    assert(dec.decode_buffer(comp, sizeof(comp), 4, &out, &n));
    assert(n == 4 && std::memcmp(out, "ABCD", 4) == 0);
    // A fresh call must not inherit the previous block's output.
    const uint8_t comp2[] = {0x20, 'X', 'Y'};
    assert(dec.decode_buffer(comp2, sizeof(comp2), 2, &out, &n));
    assert(n == 2 && std::memcmp(out, "XY", 2) == 0);
    const uint8_t repeat[] = {0x1f, 'A', 1, 0, 0};
    assert(dec.decode_buffer(repeat, sizeof(repeat), 20, &out, &n));
    assert(n == 20 && std::all_of(out, out + n, [](uint8_t b) { return b == 'A'; }));
    for (const auto &bad :
         std::vector<std::vector<uint8_t>>{{0xf0}, {0x10, 'X', 0}, {0, 0, 0}, {0x1f, 'A', 1, 0}}) {
        assert(!dec.decode_buffer(bad.data(), bad.size(), 64, &out, &n));
    }
    uint32_t state = 0x15a4e35u;
    for (size_t test = 0; test < 4096; ++test) {
        std::vector<uint8_t> input(test % 129);
        for (auto &byte : input) {
            state = state * 1664525u + 1013904223u;
            byte = static_cast<uint8_t>(state >> 24);
        }
        (void)dec.decode_buffer(input.data(), input.size(), 1u << 20, &out, &n);
        assert(dec.decode_buffer(comp, sizeof(comp), 4, &out, &n));
        assert(n == 4 && std::memcmp(out, "ABCD", 4) == 0);
    }
    // A match-length extension encodes 255 output bytes per input byte. The
    // declared decoded size must cap it instead of growing the buffer.
    std::vector<uint8_t> bomb = {0x1f, 'A', 0x01, 0x00};
    bomb.insert(bomb.end(), 200, 0xff);
    bomb.push_back(0x00);
    assert(dec.decode_buffer(bomb.data(), bomb.size(), 1u << 20, &out, &n));
    const size_t expanded = n;
    assert(expanded > 4096);
    assert(!dec.decode_buffer(bomb.data(), bomb.size(), 4096, &out, &n));
    assert(!dec.decode_buffer(bomb.data(), bomb.size(), expanded - 1, &out, &n));
    assert(dec.decode_buffer(bomb.data(), bomb.size(), expanded, &out, &n));
    std::filesystem::remove(path);
}

static void test_gpt_name_encoding() {
    // GPT entry names are UTF-16LE; a UTF-8 label must not degrade to one '?'
    // per byte, and astral characters must become a surrogate pair.
    const std::string name = "DATEN-\xc3\x84\xc3\x96\xc3\x9c";  // DATEN-ÄÖÜ
    const std::string u16 = adi::text::utf8_to_utf16le(name);
    assert(u16.size() == 2 * 9);  // 6 ASCII + 3 two-byte characters
    assert(static_cast<uint8_t>(u16[12]) == 0xc4 && static_cast<uint8_t>(u16[13]) == 0x00);
    const std::string pair = adi::text::utf8_to_utf16le("\xf0\x9f\x92\xbe");  // U+1F4BE
    assert(pair.size() == 4);
    const uint16_t hi =
        static_cast<uint8_t>(pair[0]) | (static_cast<uint16_t>(static_cast<uint8_t>(pair[1])) << 8);
    const uint16_t lo =
        static_cast<uint8_t>(pair[2]) | (static_cast<uint16_t>(static_cast<uint8_t>(pair[3])) << 8);
    assert(hi == 0xd83d && lo == 0xdcbe);
    // Invalid UTF-8 must not read past the end or emit a lone surrogate.
    const std::string junk("\xf0\x28\x8c\x28", 4);
    const std::string j16 = adi::text::utf8_to_utf16le(junk);
    assert(j16.size() % 2 == 0);
    for (size_t i = 0; i + 1 < j16.size(); i += 2) {
        const uint16_t unit =
            static_cast<uint8_t>(j16[i]) |
            (static_cast<uint16_t>(static_cast<uint8_t>(j16[i + 1])) << 8);
        assert(!(unit >= 0xd800u && unit <= 0xdbffu));
    }
}

static void test_malformed_container_construction_does_not_leak() {
#if defined(__linux__)
    // Fuzzing exhausted the descriptor limit because a constructor that threw
    // after opening the file never ran ~AdiFile. Both failure points matter.
    const auto dir = std::filesystem::temp_directory_path();
    const auto short_path = dir / "adi-extract-safety-short.adi";
    const auto bad_path = dir / "adi-extract-safety-bad-header.adi";
    { std::ofstream f(short_path, std::ios::binary); f << "short"; }
    { std::ofstream f(bad_path, std::ios::binary);
      std::vector<char> junk(4096, 'Z');
      f.write(junk.data(), static_cast<std::streamsize>(junk.size())); }
    const auto count_fds = [] {
        size_t n = 0;
        for (const auto& entry : std::filesystem::directory_iterator("/proc/self/fd")) {
            (void)entry;
            ++n;
        }
        return n;
    };
    const size_t before = count_fds();
    for (int i = 0; i < 600; ++i) {
        for (const auto& path : {short_path, bad_path}) {
            bool rejected = false;
            try {
                adi::AdiFile file(path);
            } catch (const std::exception&) {
                rejected = true;
            }
            assert(rejected && "malformed container was accepted");
        }
    }
    assert(count_fds() <= before + 8 && "failed constructions leaked descriptors");
    std::filesystem::remove(short_path);
    std::filesystem::remove(bad_path);
#endif
}

int main() {
    test_text_helpers();
    test_shim_conversions();
    test_mft_bounds();
    test_runs_and_fixup();
    test_cluster_label();
    test_br_crc32();
    test_resolve_regions();
    test_split_block_32k();
    test_container_fields_and_members();
    test_lz4_decode_buffer();
    test_gpt_name_encoding();
    test_malformed_container_construction_does_not_leak();
    std::cout << "SAFETY TESTS PASSED\n";
    return 0;
}
