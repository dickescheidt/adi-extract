// Safety regression tests. Include extract.cpp so the anonymous-namespace
// parsers are reachable, then build the whole thing under ASan+UBSan.
// Crafted MFT/FAT records below exercise the bounds and arithmetic bugs that
// the synthetic .adi images never reach.

#include "../src/extract.cpp"

#include <cassert>
#include <cstring>
#include <iostream>
#include <memory>
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

int main() {
    test_text_helpers();
    test_shim_conversions();
    test_mft_bounds();
    test_runs_and_fixup();
    std::cout << "SAFETY TESTS PASSED\n";
    return 0;
}
