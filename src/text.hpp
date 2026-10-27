#pragma once
// Bounds-safe text conversion for the POSIX build.
//
// Upstream stores names as UTF-16LE and passes them around as `wchar_t*`.
// On Windows wchar_t is 2 bytes (UTF-16); on Linux/macOS it is 4 bytes
// (UTF-32). Reinterpreting on-disk UTF-16LE bytes as wchar_t therefore reads
// twice as many bytes as the format provides, which is an out-of-bounds read.
// All conversion goes through these helpers instead: they take an explicit
// element count, never assume sizeof(wchar_t), and combine surrogate pairs.

#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <string>
#include <vector>

namespace adi {
namespace text {

inline void append_utf8(std::string& out, uint32_t cp) {
    if (cp > 0x10ffffu || (cp >= 0xd800u && cp <= 0xdfffu)) {
        cp = 0xfffdu;  // U+FFFD REPLACEMENT CHARACTER
    }
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xc0u | (cp >> 6)));
        out.push_back(static_cast<char>(0x80u | (cp & 0x3fu)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xe0u | (cp >> 12)));
        out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3fu)));
        out.push_back(static_cast<char>(0x80u | (cp & 0x3fu)));
    } else {
        out.push_back(static_cast<char>(0xf0u | (cp >> 18)));
        out.push_back(static_cast<char>(0x80u | ((cp >> 12) & 0x3fu)));
        out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3fu)));
        out.push_back(static_cast<char>(0x80u | (cp & 0x3fu)));
    }
}

inline uint16_t rd16le(const uint8_t* p) {
    return static_cast<uint16_t>(static_cast<uint16_t>(p[0]) |
                                 (static_cast<uint16_t>(p[1]) << 8));
}

/// Decode exactly `units` UTF-16LE code units (2*units bytes) into UTF-8.
/// Lone or misordered surrogates become U+FFFD. Never reads past p + 2*units.
inline std::string utf16le_to_utf8(const uint8_t* p, size_t units) {
    std::string out;
    if (!p) {
        return out;
    }
    out.reserve(units);
    for (size_t i = 0; i < units; ++i) {
        uint32_t cp = rd16le(p + 2 * i);
        if (cp >= 0xd800u && cp <= 0xdbffu && i + 1 < units) {
            const uint32_t lo = rd16le(p + 2 * (i + 1));
            if (lo >= 0xdc00u && lo <= 0xdfffu) {
                cp = 0x10000u + ((cp - 0xd800u) << 10) + (lo - 0xdc00u);
                ++i;
            } else {
                cp = 0xfffdu;
            }
        } else if (cp >= 0xd800u && cp <= 0xdfffu) {
            cp = 0xfffdu;
        }
        append_utf8(out, cp);
    }
    return out;
}

/// Decode `n` UTF-8 bytes into code points. Malformed or truncated sequences
/// produce U+FFFD and consume only the leading byte, so the loop always
/// advances and never reads past src + n.
inline std::vector<uint32_t> utf8_to_codepoints(const char* src, size_t n) {
    std::vector<uint32_t> out;
    if (!src) {
        return out;
    }
    size_t i = 0;
    while (i < n) {
        const auto c = static_cast<unsigned char>(src[i]);
        uint32_t cp = 0;
        size_t extra = 0;
        uint32_t min_cp = 0;
        if (c < 0x80) {
            cp = c;
        } else if (c >= 0xc2 && c <= 0xdf) {
            cp = c & 0x1fu;
            extra = 1;
            min_cp = 0x80;
        } else if (c >= 0xe0 && c <= 0xef) {
            cp = c & 0x0fu;
            extra = 2;
            min_cp = 0x800;
        } else if (c >= 0xf0 && c <= 0xf4) {
            cp = c & 0x07u;
            extra = 3;
            min_cp = 0x10000;
        } else {
            out.push_back(0xfffdu);
            ++i;
            continue;
        }
        if (i + extra >= n) {
            out.push_back(0xfffdu);
            ++i;
            continue;
        }
        bool bad = false;
        for (size_t k = 1; k <= extra; ++k) {
            const auto cc = static_cast<unsigned char>(src[i + k]);
            if ((cc & 0xc0u) != 0x80u) {
                bad = true;
                break;
            }
            cp = (cp << 6) | (cc & 0x3fu);
        }
        if (bad || cp < min_cp || cp > 0x10ffffu ||
            (cp >= 0xd800u && cp <= 0xdfffu)) {
            out.push_back(0xfffdu);
            ++i;
            continue;
        }
        out.push_back(cp);
        i += extra + 1;
    }
    return out;
}

inline void append_wchar(std::wstring& out, uint32_t cp) {
    if constexpr (sizeof(wchar_t) == 2) {
        // Windows: emit a UTF-16 surrogate pair.
        if (cp > 0x10ffffu || (cp >= 0xd800u && cp <= 0xdfffu)) {
            cp = 0xfffdu;
        }
        if (cp >= 0x10000u) {
            const uint32_t v = cp - 0x10000u;
            out.push_back(static_cast<wchar_t>(0xd800u + (v >> 10)));
            out.push_back(static_cast<wchar_t>(0xdc00u + (v & 0x3ffu)));
        } else {
            out.push_back(static_cast<wchar_t>(cp));
        }
    } else {
        out.push_back(static_cast<wchar_t>(cp));
    }
}

/// UTF-16LE bytes -> wstring, correct on both 2-byte and 4-byte wchar_t.
inline std::wstring utf16le_to_wstring(const uint8_t* p, size_t units) {
    std::wstring out;
    if (!p) {
        return out;
    }
    out.reserve(units);
    for (size_t i = 0; i < units; ++i) {
        uint32_t cp = rd16le(p + 2 * i);
        if (cp >= 0xd800u && cp <= 0xdbffu && i + 1 < units) {
            const uint32_t lo = rd16le(p + 2 * (i + 1));
            if (lo >= 0xdc00u && lo <= 0xdfffu) {
                cp = 0x10000u + ((cp - 0xd800u) << 10) + (lo - 0xdc00u);
                ++i;
            } else {
                cp = 0xfffdu;
            }
        } else if (cp >= 0xd800u && cp <= 0xdfffu) {
            cp = 0xfffdu;
        }
        append_wchar(out, cp);
    }
    return out;
}

/// wstring -> UTF-8. On 2-byte wchar_t, combines surrogate pairs.
inline std::string wstring_to_utf8(const wchar_t* src, size_t n) {
    std::string out;
    if (!src) {
        return out;
    }
    out.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        uint32_t cp = static_cast<uint32_t>(src[i]);
        if constexpr (sizeof(wchar_t) == 2) {
            if (cp >= 0xd800u && cp <= 0xdbffu && i + 1 < n) {
                const uint32_t lo = static_cast<uint32_t>(src[i + 1]);
                if (lo >= 0xdc00u && lo <= 0xdfffu) {
                    cp = 0x10000u + ((cp - 0xd800u) << 10) + (lo - 0xdc00u);
                    ++i;
                } else {
                    cp = 0xfffdu;
                }
            } else if (cp >= 0xd800u && cp <= 0xdfffu) {
                cp = 0xfffdu;
            }
        }
        append_utf8(out, cp);
    }
    return out;
}

inline std::wstring utf8_to_wstring(const char* src, size_t n) {
    const auto cps = utf8_to_codepoints(src, n);
    std::wstring out;
    out.reserve(cps.size());
    for (uint32_t cp : cps) {
        append_wchar(out, cp);
    }
    return out;
}

}  // namespace text
}  // namespace adi
