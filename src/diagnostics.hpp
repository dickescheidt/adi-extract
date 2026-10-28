#pragma once

#include <iostream>
#include <streambuf>

namespace adi {

// Shared across translation units (C++17); set once when parsing the CLI.
inline bool debug_diagnostics = false;

inline std::ostream& debug_log() {
    class NullBuffer : public std::streambuf {
        int_type overflow(int_type c) override { return traits_type::not_eof(c); }
    };
    static NullBuffer buffer;
    static std::ostream sink(&buffer);
    return debug_diagnostics ? std::cerr : sink;
}

}  // namespace adi
