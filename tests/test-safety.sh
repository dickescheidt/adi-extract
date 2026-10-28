#!/usr/bin/env bash
# Build the parser under AddressSanitizer + UBSan and run the safety cases.
set -euo pipefail
cd "$(dirname "$0")/.."
CXX="${CXX:-g++}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

FLAGS=(-std=c++17 -O1 -g -fno-omit-frame-pointer
       -fsanitize=address,undefined -Isrc -Wall -Wextra)

for f in adi_file codec image image_set records; do
    "$CXX" "${FLAGS[@]}" -c "src/$f.cpp" -o "$TMP/$f.o"
done
"$CXX" "${FLAGS[@]}" -c tests/test-safety.cpp -o "$TMP/test.o"
"$CXX" "${FLAGS[@]}" "$TMP/test.o" "$TMP/adi_file.o" "$TMP/codec.o" "$TMP/image.o" \
    "$TMP/image_set.o" "$TMP/records.o" -o "$TMP/test-safety"

ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
    "$TMP/test-safety"
