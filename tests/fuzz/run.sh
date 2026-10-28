#!/bin/sh
# Bounded coverage-guided fuzzing with Clang libFuzzer + ASan/UBSan.
# Optional: this is not part of `make test`. Usage: tests/fuzz/run.sh [seconds]
set -eu
seconds=${1:-60}
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$root"
: "${FUZZ_CXX:=clang++}"
if ! command -v "$FUZZ_CXX" >/dev/null 2>&1; then
    echo "$FUZZ_CXX not found: install Clang with compiler-rt (libclang-rt-dev)" >&2
    exit 1
fi
python3 tests/fuzz/prepare.py
for target in codec records image_file legacy; do
    echo "== $target (${seconds}s per target)"
    max_len=4096
    [ "$target" = image_file ] && max_len=65536
    # LeakSanitizer cannot run under ptrace-sandboxed environments, so disable
    # it here; descriptor leaks are covered by tests/test-safety.cpp instead.
    env ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
        "target/fuzz/$target" "target/fuzz/corpus/$target" -dict=tests/fuzz/adi.dict \
        -max_total_time="$seconds" -max_len="$max_len" -timeout=5 \
        -rss_limit_mb=768 -artifact_prefix=target/fuzz/artifacts/
done
