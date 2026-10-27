#!/usr/bin/env bash
# Regression test: a 4-partition disk stored as one contiguous block chain.
set -euo pipefail
cd "$(dirname "$0")/.."
make -s
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

python3 tests/make_multipart_adi.py "$TMP/multipart.adi" > /dev/null
./adi-extract reconstruct "$TMP/multipart.adi" "$TMP/disk.img" > "$TMP/log" 2>&1

grep -q "boot sectors: 4" "$TMP/log"
grep -q "layout: whole-disk stream" "$TMP/log"
grep -q "4 partitions" "$TMP/log"
grep -q "8 units placed" "$TMP/log"
! grep -q "units outside their volume" "$TMP/log"

python3 - "$TMP/disk.img" << 'PY'
import struct, sys
d = open(sys.argv[1], 'rb').read()
assert d[512:520] == b'EFI PART', 'primary GPT missing'
ents = d[1024:1024 + 128 * 128]
entries = [ents[i*128:(i+1)*128] for i in range(128)]
live = [e for e in entries if any(e[:16])]
assert len(live) == 4, f'expected 4 GPT entries, got {len(live)}'
for n, off in enumerate([1 << 20, 2 << 20, 3 << 20, 4 << 20]):
    assert d[off+3:off+11] == b'NTFS    ', f'partition {n} boot sector missing'
    assert d[off+510:off+512] == b'\x55\xaa', f'partition {n} signature missing'
assert d[1310720] == 0xA0, 'partition 1 data missing'
assert d[(3 << 20) + 262144] == 0xA2, 'partition 3 data missing'
assert d[(2 << 20) + 262144] == 0, 'zero cluster not preserved as a hole'
print('  all 4 partitions, markers and holes verified')
PY

# Sparse: allocated bytes must be far below apparent size.
apparent=$(stat -c %s "$TMP/disk.img")
allocated=$(( $(stat -c %b "$TMP/disk.img") * $(stat -c %B "$TMP/disk.img") ))
[[ "$allocated" -lt $((apparent / 10)) ]] || {
  echo "not sparse: allocated $allocated of $apparent"; exit 1;
}
echo "  sparse: $allocated allocated / $apparent apparent bytes"
echo "MULTIPART TEST PASSED"
