#!/usr/bin/env bash
# Regressions from the independent VDB format cross-check:
#   * BRCrc32 (CRC32C) is verified over decoded blocks
#   * a bad checksum is reported and only that block is skipped
#   * 32 KiB clusters with a 1-byte sparse bitmap are decoded, not dropped
#   * chain gaps no longer scramble an ordered index (see test-safety.cpp)
set -euo pipefail
cd "$(dirname "$0")/.."
make -s
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

python3 tests/make_sample_adi.py "$TMP/sample.adi" sample > /dev/null
python3 tests/make_sample_adi.py "$TMP/badcrc.adi" badcrc > /dev/null
python3 tests/make_sample_adi.py "$TMP/bigcluster.adi" bigcluster > /dev/null

echo "== info reports BRCrc32 records =="
./adi-extract info "$TMP/sample.adi" > "$TMP/info" 2>&1
grep -q "crcs:      2 records carry a BRCrc32 checksum" "$TMP/info"
echo "  info: OK"

echo "== reconstruct verifies decoded blocks =="
./adi-extract reconstruct "$TMP/sample.adi" "$TMP/sample.img" > "$TMP/log" 2>&1
grep -q "2 BRCrc32 checked, 0 bad" "$TMP/log"
grep -q "2 units placed" "$TMP/log"
python3 - "$TMP/sample.img" << 'PY'
import sys
d = open(sys.argv[1], 'rb').read()
assert d[510:512] == b'\x55\xaa', 'protective MBR missing'
assert d[512:520] == b'EFI PART', 'primary GPT missing'
assert d[1048576 + 510:1048576 + 512] == b'\x55\xaa', 'NTFS boot sector missing'
assert d[1310720] == 0xC3, 'second region missing'
print('  sample: OK')
PY

echo "== a bad checksum is reported and only that block skipped =="
./adi-extract reconstruct "$TMP/badcrc.adi" "$TMP/badcrc.img" > "$TMP/bad.log" 2>&1
grep -q "BRCrc32 mismatch" "$TMP/bad.log"
grep -q "2 BRCrc32 checked, 1 bad" "$TMP/bad.log"
python3 - "$TMP/badcrc.img" << 'PY'
import sys
d = open(sys.argv[1], 'rb').read()
assert d[1048576 + 510:1048576 + 512] == b'\x55\xaa', 'good block was skipped'
assert d[1310720] == 0, 'bad block was written despite checksum mismatch'
print('  badcrc: OK')
PY

echo "== 32 KiB sparse clusters =="
./adi-extract reconstruct "$TMP/bigcluster.adi" "$TMP/big.img" > "$TMP/big.log" 2>&1
grep -q "2 BRCrc32 checked, 0 bad" "$TMP/big.log"
! grep -q "unrecognised headers" "$TMP/big.log"
python3 - "$TMP/big.img" << 'PY'
import sys
REGION, C, ORIGIN = 256 * 1024, 32768, 2048 * 512
d = open(sys.argv[1], 'rb').read()
assert d[ORIGIN + 510:ORIGIN + 512] == b'\x55\xaa', 'boot sector missing'
assert d[ORIGIN + 13] == 64, '32 KiB geometry missing'
assert d[ORIGIN + C] == 0xA1, 'unit 1 missing'
assert not any(d[ORIGIN + 2*C:ORIGIN + 3*C]), 'unit 2 hole not preserved'
assert d[ORIGIN + 3*C] == 0xA3, 'unit 3 missing'
assert not any(d[ORIGIN + 4*C:ORIGIN + 6*C]), 'units 4-5 hole not preserved'
assert d[ORIGIN + 6*C] == 0xA6, 'unit 6 missing'
second = ORIGIN + REGION
assert d[second] == 0xB0, 'second region unit 0 missing'
assert not any(d[second + C:second + 7*C]), 'second region hole not preserved'
assert d[second + 7*C] == 0xB7, 'second region unit 7 missing'
print('  bigcluster: OK')
PY

echo "VDB TESTS PASSED"
