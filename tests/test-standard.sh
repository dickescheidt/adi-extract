#!/usr/bin/env bash
# Standard 0x201/0x202/0x109 record path and image-set member translation.
set -euo pipefail
cd "$(dirname "$0")/.."
make -s
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

python3 tests/make_standard_adi.py "$TMP/standard.adi" single > /dev/null
python3 tests/make_standard_adi.py "$TMP/split.adi" split > /dev/null

echo "== standard record parsing =="
./adi-extract info "$TMP/standard.adi" > "$TMP/info" 2>&1
grep -q "standard record path: 1 volume set(s), 2 VDB entries" "$TMP/info"
grep -q "delta 0x65c" "$TMP/info"
grep -q "8 clusters/block x 64 sectors/cluster x 512 B" "$TMP/info"
grep -q "metadata: LBA 2048, 4096 sectors" "$TMP/info"
grep -q "modes:      compress 1, encrypt 0" "$TMP/info"
grep -q "BRCrc32 valid" "$TMP/info"
grep -q "DataOffInSet 0x0, DataLenInSet" "$TMP/info"

./adi-extract reconstruct "$TMP/standard.adi" "$TMP/standard.img" > "$TMP/rec" 2>&1
grep -q "map: standard 0x201/0x202/0x109 records" "$TMP/rec"
grep -q "6 units placed, 2 BRCrc32 checked, 0 bad" "$TMP/rec"
python3 tests/check_standard.py "$TMP/standard.img" 3163136
echo "  single member: OK"

echo "== image-set member offset translation =="
MEMBER="$TMP/split.adi.member1.adi"
ADI_EXTRACT_MEMBERS="$MEMBER" ./adi-extract info "$TMP/split.adi" > "$TMP/sinfo" 2>&1
grep -q "logical 0x20700..0x30800" "$TMP/sinfo"
ADI_EXTRACT_MEMBERS="$MEMBER" ./adi-extract reconstruct "$TMP/split.adi" \
    "$TMP/split.img" > "$TMP/srec" 2>&1
grep -q "6 units placed, 2 BRCrc32 checked, 0 bad" "$TMP/srec"
python3 tests/check_standard.py "$TMP/split.img" 3163136
cmp "$TMP/standard.img" "$TMP/split.img"

# Without the extra member the second VDB block is unreachable: fail loudly.
if ./adi-extract reconstruct "$TMP/split.adi" "$TMP/missing.img" > "$TMP/missing" 2>&1; then
    echo "missing image-set member was not detected"; exit 1
fi
grep -qi "not covered by any member" "$TMP/missing"
echo "  split set: OK"

# Containers without image-set fields must still take the legacy path.
python3 tests/make_sample_adi.py "$TMP/legacy.adi" sample > /dev/null
./adi-extract reconstruct "$TMP/legacy.adi" "$TMP/legacy.img" > "$TMP/legacy.log" 2>&1
grep -q "no standard record sets; using legacy signature scan" "$TMP/legacy.log"
echo "  legacy fallback: OK"

echo "STANDARD TESTS PASSED"

python3 tests/test_boundary.py ./adi-extract cpp

python3 tests/test_warnings.py ./adi-extract cpp

python3 tests/test_properties.py ./adi-extract cpp
python3 tests/test_malformed.py ./adi-extract cpp
python3 tests/test_trace.py ./adi-extract cpp
