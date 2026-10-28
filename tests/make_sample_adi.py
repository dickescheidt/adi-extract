#!/usr/bin/env python3
"""Generate tiny synthetic AOMEI-style .adi files for the adi-extract tests.

Each image has a BIFH header, LZ4-literal blocks, a block index whose records
carry real AOMEI BRCrc32 checksums, and a BIFT footer. NOT a real backup.

Kinds:
  sample       two 512-byte-cluster blocks, one NTFS boot sector (default)
  badcrc       same, but the second block's checksum is deliberately wrong
  bigcluster   two 32 KiB-cluster blocks with a sparse 1-byte bitmap
  gaps         six blocks in three chain runs with strictly increasing regions

Usage: python3 tests/make_sample_adi.py OUTPUT.adi [KIND]
"""
import sys

from adi_fixture import boot_sector, build_adi, make_block

C512 = 512
C32K = 32768
HIDDEN = 2048
TOTAL = 4096


def sample(bad_crc=False) -> bytes:
    c = C512
    recipes = [
        {"decoded": make_block(c, {0: boot_sector(HIDDEN, TOTAL, 1)}),
         "raw_region": 1},
        {"decoded": make_block(c, {0: bytes([0xC3]) * c}),
         "raw_region": 0},
    ]
    return build_adi(recipes, bad_crc_indices={1} if bad_crc else ())


def bigcluster() -> bytes:
    c = C32K
    recipes = [
        {"decoded": make_block(c, {
            0: boot_sector(HIDDEN, TOTAL, 64),
            1: bytes([0xA1]) * c,
            3: bytes([0xA3]) * c,
            6: bytes([0xA6]) * c,
        }), "raw_region": 1},
        {"decoded": make_block(c, {
            0: bytes([0xB0]) * c,
            7: bytes([0xB7]) * c,
        }), "raw_region": 0},
    ]
    return build_adi(recipes)


def gaps() -> bytes:
    c = C512
    recipes = []
    for i in range(6):
        unit = boot_sector(HIDDEN, TOTAL, 1) if i == 0 else bytes([0xC3]) * c
        recipes.append({
            "decoded": make_block(c, {0: unit}),
            "raw_region": 100000 + i,
            "gap_before": 128 if i and i % 2 == 0 else 0,
        })
    return build_adi(recipes)


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "sample.adi"
    kind = sys.argv[2] if len(sys.argv) > 2 else "sample"
    kinds = {
        "sample": sample,
        "badcrc": lambda: sample(bad_crc=True),
        "bigcluster": bigcluster,
        "gaps": gaps,
    }
    data = kinds[kind]()
    with open(path, "wb") as f:
        f.write(data)
    print(f"wrote {path} ({len(data)} bytes, {kind})")


if __name__ == "__main__":
    main()
