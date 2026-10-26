#!/usr/bin/env python3
"""Generate a tiny synthetic AOMEI-style .adi for smoke-testing the build.

It contains a BIFH header, two LZ4-literal blocks (one holding an NTFS boot
sector), a two-record block index, and a BIFT footer. NOT a real backup.
Usage: python3 tests/make_sample_adi.py sample.adi
"""
import struct
import sys

CLUSTER = 512
UNITS_PER_REGION = 262144 // CLUSTER          # 512
HDR = UNITS_PER_REGION // 8                   # 64-byte used-sector bitmap
TOTAL_SECTORS = 4096
HIDDEN_SECTORS = 2048


def boot_sector() -> bytes:
    b = bytearray(CLUSTER)
    b[0] = 0xEB
    b[1] = 0x52
    b[2] = 0x90
    b[3:11] = b"NTFS    "
    struct.pack_into("<H", b, 11, 512)        # bytes per sector
    b[13] = 1                                # sectors per cluster -> 512
    struct.pack_into("<H", b, 14, 1)          # reserved sectors
    struct.pack_into("<I", b, 28, HIDDEN_SECTORS)
    struct.pack_into("<Q", b, 40, TOTAL_SECTORS)
    struct.pack_into("<Q", b, 48, 16)         # MFT LCN
    b[510] = 0x55
    b[511] = 0xAA
    return bytes(b)


def block(payload: bytes) -> bytes:
    """One decompressed block: bitmap + only the clusters whose bits are set."""
    bitmap = bytearray(HDR)
    bitmap[0] = 0x01                          # unit 0 present
    return bytes(bitmap) + payload


def lz4_literals(data: bytes) -> bytes:
    """Encode as a single LZ4 literal run in the dialect adi-extract expects."""
    n = len(data)
    out = bytearray()
    token_lit = min(n, 15)
    token = token_lit << 4                    # low nibble = match length 0
    out.append(token)
    left = n - token_lit
    if token_lit == 15:
        while left >= 255:
            out.append(255)
            left -= 255
        out.append(left)
    out += data
    return bytes(out)


def record(off, usize, csize, stream, region) -> bytes:
    return struct.pack("<QIIIIII", off, usize, csize, 0, stream, region, 0)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "sample.adi"

    header = bytearray(0x40)
    header[0:4] = b"BIFH"
    struct.pack_into("<I", header, 4, len(header))
    struct.pack_into("<I", header, 8, 0)

    data = lz4_literals(block(boot_sector()))
    filler = bytes([0xC3]) * CLUSTER
    data2 = lz4_literals(block(filler))

    # resolve_regions() shifts the region field of record 0 onto block 1,
    # so record 0 carries the region of the *second* block (1).
    index = record(0, 576, len(data), 0, 1) + record(
        len(data), 576, len(data2), 0, 0
    )
    # scan_block_index() keeps a 64-byte overlap at the end of each chunk and
    # never treats those last 64 bytes as a record start, so leave padding.
    payload = data + data2 + index + bytes(256)

    footer = struct.pack("<III", 0, 0, 16) + b"BIFT"

    with open(path, "wb") as f:
        f.write(header)
        f.write(payload)
        f.write(footer)
    print(f"wrote {path} ({0x40 + len(payload) + len(footer)} bytes)")


if __name__ == "__main__":
    main()
