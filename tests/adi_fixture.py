#!/usr/bin/env python3
"""Shared helpers for adi-extract's synthetic .adi fixtures.

The 32-byte records built here are the window the signature scanner finds: a
real VDB index entry read 12 bytes late. Field 4 (offset 16) is the VDB
``Crc32``, i.e. ``Encrypt.dll!BRCrc32`` over the *decoded* block bytes.
"""
import struct

REGION = 256 * 1024
SECTOR = 512

_POLY = 0x82F63B78
_TAB = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ _POLY if _c & 1 else _c >> 1
    _TAB.append(_c)


def br_crc32(data: bytes) -> int:
    """CRC32C/Castagnoli, zero seed, final inversion (AOMEI BRCrc32)."""
    crc = 0
    for b in data:
        crc = (crc >> 8) ^ _TAB[(crc ^ b) & 0xFF]
    return (~crc) & 0xFFFFFFFF


def record(off, usize, csize, stream, region, crc=0) -> bytes:
    """One 32-byte block-index record as seen by the scanner."""
    return struct.pack("<QIIIIII", off, usize, csize, crc, stream, region, 0)


def lz4_literals(data: bytes) -> bytes:
    """One LZ4 literal run in the dialect used inside .adi blocks."""
    n = len(data)
    out = bytearray([min(n, 15) << 4])
    left = n - min(n, 15)
    if n >= 15:
        while left >= 255:
            out.append(255)
            left -= 255
        out.append(left)
    out += data
    return bytes(out)


def boot_sector(hidden: int, total: int, spc: int) -> bytes:
    """NTFS boot sector padded out to a full cluster."""
    b = bytearray(SECTOR)
    b[0:3] = b"\xeb\x52\x90"
    b[3:11] = b"NTFS    "
    struct.pack_into("<H", b, 11, SECTOR)
    b[13] = spc
    struct.pack_into("<H", b, 14, 1)
    struct.pack_into("<I", b, 28, hidden)
    struct.pack_into("<Q", b, 40, total)
    struct.pack_into("<Q", b, 48, 16)
    b[510:512] = b"\x55\xaa"
    return bytes(b)


def make_block(cluster: int, present: dict) -> bytes:
    """Used-sector bitmap followed by only the clusters whose bits are set."""
    units = REGION // cluster
    bitmap = bytearray(units // 8)
    body = bytearray()
    for u in sorted(present):
        bitmap[u >> 3] |= 1 << (u & 7)
        body += present[u].ljust(cluster, b"\x00")[:cluster]
    return bytes(bitmap) + bytes(body)


def build_adi(recipes, bad_crc_indices=()) -> bytes:
    """Build a synthetic .adi from decoded blocks.

    Each recipe is a dict with ``decoded`` (bytes), ``raw_region`` (int) and
    an optional ``gap_before`` (number of padding bytes before the block).
    A gap in the compressed chain creates a new index run.
    """
    payload = bytearray()
    recs = []
    for r in recipes:
        payload += bytes(r.get("gap_before", 0))
        decoded = r["decoded"]
        comp = lz4_literals(decoded)
        off = len(payload)
        payload += comp
        recs.append((off, len(decoded), len(comp),
                     r["raw_region"], br_crc32(decoded)))

    index = bytearray()
    for i, (off, usize, csize, raw_region, checksum) in enumerate(recs):
        if i in bad_crc_indices:
            checksum = 0xDEADBEEF
        index += record(off, usize, csize, 0, raw_region, checksum)
    payload += index
    payload += bytes(256)  # keep the index out of the scanner's 64-byte tail

    header = bytearray(0x40)
    header[0:4] = b"BIFH"
    struct.pack_into("<I", header, 4, len(header))
    footer = struct.pack("<III", 0, 0, 16) + b"BIFT"
    return bytes(header) + bytes(payload) + footer
