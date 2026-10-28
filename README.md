# adi-extract

Command-line tool to extract files from AOMEI Backupper `.adi` disk images.

```
adi-extract info        <file.adi>
adi-extract scan        <file.adi> [report.txt] [max_out]
adi-extract reconstruct <file.adi> <disk.img> [max_bytes]
adi-extract verify      <disk.img>
adi-extract extract     <file.adi> <outdir>
```

`extract` builds or reuses a disk image, then writes one folder per partition under the output directory.

`reconstruct <file.adi> <disk.img>` writes a flat raw disk image (sparse, with a
reconstructed GPT) that can be mounted, carved or converted with `qemu-img`.
**Linux/macOS:** this fork also builds natively — see [POSIX.md](POSIX.md).

Unofficial tool, not affiliated with AOMEI. Use at your own risk.

## Format handling notes

The 0x20-byte block-index records found by the payload signature scan are VDB
index entries read 12 bytes late; their region/stream fields describe the
**next** block. `resolve_regions()` therefore applies one global one-record
shift. Chain gaps (normal metadata between block runs) do not reset region
numbering — an earlier version invented a "free" region number at each gap and
produced large bogus backward jumps. The on-disk `.index` cache includes a
format version and is regenerated automatically when the parser changes.

Each entry's `Crc32` is AOMEI's `BRCrc32`: CRC32C/Castagnoli, zero seed, final
inversion, checked over the **decoded** block bytes. `reconstruct` and `scan`
verify it and skip (with a warning) any block that fails; `info` reports how
many entries carry a checksum, and `scan`'s report lists checked/bad counts.
Entries with a zero checksum field are treated as "no checksum".

Decoded blocks are a used-sector bitmap followed by only the present clusters.
Cluster sizes from 512 B to 64 KiB are recognised, including the 32 KiB
clusters used by sparse NTFS regions. `usize == 1 + 256 KiB` is a distinct
"all clusters present" shorthand, not a real one-byte bitmap.

## Tests

```bash
make test
```

Runs the four-partition/sparse-write regression, the VDB checksum and 32 KiB
cluster regressions, and the ASan/UBSan safety suite.

Licensed under the MIT License. See LICENSE.
