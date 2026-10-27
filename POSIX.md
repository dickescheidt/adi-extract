# Building on Linux / macOS

Upstream `adi-extract` was Windows-only (`CreateFileW`, `ReadFile`, sparse-file
ioctls and `RtlDecompressBuffer` from `ntdll.dll`). This fork adds
`src/win32_shim.hpp`, a small header that emulates just the Win32 subset the
project uses on top of POSIX `open`/`read`/`ftruncate`. The POSIX build also
fixes two reconstruction bugs: multi-partition layout discovery and sparse
writing (see below).

## Build

Requires a C++17 compiler and `make`. No external libraries.

```bash
make                 # -> ./adi-extract
```

`cmake -S . -B build && cmake --build build` works too.

Windows users can keep using the original MSVC path (`CMakeLists.txt` or
`build.ps1`); the `_WIN32` branches are unchanged.

## Produce a raw image from an .adi

```bash
mkdir ~/adi-work && cd ~/adi-work
cp /path/to/"System Backup.adi" .        # work on a copy in a scratch dir

~/path/to/adi-extract info       "System Backup.adi"
~/path/to/adi-extract reconstruct "System Backup.adi" disk.img
~/path/to/adi-extract verify      disk.img
```

A cap (`... disk.img 512M`) limits the first pass to a few GiB. This is useful
for checking the image is understood before spending time on the full rebuild.

The tool writes `<file.adi>.index` (block-index cache) **next to the source
`.adi`** and `map.csv` (volume table: fs, label, LBA, sectors, cluster size)
next to `disk.img`. Keep the `.adi` itself read-only.

### What `disk.img` is

* A flat raw disk image (`.img`/`.raw`/`dd` compatible), 512-byte sectors.
* Sparse on ext4/xfs/btrfs: `ftruncate` grows it to the full disk size but only
  used clusters consume real blocks. Leading/trailing zero bytes in a written
  cluster are skipped too, so AOMEI images that store whole zero clusters stay
  sparse instead of allocating every block. Compare `du -h` with
  `du -h --apparent-size`.
* It carries a **synthesised protective MBR + GPT** derived from the volumes
  found in the backup; partition type GUIDs are guessed from the filesystem.
  Only used sectors are written; everything else reads as zero.
* It is **not a byte-identical forensic clone**: the original partition table,
  unused sectors and unallocated/deleted data are not preserved. For an exact
  clone, restore with AOMEI to a spare disk and `dd` it.

### Multi-partition images

The original volume discovery split the block index into volumes only where the
compressed block chain had a gap, then probed only `region 0` of each run. AOMEI
usually writes a whole multi-partition disk as **one** contiguous chain, so only
the first partition was found and every cluster past its end was dropped
(`N units outside their volume` in the output).

This build scans the whole decompressed stream for volume boot records first.
Each boot sector carries its own partition start in `hidden_sectors`; when all
of them agree on

```
origin = hidden_sectors * 512 - (region * 256KiB + unit * cluster)
```

the stream is a whole-disk coordinate space shifted by `origin`, and every
cluster is written at `stream offset + origin`. All partitions then land at
their real LBAs and the generated GPT gets one entry per partition. If the
stream already contains a protective MBR/GPT at LBA 0, the tool keeps it
instead of synthesising one.

`reconstruct` prints the boot sectors it found and the computed origin:

```
  boot sectors: 4
    LBA 2048 (byte 1048576) at stream 0 -> origin 1048576  NTFS ...
    ...
  layout: whole-disk stream (origin 1048576 bytes)
```

If the origins disagree, it falls back to the old volume-run mapping and says
so. Set `ADI_EXTRACT_LEGACY_MAP=1` to force the old behaviour. The scan is an
extra full decompression pass, so a large image is read and decompressed twice.

If a real image is still misplaced, send the `boot sectors:`/`layout:` lines
plus `map.csv` and the `scan.txt` from `adi-extract scan file.adi scan.txt`.

### Use the image

```bash
fdisk -l disk.img
7z l disk.img                                  # browse GPT volumes
sudo losetup -Pf --show disk.img               # -> /dev/loop0
sudo mount -o ro /dev/loop0p1 /mnt
qemu-img convert -f raw -O qcow2 disk.img disk.qcow2
VBoxManage convertfromraw disk.img disk.vdi
testdisk disk.img
photorec disk.img                              # carving; loses filenames
```

`extract` still works on POSIX: it builds `outdir/disk.img` and then pulls
files out of NTFS/FAT partitions into `outdir/p0_NTFS/...`.

## Smoke test (no real .adi needed)

```bash
make
python3 tests/make_sample_adi.py /tmp/sample.adi
./adi-extract info        /tmp/sample.adi
./adi-extract reconstruct /tmp/sample.adi /tmp/disk.img
./adi-extract verify      /tmp/disk.img
python3 - <<'PY'
d = open('/tmp/disk.img','rb').read()
print('GPT:', d[512:520], '| NTFS boot sector:', d[2048*512+3:2048*512+11])
PY
```

Expected: 2 block-index records, one NTFS volume at LBA 2048, and a 3.1 MB
sparse raw image with a valid protective MBR, GPT header and NTFS boot sector.
`verify` reports `0/0` checks on this sample because the synthetic image has no
MFT; that is expected.

## POSIX-specific limitations

* `lznt1_decompress` is a no-op on POSIX (the Windows implementation calls
  `RtlDecompressBuffer` in `ntdll.dll`). It is only used when `extract` reads
  **NTFS-compressed** files; `reconstruct` is unaffected. Those files are
  extracted as raw compressed data or skipped.
* `extract` still cannot decompress NTFS-compressed file contents.
* Wide-char paths are converted UTF-8 <-> UTF-8 by the shim, which also
  normalises `\\?\` / `\\?\UNC\` prefixes and backslashes for `open()`.

### Memory-safety notes

`wchar_t` is 2 bytes on Windows (UTF-16) but 4 bytes on Linux/macOS (UTF-32).
Upstream stores filenames as UTF-16LE and cast those bytes straight to
`wchar_t*`; on POSIX that read **twice** the number of bytes present in the
field and merged pairs of characters. All conversion now goes through
`src/text.hpp`, which takes an explicit element count, combines surrogate
pairs, and never assumes `sizeof(wchar_t)`. This also means non-ASCII backup
comments and filenames now round-trip correctly in `info` on POSIX.

The MFT/FAT parsers additionally reject out-of-range attribute offsets and
lengths, `uint32` additions that wrap, zero-length data runs, and NTFS
compression units outside `0..16`. `make test` runs the regression suite plus
`tests/test-safety.sh`, which builds the parser under AddressSanitizer and
UBSan and feeds it crafted malformed records.

Run a stricter compile with:

```bash
g++ -std=c++17 -Wall -Wextra -Wconversion -Wsign-conversion -Wshadow \
    -Wformat-overflow=2 -Isrc -fsyntax-only src/*.cpp
```

All other [upstream limitations](README.md) still apply: single full `.adi`
only (no incremental/differential chains, split sets or encrypted images),
`.afi` is not supported, and filesystem support is NTFS/FAT.
