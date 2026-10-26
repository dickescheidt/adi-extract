# Building on Linux / macOS

Upstream `adi-extract` was Windows-only (`CreateFileW`, `ReadFile`, sparse-file
ioctls and `RtlDecompressBuffer` from `ntdll.dll`). This fork adds
`src/win32_shim.hpp`, a small header that emulates just the Win32 subset the
project uses on top of POSIX `open`/`read`/`ftruncate`. The decompression and
disk-reconstruction logic is unchanged.

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
  used clusters consume real blocks. Compare `du -h` with
  `du -h --apparent-size`.
* It carries a **synthesised protective MBR + GPT** derived from the volumes
  found in the backup; partition type GUIDs are guessed from the filesystem.
  Only used sectors are written; everything else reads as zero.
* It is **not a byte-identical forensic clone**: the original partition table,
  unused sectors and unallocated/deleted data are not preserved. For an exact
  clone, restore with AOMEI to a spare disk and `dd` it.

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
* `utf16le_z` keeps upstream's ASCII-only fallback, so non-ASCII backup
  comments/filenames show as `?` in `info` on POSIX.
* Wide-char paths are converted UTF-8 <-> UTF-32 by the shim. `\\?\` prefixes
  and backslashes are stripped/normalised for `open()`.

All other [upstream limitations](README.md) still apply: single full `.adi`
only (no incremental/differential chains, split sets or encrypted images),
`.afi` is not supported, and filesystem support is NTFS/FAT.
