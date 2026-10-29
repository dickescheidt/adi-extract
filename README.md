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
After a successful run it reports how much of the image holds recovered data,
e.g. `data: 196608 bytes of block data placed, 2966528 bytes left zero (6.216%
of the 3163136-byte image)`. The two numbers add up to the image size, so a
mostly empty image is easy to tell apart from a truncated one.

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
many entries carry a checksum and decodes an evenly spread sample of them,
printing `verified: C of T decoded blocks checked, B mismatches, U unchecked`;
`scan`'s report lists checked/bad counts. Entries with a zero checksum field
are treated as "no checksum".

Decoded blocks are a used-sector bitmap followed by only the present clusters.
Cluster sizes from 512 B to 64 KiB are recognised, including the 32 KiB
clusters used by sparse NTFS regions. `usize == 1 + 256 KiB` is a distinct
"all clusters present" shorthand, not a real one-byte bitmap.

### Standard record path

Real images contain a standard record stream: CRC-valid `0x201` volume indexes,
`0x202` data-block indexes, `0x109` region geometry, `0x102` volume metadata
and `0x105`/`0x106` compression/encryption modes. `info` and `reconstruct`
discover those records first. A `0x201` directory entry pointing at the end of
the VDB table is matched against the `0x202` header to derive a per-volume
logical-to-physical delta; the delta resolves the region, metadata and mode
records and the VDB table itself.

With that path the block geometry and the partition's absolute start LBA, size,
GPT type GUID, unique GUID and label are recovered from the records instead of
being guessed from boot sectors, and the real 0x20-byte VDB entries are read
directly.

The filesystem in `info`'s volume line is read from each volume's own boot
sector. If that sector did not survive, the name is guessed from the volume
label and printed with a trailing `?` plus a footnote. Regions that disagree on
the cluster size are listed in full, e.g. `cluster mixed (4096, 32768)`. A FAT
volume only becomes an EFI system partition in the synthesised GPT when its
label says ESP or EFI.

If no CRC-valid record set exists (synthetic or older images), the tool falls
back to the signature-scan parser. Set `ADI_EXTRACT_LEGACY_ONLY=1` to force that
fallback.

`ImgOffset` in a VDB entry is a **logical image-set offset**, not a raw file
offset. Reads use `physical = logical - DataOffInSet + BIFH.size`, with
`DataOffInSet` / `DataLenInSet` read from BIFT `+0x628` / `+0x620`. Split
backups need their extra members listed in `ADI_EXTRACT_MEMBERS` as a
colon-separated list:

```bash
ADI_EXTRACT_MEMBERS="Backup1.adi:Backup2.adi" \
  ./adi-extract reconstruct Backup.adi disk.img
```

`info` prints each member's logical range; a read outside every member fails
rather than silently seeking to the wrong offset. Only compression mode 1
(AOMEI LZ4) and direct blocks, with encryption mode 0, are supported.

Standard-record blocks are bounded by their `0x109` region length. Short final
blocks, including a partial final cluster, are supported; padded blocks are
clipped to the region boundary. Other decoded geometry mismatches stop extraction
with an error instead of silently omitting the block.

## Performance

`reconstruct` is single-threaded; three things used to dominate it:

* **No full pass before the first byte.** The standard record block is searched
  in the last 4 MiB of the container; the old build read the entire image
  first (70 s for 70 GiB at 1 GB/s) before writing anything. If the records are
  not in that window the tool falls back to scanning the whole file, and
  `ADI_EXTRACT_FULL_SCAN=1` forces that path.
* **BRCrc32 uses slicing-by-16.** Every decoded byte is checksummed, and the
  byte-at-a-time table ran at ~0.43 GB/s on a 2.6 GHz core, which capped the
  whole run; the sliced version runs at ~2.4 GB/s.
* **LZ4 matches are copied in doubling steps** instead of byte by byte.

Measured on a 2.6 GHz VM with output to `/dev/null`: 4 GiB of compressible
blocks 14.0 s → 5.2 s, 2 GiB of stored blocks 16.3 s → 4.1 s.

## Debug diagnostics and verification

Use `--debug` to enable extended format-audit diagnostics on **stderr**:

```bash
adi-extract --debug info backup.adi
adi-extract --debug reconstruct backup.adi disk.img 2> debug.log
```

The flag can appear before or after the command. Use `--` to end option parsing
if a filename is literally `--debug`. Existing corruption/skip warnings and fatal
errors remain visible without the flag. Debug mode changes diagnostics only,
not the recovered bytes or exit status.

Extended diagnostics cover unknown referenced records, rejected record-set
candidates, missing or ambiguous metadata/modes, absent/unverified checksums,
image-set gaps/overlaps, and inferred geometry or partition metadata. They also
say when a filesystem was guessed from the volume label and when `info` only
verified a sample of decoded blocks. Correctly bounded partial final blocks are
supported, not a geometry warning.

A zero exit status is not proof of a complete or exact restore. Review recovery
warnings; do not use partial output left by a failed command. This is a
reverse-engineered format: diagnostics cover detected uncertainty, not unknown
semantics the parser cannot recognize. Arbitrary signature-like bytes in
compressed payloads are not treated as records, so rejected scan candidates
alone do not trigger diagnostics.

Validate the recovered layout and filesystem independently before restoring
valuable media. Decoded block checksums do not verify destination placement or
prove that a reconstructed GPT is identical to the original partition table.

## Tests

```bash
make test
```

Runs the four-partition/sparse-write regression, the VDB checksum and 32 KiB
cluster regressions, the standard-record and split-image-set regressions, and
the ASan/UBSan safety suite.

Licensed under the MIT License. See LICENSE.

### Testing without a private backup

The full suite includes deterministic randomized and malformed-input tests:

* **Placement oracle:** 24 seeds vary cluster/block geometry, sparse bitmaps,
  unused bitmap bits, region bases and partial final clusters. Expected partition
  bytes are constructed directly from logical sector addresses, independently of
  the production parser/decoder. The writer reuses fixture framing/CRC helpers,
  so this is not an independent specification of the entire ADI format.
* **Metamorphic tests:** each model is encoded six ways: direct, literal-only
  compression, overlapping LZ4 matches, padded final blocks, regrouped VDB
  references, and split members. Variants also reorder entries/storage and
  relocate metadata. A member boundary falls inside stored block bytes. All six
  must produce identical whole-disk output as well as match the placement oracle.
* **Malformed-input smoke tests:** 128 deterministic cases cover truncation,
  framing corruption, CRC-repaired structural mutations and compressed payload
  corruption. POSIX subprocesses have 512 MiB address-space, three-second CPU,
  six-second wall-clock and 32 MiB output-file limits. Expected errors/skips are
  allowed; signals, panics and timeouts fail the tests.
* **Decoder smoke fuzzing:** 4,096 deterministic short inputs plus known
  overlapping matches and truncations. The C++ safety suite runs these under
  AddressSanitizer/UBSan; Rust runs them as unit tests.

These are bounded regression/smoke tests, not coverage-guided fuzzing or proof
that arbitrary hostile inputs cannot exhaust resources. A real AOMEI restore
comparison and independent filesystem checks remain necessary.

For a longer reproducible placement run:

```bash
python3 tests/test_properties.py ./adi-extract cpp --seeds 200
```

### Coverage-guided fuzzing

Optional libFuzzer harnesses harden the record parsers, the LZ4 decoder, the legacy
chained decoder and the whole container path against malformed input. They are not
part of the default test suite; see [`tests/fuzz/README.md`](tests/fuzz/README.md) for
prerequisites, targets and the recorded campaign. Run them with:

```bash
sh tests/fuzz/run.sh 90
```

The 2026-10-28 campaign executed about 9.97 million cases under AddressSanitizer and
UndefinedBehaviorSanitizer with no crash artifact. It also exposed a descriptor leak
when a rejected container throws during construction; that is fixed and covered by a
regression test. Fuzzing cannot validate the format itself and does not replace a real
AOMEI restore comparison.

### Offset-only debug trace

For the standard-record extraction path, `--debug` also emits `trace:` lines
showing VDB region/block identity, stored logical offsets, member ordinals and
physical read chunks, decoded size/checksum, bitmap and destination write ranges.
Trace lines contain no recovered payload bytes, labels, GUIDs or filenames.
They are not a substitute for the decoded checksum/skip diagnostics.

```bash
adi-extract --debug reconstruct backup.adi disk.img 2> debug.log
grep 'trace:' debug.log > offsets.trace.txt
```

Review before sharing: the complete debug log can contain filenames/labels,
and even an offset-only trace exposes disk geometry, sparse allocation and
checksums. Tracing is opt-in and does not change recovered bytes.
