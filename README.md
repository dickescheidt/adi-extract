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

Unofficial tool, not affiliated with AOMEI. Use at your own risk.

Licensed under the MIT License. See LICENSE.
