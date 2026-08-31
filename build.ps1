# Build adi-extract with MSVC Build Tools (no CMake required).
$ErrorActionPreference = "Stop"
$vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $vcvars)) {
    throw "vcvars64.bat not found: $vcvars"
}
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$out = Join-Path $root "adi-extract.exe"
$src = @(
    (Join-Path $root "src\main.cpp"),
    (Join-Path $root "src\adi_file.cpp"),
    (Join-Path $root "src\codec.cpp"),
    (Join-Path $root "src\image.cpp"),
    (Join-Path $root "src\extract.cpp")
)
$cmd = "call `"$vcvars`" && cl /nologo /EHsc /std:c++17 /O2 /W3 /D_CRT_SECURE_NO_WARNINGS /DNOMINMAX /DWIN32_LEAN_AND_MEAN /I `"$root\src`" $($src -join ' ') /Fe:`"$out`" /Fo:`"$root\obj\\`""
New-Item -ItemType Directory -Force -Path (Join-Path $root "obj") | Out-Null
cmd /c $cmd
if ($LASTEXITCODE -ne 0) { throw "cl failed: $LASTEXITCODE" }
Write-Host "built $out"
