#!/usr/bin/env python3
"""Build LLVM libFuzzer targets with ASan/UBSan; no production build changes."""
from pathlib import Path
import os
import subprocess
from seeds import seed_corpus
root = Path(__file__).resolve().parents[2]
out = root / 'target' / 'fuzz'
out.mkdir(parents=True, exist_ok=True)
seed_corpus(out / 'corpus')
(out / 'artifacts').mkdir(exist_ok=True)
compiler = os.environ.get('FUZZ_CXX', 'clang++')
flags = ['-std=c++17','-O1','-g','-fno-omit-frame-pointer', '-fsanitize=fuzzer,address,undefined',
         '-fno-sanitize-recover=all','-I'+str(root/'src')]
for name in ('codec','records','image_file','legacy'):
    subprocess.run([compiler, *flags, '-DFUZZ_'+name.upper(), str(root/'tests/fuzz/cpp_target.cpp'),
                    *[str(root/'src'/f'{n}.cpp') for n in ('adi_file','codec','image','image_set')],
                    '-o',str(out/name)], check=True)
print(out)
