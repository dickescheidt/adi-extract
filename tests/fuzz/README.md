# Coverage-guided fuzzing (C++)

Optional harnesses for parser, decoder and container hardening. They are built with
Clang's libFuzzer, AddressSanitizer and UndefinedBehaviorSanitizer; the normal build
and `make test` do not depend on them.

| Target | Exercises |
|---|---|
| `codec` | `Lz4Stream::decode_buffer` and `split_block` on arbitrary bytes |
| `records` | Each `0x201/0x202/0x102/0x105/0x106/0x109` parser, VDB entries and offset shifting, called directly |
| `image_file` | Whole constrained container: framing, record scan, standard image parse; record CRCs are repaired so fuzzing passes the checksum barrier |
| `legacy` | History-aware chained decoder (`next_chunk`/`read`) over a valid stub container |

Run with `sh tests/fuzz/run.sh [seconds-per-target]` (default 60). The runner:

1. builds every target with `-fsanitize=fuzzer,address,undefined` into the ignored
   `target/fuzz/` directory;
2. seeds a fresh corpus from `seeds.py` (public synthetic models, no user data);
3. runs each target with the committed dictionary, a 5 s per-input limit and a
   768 MiB RSS cap.

Reproduce a finding by passing the artifact to the target binary, e.g.
`target/fuzz/image_file target/fuzz/artifacts/crash-...`. LeakSanitizer is disabled in
the runner because it cannot run under ptrace-based sandboxes; descriptor leaks are
covered by the safety regression instead.

#### Recorded campaign

Seed `20261028`, Clang 19 libFuzzer with AddressSanitizer and UndefinedBehaviorSanitizer,
90 seconds per target on x86-64 Linux, synthetic seeds from `tests/fuzz/seeds.py`:

| Target | Executions | Coverage units |
|---|---|---|
| `codec` | 28,412 | 81 |
| `records` | 9,868,782 | 142 |
| `image_file` | 38,705 | 764 |
| `legacy` | 26,112 | 374 |

9,962,011 executions in total. Coverage units come from LLVM edge counters.

No sanitizer finding, timeout or crash artifact in the final campaign. Edge coverage
counts are toolchain-specific, so they are not comparable across the two programs.

An earlier `image_file` campaign stopped with `Too many open files`. The cause was a
real bug: `AdiFile` opened its handle and then threw while parsing, so `~AdiFile` never
ran and every rejected container leaked a descriptor. The constructor now releases the
handle on every failure path, and `tests/test-safety.cpp` constructs 1,200 malformed
containers while checking `/proc/self/fd`.

#### Limitations

Fuzzing shows that these inputs do not crash, hang or trigger sanitizers. It cannot
show that the format interpretation is correct, and it is not a substitute for a real
AOMEI backup and restore comparison. Inputs are capped at 64 KiB and each campaign is
time-bounded; corpus and artifacts are deliberately not committed.
