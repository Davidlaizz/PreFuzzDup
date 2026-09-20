# Repository Guidelines

## Project Structure & Module Organization

The repository root contains three independently buildable C++20 research prototypes:

- `PreFuzzDup/`: end-to-end deduplication, `src/prefix_filter.hpp`, and `src/persistent_lookup.cpp` for indexed lookup experiments.
- `SimLESS/`: attribute-based encryption and pairing-based proofs, plus a full-scan lookup benchmark.
- `FuzzyDedup/`: oblivious-transfer proofs and optimized Hamming-distance lookup.

Each project has its own `CMakeLists.txt`, `README.md`, and `src/`. The comparison projects include local `prefuzzdup_core.cpp` copies to preserve independence; do not introduce sibling-directory dependencies. Small CSV fixtures live in `PreFuzzDup/examples/`. There is no separate test or asset directory. Treat `build-check/` and `__MACOSX/` as generated artifacts or archive metadata.

## Build, Test, and Development Commands

Use CMake 3.22+, a C++20 compiler compatible with the existing GCC/Clang flags, OpenSSL 3, and SQLite3 development packages. SimLESS and FuzzyDedup additionally require GMP and PBC 0.5.14. These shell examples assume Linux or WSL, starting at this guide's directory:

```bash
cd PreFuzzDup
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/prefuzzdup self-test
./build/prefuzzdup_persistent_lookup --records examples/records.csv --queries examples/queries.csv --db build/index.sqlite --tag-bits 16 --threshold default=1 --strategies scan,exact,prefuzz --repeat 3 --verify-equivalence
```

These commands configure, compile, check the protocol, and compare lookup results against the scan baseline. Build the other projects separately; run `./build/simless self-test` or `./build/fuzzydedup self-test` in their directories. Supply `OPENSSL_ROOT_DIR`, `PBC_ROOT`, and `GMP_ROOT` through `-D` when needed. Optional PreFuzzDup image support uses `-DPREFUZZDUP_ENABLE_MEDIA=ON` and requires OpenCV.

## Coding Style & Naming Conventions

Match surrounding code: expanded blocks generally use two-space indentation, functions and variables use `snake_case`, types use `PascalCase`, and constants use `kName`. Preserve existing compact sections without unrelated reformatting. No formatter or linter configuration is supplied; compilation enables `-Wall -Wextra -Wpedantic`.

## Testing Guidelines

Tests are built-in `self_test()` routines, not a separate framework; no coverage threshold is configured. Extend these checks for protocol changes. For lookup changes, verify equivalence and index reuse/rebuild behavior using disposable databases. Record commands and results; benchmark timings alone do not establish correctness.

## Commit & Pull Request Guidelines

This snapshot contains no Git history, so historical conventions cannot be verified. Use concise imperative subjects, optionally scoped, such as `fix(prefuzzdup): preserve lookup equivalence`. Keep changes focused. PRs should explain the affected scheme, rationale, validation commands, and results; link relevant issues. For performance claims, include dataset parameters, thresholds, repetitions, and environment. Exclude build outputs, databases, private datasets, and keys.
