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

Enron tools additionally use Python unittest: run discovery separately in `tools/enron-5w` and `tools/enron-full`. Install `tools/requirements.txt` first. These unit tests use synthetic fixtures and do not require the Enron corpus; see `tools/README.md` for C++ verification and full experiment prerequisites.

## Commit & Pull Request Guidelines

Use Conventional Commit subjects, such as `fix(prefuzzdup): preserve lookup equivalence`, consistent with the initial `chore:` commit. Keep changes focused. PRs should explain the affected scheme, rationale, validation commands, and results; link relevant issues. For performance claims, include dataset parameters, thresholds, repetitions, and environment. Exclude build outputs, databases, private datasets, and keys.

## Enron 实验约束

- 原始语料、压缩包、生成数据、SQLite、密文和原始运行证据保持忽略；不得强制加入 Git。
- 可复现工具保存在 `tools/enron-5w/` 与 `tools/enron-full/`，输出仍写入 `results-local/` 或 WSL 原生文件系统 scratch。
- 正文按第一个空行移除外层邮件头，统一 CRLF 为 LF 并去首尾空白；保留引用与签名，不做 MIME 解码。
- 检索统一使用 256 位文本 SimHash；正文 SHA-256 分组不代替检索真值，五词 Jaccard 不等于 SimHash 距离。
- 2026-09-21 状态：5w 与全量标签检索已完成；完整协议、两机通信、全量独立文本近似分类尚未完成。
- PreFuzzDup 返回全部候选，SimLESS 求最小距离，FuzzyDedup 找到首个匹配即返回；耗时不能解释为相同输出任务的速度排名。
- 样本内重复率、参考库查询命中率、最终协议复用率不得混用。近似复用不保证逐字节恢复原查询文件。
- 数据准备历史与统计来源见 `docs/enron-dataset-history.md`；修改预处理或重新统计时同步更新口径。
