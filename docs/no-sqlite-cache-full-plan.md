# No-SQLite-cache full lookup experiment plan

日期：2026-09-28  
分支：`codex/no-sqlite-cache-full`  
角色：本机为客户端，4110 为服务端

## 目标

在 Enron full 数据上重新执行 PreFuzzDup、SimLESS 和 FuzzyDedup 的 256 位 SimHash 标签检索 benchmark。本次保留 OS page cache，但禁用 SQLite 自身 page cache，用来区分共享操作系统缓存与 SQLite 内部缓存的影响。

本实验不运行 AES、CP-ABE、pairing proof、OT、密文上传下载或网络延迟测试。Git 只承担离线产物交接，Git 传输时间不计入任何算法耗时。

## 缓存口径

| 层次 | 策略 | 说明 |
| --- | --- | --- |
| OS page cache | 保留 | 三个算法都可公平使用；不执行 `drop_caches` |
| SQLite page cache | 禁用 | 所有查询命令使用 `--sqlite-cache-kib 0` |
| SQLite mmap | 禁用 | 避免绕过 SQLite page cache 的映射读取 |
| SQLite storage layer | 保留 | B-tree、BLOB 分块、prepared statement 开销仍在测量内 |

`--sqlite-cache-kib 0` 表示排除 SQLite 保留缓存，不等价于完全排除 SQLite。若要完全排除 SQLite 影响，需要为三个算法实现同一个非 SQLite 存储层，这不在本次范围内。

## 客户端职责

1. 从 `results-local/enron-full/lookup-experiment/inputs` 生成新交接包。
2. 校验 reference、bench query、verify query 的行数、ID 和 SHA-256。
3. 脱敏分组文件，只保留 `exact_ref`、`no_exact_ref` 或 `verify`。
4. 在 manifest 中记录 `cache_mode=no_sqlite_cache`、`sqlite_cache_kib=0`、`sqlite_mmap=0`、`os_page_cache=warm`。
5. 不交付原始邮件、正文、正文哈希、SQLite、密文或密钥。

交接包：

```text
handoff/20260928-no-sqlite-cache-full/
├── handoff-manifest.json
├── README.md
└── inputs/
    ├── reference.csv
    ├── queries_bench_1000.csv
    ├── queries_verify_100.csv
    ├── query_groups_bench_1000.csv
    ├── query_groups_verify_100.csv
    └── split_summary.json
```

## 服务端职责

1. 校验 manifest 和全部输入 SHA-256。
2. 构建三个 lookup benchmark。
3. 强制 manifest 与命令行的 `--sqlite-cache-kib` 一致。
4. 在 Linux 原生 scratch 中创建本次专用 SQLite。
5. 按固定顺序执行 verify 和 benchmark。
6. 记录日志、环境、命令、数据库大小和结果清单。
7. 只回传 `results/`，不回传 scratch SQLite。

固定顺序：

```text
PreFuzzDup verify
PreFuzzDup threshold 4
PreFuzzDup threshold 5
PreFuzzDup threshold 6
SimLESS verify
SimLESS benchmark
FuzzyDedup verify
FuzzyDedup benchmark
```

## 结果与判定

| 方案 | 预期 benchmark 行数 | 必须与 warm 基线一致的字段 |
| --- | ---: | --- |
| PreFuzzDup | 9,000 | `candidate_count`, `filter_queries`, `inverted_lookups`, `posting_records_read`, `full_tag_distance_computations` |
| SimLESS | 9,000 | `matched`, `best_distance`, `records_examined`, `bits_compared` |
| FuzzyDedup | 9,000 | `matched`, `best_distance`, `records_examined`, `bits_compared` |

`latency_us` 允许变化。三方案 matched 判定必须一致。任何 workload 不一致都应中止分析并保留原始 CSV。

## 分析口径

1. 与 4110 上已有 warm-SQLite-cache 结果比较，得到 SQLite 内部缓存收益。
2. 与本机 warm 基线比较，只作为硬件和运行环境参考。
3. 不比较冷盘或冷启动性能，因为 OS page cache 未清空。
4. 报告必须明确标注：`warm OS page cache + disabled SQLite page cache`。

## 完成标准

- 服务端结果状态为 `passed`。
- PreFuzzDup `equivalence_check=passed`。
- 每个方案 9,000 行正式结果。
- 服务端与客户端 manifest 的缓存口径一致。
- workload 和 matched 校验全部通过。
- 结果报告解释 SQLite cache 禁用前后的延迟变化，不将其解释为冷启动性能。
