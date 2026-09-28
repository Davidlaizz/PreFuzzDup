# Three-scheme full lookup handoff analysis

日期：2026-09-22
分支：`codex/three-scheme-lookup-handoff-full`

本机作为客户端，4210 作为服务端。Git 只承担离线文件交接，Git clone/push/pull 时间不计入算法耗时。实验只覆盖 256 位 SimHash 标签检索，不包含 AES、CP-ABE、pairing proof、OT、密文上传下载或网络延迟测试。

## 数据规模

| 项目 | 数量 |
| --- | ---: |
| 总数据 | 517,401 |
| 参考库 | 413,921 |
| 查询池 | 103,480 |
| 正式查询 | 1,000 |
| 抽查查询 | 100 |

阈值固定为 4、5、6；每个查询重复 3 次。每个方案正式输出 9,000 行结果。

## 客户端职责

本机从既有 Enron full 实验产物生成并校验交接包：

1. 读取 reference、bench query、verify query 和分组文件。
2. 校验 ID、标签格式、行数和数据规模。
3. 校验 reference 与查询池不相交。
4. 允许 bench 和 verify 存在重叠 ID，但要求重叠记录的标签一致。
5. 生成 SHA-256 清单和期望输出列表。
6. 清空分组文件中的 `payload_digest` 与 `source_ref`，只保留统计分组。
7. 不交付原始邮件、正文、正文哈希、SQLite、密文或密钥。

客户端提交：

```text
2a0d1ca feat(experiments): add three-scheme full lookup handoff
```

交付目录：

```text
handoff/20260922-three-scheme-full/
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

4210 拉取交接分支后执行：

1. 校验全部输入 SHA-256。
2. 构建三个 lookup benchmark：
   - `prefuzzdup_persistent_lookup`
   - `simless_lookup_benchmark`
   - `fuzzydedup_lookup_benchmark`
3. 构建 SQLite 索引。
4. 先执行 100 条 verify，PreFuzzDup 做等价性检查。
5. 执行正式 benchmark，阈值 4、5、6，每条查询重复 3 次。
6. 校验每个方案输出结构、行数和唯一 workload key。
7. 检查三方案 matched 判定是否一致。
8. 记录 stdout/stderr、环境信息、数据库大小、运行命令和结果清单。
9. 只回传 `results/`，不回传 scratch SQLite。

服务端提交：

```text
708c307 fix(lookup-handoff): repair server entrypoint and record three-scheme full results
```

服务端结果状态：

```text
status=passed
equivalence_check=passed
```

服务端结果目录：

```text
handoff/20260922-three-scheme-full/results/
```

## 服务端环境

| 项目 | 值 |
| --- | --- |
| CPU | Intel Xeon Silver 4110 @ 2.10 GHz |
| 系统 | Ubuntu 22.04, Linux 6.8.0-59-generic |
| 编译器 | GCC 12.3.0 |
| CMake | 3.22.1 |
| SQLite | 3.37.2 |
| SQLite 应用缓存 | 约 1 MiB |
| OS page cache | 未清空 |

## 延迟结果

单位为微秒（µs）。“本机 mean”来自本地 full 基线。

| 方案 | 阈值 | 服务端 mean | 服务端 p50 | 服务端 p95 | 服务端 p99 | 本机 mean |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| PreFuzzDup | 4 | 85.9 | 60 | 167 | 674 | 34.8 |
| PreFuzzDup | 5 | 111.2 | 76 | 226 | 999 | 41.6 |
| PreFuzzDup | 6 | 124.7 | 85 | 255 | 963 | 50.1 |
| SimLESS | 4 | 28,026.5 | 27,815.9 | 30,305.9 | 33,296.0 | 11,336.3 |
| SimLESS | 5 | 28,026.5 | 27,815.9 | 30,305.9 | 33,296.0 | 11,336.3 |
| SimLESS | 6 | 28,026.5 | 27,815.9 | 30,305.9 | 33,296.0 | 11,336.3 |
| FuzzyDedup | 4 | 3,214.3 | 3,252.4 | 6,315.7 | 7,207.3 | 1,219.7 |
| FuzzyDedup | 5 | 3,650.9 | 3,693.5 | 7,135.7 | 8,138.3 | 1,419.9 |
| FuzzyDedup | 6 | 4,092.6 | 4,132.6 | 8,058.3 | 9,270.6 | 1,612.9 |

服务端比本机慢约 2.5 到 2.7 倍。由于 workload 完全一致，这主要反映硬件、内存路径和编译/运行环境差异，不是测量口径问题。

## PreFuzzDup workload

| 阈值 | 平均候选数 | filter 查询 | 倒排定位 | posting 读取 | 完整距离计算 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 4 | 4.465 | 5.0 | 3.674 | 22.100 | 5.588 |
| 5 | 4.618 | 6.0 | 4.416 | 28.451 | 6.974 |
| 6 | 4.773 | 7.0 | 5.170 | 35.157 | 8.161 |

PreFuzzDup 通过分段 prefix filter 和 SQLite 倒排索引，把每查询工作量压缩到少量 posting 和少量完整 Hamming 距离计算。

## SimLESS workload

| 阈值 | 平均 matched | 平均 best distance | 检查记录数 | 比较位数 |
| ---: | ---: | ---: | ---: | ---: |
| 4 | 0.732 | 17.061 | 413,921 | 105,963,776 |
| 5 | 0.732 | 17.061 | 413,921 | 105,963,776 |
| 6 | 0.733 | 17.061 | 413,921 | 105,963,776 |

SimLESS 每次查询做全库扫描，因此三个阈值的工作量和延迟基本不变。

## FuzzyDedup workload

| 阈值 | 平均 matched | 首匹配距离 | 检查记录数 | 比较位数 |
| ---: | ---: | ---: | ---: | ---: |
| 4 | 0.732 | 1.369 | 62,156 | 3,978,184 |
| 5 | 0.732 | 1.638 | 75,419 | 4,827,054 |
| 6 | 0.733 | 1.917 | 88,207 | 5,645,535 |

FuzzyDedup 使用重量筛选和分段提前终止，工作量显著低于 SimLESS，但仍远高于 PreFuzzDup 的索引定位。

## 匹配一致性

三方案的 matched 判定完全一致。

| 阈值 | 匹配数 / 1,000 |
| ---: | ---: |
| 4 | 732 |
| 5 | 732 |
| 6 | 733 |

SimLESS 的全局最小距离分布：

| 距离范围 | 查询数 |
| --- | ---: |
| 0 | 729 |
| 1-4 | 3 |
| 5-6 | 1 |
| 大于 6 | 267 |

因此 t=4 到 t=5 没有新增匹配；t=5 到 t=6 新增 1 条匹配。

## OS page cache 的影响

本次实验没有清空 OS page cache，因此操作系统会继续保留最近读写过的文件块。SQLite B-tree 页、posting list、参考数据页和日志文件再次访问时，可能直接从内存返回，而不是真正访问磁盘。

这意味着本报告中的延迟应理解为 **热缓存查询延迟**，而不是冷启动或磁盘边界延迟。服务端内存约 251 GiB，单个 PreFuzzDup 索引约 80-99 MiB，索引页很可能大量甚至完整驻留在 page cache 中。因此 PreFuzzDup 的几十微秒级查询延迟更适合解释为索引热路径性能。

page cache 对三个方案的影响不同：

| 方案 | page cache 的作用 |
| --- | --- |
| PreFuzzDup | 最明显；少量 B-tree 定位和 posting 读取可能变成内存访问 |
| SimLESS | 有帮助；但仍需遍历 413,921 条记录，CPU 和内存扫描占主导 |
| FuzzyDedup | 有帮助；剪枝后仍检查约 62,000-88,000 条记录，计算和内存遍历仍然主要 |

由于命令按固定顺序执行，前面 workload 可能会让后面的数据页更热。因此不同阈值和方案之间不是独立的冷缓存实验。不过 page cache 不改变候选数、best distance、matched、检查记录数等逻辑结果，所以 workload 一致性和匹配正确性结论不受影响。

如需测量冷启动性能，应在建立索引后执行：

```bash
sync
sudo sysctl vm.drop_caches=3
```

然后再运行查询。若要测量完整冷启动，应删除旧 SQLite、清空 page cache、重建索引并重新查询。该操作只适合实验机，不适合生产服务。

## 校验结果

| 检查 | 结果 |
| --- | --- |
| 服务端状态 | passed |
| PreFuzzDup 等价性检查 | passed |
| 每方案输出行数 | 9,000 |
| 服务端/本地 workload 不一致 | 0 |
| 服务端/本地 matched 不一致 | 0 |
| 三方案 cross-scheme matched 不一致 | 0 |
| 分组不一致 | 0 |
| 缺失 key | 0 |

## 结论

1. PreFuzzDup 是索引驱动的微秒级查询方案，检索工作量最小。
2. SimLESS 是全库扫描方案，每查询约 28 ms，对阈值不敏感。
3. FuzzyDedup 通过剪枝和首匹配提前返回，延迟约 3 到 4 ms。
4. 三者输出目标不同，延迟不能解释为同一任务的速度排名：
   - PreFuzzDup 返回全部候选；
   - SimLESS 求全局最小距离；
   - FuzzyDedup 找到首个匹配即返回。
5. matched 结果在阈值和方案间完全一致，说明实验数据和判定逻辑可靠。
6. 所有延迟结论都限于 warm-cache 场景；它们不代表服务冷启动、缓存淘汰后或磁盘 I/O 主导时的性能。
7. Git 传输时间未测量；OS page cache 未清空；SQLite 应用层缓存约 1 MiB；命令按固定顺序执行。
