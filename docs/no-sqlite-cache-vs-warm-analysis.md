# 无 SQLite 缓存与热缓存检索结果对比

日期：2026-09-29  
分支：`codex/no-sqlite-cache-full`

本文对比 Enron full 标签检索实验中两次同机运行结果。两次实验使用同一套参考库、查询、分组和阈值，服务端均为 4110 ThinkStation P920。这里的“无 SQLite 缓存”指禁用 SQLite 应用层 page cache，而不是移除 SQLite 存储引擎，也不是清空 OS page cache。

## 实验口径

| 项目 | 值 |
| --- | ---: |
| 数据总数 | 517,401 |
| 参考库 | 413,921 |
| 正式查询 | 1,000 |
| 阈值 | 4、5、6 |
| 重复次数 | 3 |
| 标签位数 | 256 |

两次输入的六份 CSV/JSON 清单 SHA-256 完全一致。每个方案有 9,000 条正式查询结果，即 1,000 条查询 × 3 次重复 × 3 个阈值。

两次运行的缓存控制如下：

| 运行 | SQLite 应用缓存 | SQLite mmap | OS page cache |
| --- | ---: | ---: | --- |
| warm | 1,024 KiB | 默认记录中未显式覆盖 | 保留 |
| no-sqlite-cache | 0 KiB | 0 | 保留 |

因此，本对比测量的是：在同一个热 OS page cache 环境下，禁用 SQLite 内部缓存带来的增量影响。它不是冷盘、冷启动或无 SQLite 存储引擎的实验。

## 正确性

所有严格校验通过：

| 检查 | 结果 |
| --- | --- |
| 服务端状态 | passed |
| PreFuzzDup 等价性检查 | passed |
| workload 不一致数 | 0 |
| 服务端与本地 matched 不一致数 | 0 |
| 三方案交叉 matched 不一致数 | 0 |
| 分组不一致数 | 0 |
| 缺失结果键 | 0 |

三方案 matched 判定也完全一致：

| 阈值 | 匹配数 / 1,000 |
| ---: | ---: |
| 4 | 732 |
| 5 | 732 |
| 6 | 733 |

## 查询延迟对比

延迟单位为微秒（µs）。两列都来自同一台 4110 服务端，不是本地机器与服务端的比较。`Ratio` 为 `no-cache mean / warm mean`。

### 平均延迟

| 方案 | 阈值 | Warm mean | No-cache mean | Ratio | 变化 |
| --- | ---: | ---: | ---: | ---: | ---: |
| PreFuzzDup | 4 | 85.94 | 133.65 | 1.56 | +55.5% |
| PreFuzzDup | 5 | 111.23 | 155.30 | 1.40 | +39.6% |
| PreFuzzDup | 6 | 124.67 | 187.65 | 1.50 | +50.5% |
| SimLESS | 4 | 28,026.49 | 26,130.44 | 0.93 | -6.8% |
| SimLESS | 5 | 28,026.49 | 26,130.44 | 0.93 | -6.8% |
| SimLESS | 6 | 28,026.49 | 26,130.44 | 0.93 | -6.8% |
| FuzzyDedup | 4 | 3,214.31 | 4,080.73 | 1.27 | +27.0% |
| FuzzyDedup | 5 | 3,650.91 | 4,678.22 | 1.28 | +28.1% |
| FuzzyDedup | 6 | 4,092.63 | 5,266.19 | 1.29 | +28.7% |

### p50 与 p95

| 方案 | 阈值 | Warm p50 | No-cache p50 | Warm p95 | No-cache p95 |
| --- | ---: | ---: | ---: | ---: | ---: |
| PreFuzzDup | 4 | 60 | 83 | 167 | 264 |
| PreFuzzDup | 5 | 76 | 96 | 226 | 289 |
| PreFuzzDup | 6 | 85 | 122 | 255 | 345 |
| SimLESS | 4/5/6 | 27,815.85 | 25,837.38 | 30,305.89 | 29,725.57 |
| FuzzyDedup | 4 | 3,252.38 | 4,154.66 | 6,315.67 | 7,844.29 |
| FuzzyDedup | 5 | 3,693.49 | 4,759.99 | 7,135.72 | 9,109.54 |
| FuzzyDedup | 6 | 4,132.62 | 5,367.03 | 10,269.77 |

## 为什么影响差距很大

### PreFuzzDup：最依赖 SQLite 热页路径

PreFuzzDup 的主要路径是分段 key 定位 SQLite B-tree、读取少量 posting list、合并候选，再做完整 Hamming 距离校验。单次查询平均只读取约 22-36 条 posting，因此索引定位和 pager 路径在总耗时中的占比很高。

禁用 SQLite 内部缓存后，即使数据页仍可能留在 OS page cache 中，SQLite 仍要重复走 pager/B-tree 页读取路径，不能复用应用层缓存中的热页。这解释了查询延迟上升约 40%-56%。

### SimLESS：瓶颈是全库扫描

SimLESS 每个查询检查 413,921 条记录、比较约 105,963,776 位。原 1 MiB SQLite 应用缓存相对这个工作负载很小，且访问模式是全库扫描，主瓶颈在 CPU 和内存带宽。

因此禁用 SQLite 内部缓存没有造成可解释的性能退化。本次 no-cache 均值反而低 6.8%，但 p99 更高；更稳妥的结论是运行波动，而不是“关闭缓存让 SimLESS 变快”。

### FuzzyDedup：中等影响

FuzzyDedup 通过重量筛选和三段提前终止，把平均检查记录数降到约 62,156-88,207 条，明显低于 SimLESS，但仍远高于 PreFuzzDup 的少量 posting 读取。其比较位数约 3.98M-5.65M，计算剪枝已经承担了主要削减工作。

SQLite 缓存仍有帮助，但不像 PreFuzzDup 那样决定性。禁用后延迟上升约 27%-29%。

## workload 一致性

缓存只应影响时间，不应改变算法逻辑。实际结果正是如此：

| 方案 | workload 结论 |
| --- | --- |
| PreFuzzDup | 每个阈值的 candidate、filter 查询、倒排定位、posting 读取、完整距离计算全部逐键一致 |
| SimLESS | matched、best distance、records examined、bits compared 全部逐键一致 |
| FuzzyDedup | matched、best distance、records examined、bits compared 全部逐键一致 |

PreFuzzDup 的平均 posting 读取量保持不变：

| 阈值 | 平均 posting 读取 |
| ---: | ---: |
| 4 | 22.100 |
| 5 | 28.451 |
| 6 | 35.157 |

FuzzyDedup 的平均检查记录数也保持不变：

| 阈值 | 平均检查记录数 | 平均比较位数 |
| ---: | ---: | ---: |
| 4 | 62,156.03 | 3,978,184.06 |
| 5 | 75,418.62 | 4,827,054.46 |
| 6 | 88,206.76 | 5,645,535.10 |

## 索引准备时间不可比

PreFuzzDup 的 `index_prepare_us` 不适合直接解释为 SQLite 缓存收益。

| 运行 | `disk_index_reused` |
| --- | --- |
| warm | 1，三个阈值均复用已有索引 |
| no-sqlite-cache | 0，三个阈值均新建索引 |

warm 的索引准备时间约 0.96-1.30 秒，no-sqlite-cache 约 22.53-31.50 秒。这个巨大差异主要来自“复用索引”与“重建索引”的路径不同，不能归因于 1 MiB SQLite 应用缓存。

三个 PreFuzzDup 数据库大小完全一致，说明索引内容没有变化：

| 阈值 | 数据库大小 |
| ---: | ---: |
| 4 | 80,617,472 bytes |
| 5 | 90,148,864 bytes |
| 6 | 98,947,072 bytes |

## 结论

1. SQLite 内部缓存对 PreFuzzDup 影响最大：禁用后平均延迟上升约 40%-56%。
2. SQLite 内部缓存对 FuzzyDedup 有中等影响：禁用后平均延迟上升约 27%-29%。
3. SimLESS 基本不受 SQLite 内部缓存影响；其全库扫描工作量太大，1 MiB 应用缓存不是主要瓶颈。
4. 所有逻辑结果、workload 指标和三方案 matched 判定保持一致，说明缓存没有改变正确性。
5. 本次结果应表述为 `warm OS page cache + disabled SQLite page cache`，不能表述为冷盘或冷启动性能。
6. 本实验只排除了 SQLite 应用层缓存的边际影响；SQLite B-tree、pager 和存储引擎的结构性开销仍然存在。
7. 三个算法输出目标不同：PreFuzzDup 返回全部候选，SimLESS 求全局最小距离，FuzzyDedup 找到首个匹配即返回。延迟仍然不能解释为同一输出任务的速度排名。
