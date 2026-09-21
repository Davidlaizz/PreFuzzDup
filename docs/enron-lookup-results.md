# Enron 标签检索实验结果

截至 2026-09-21，5w 与全量实验已完成。本报告整理已有运行证据，
不是迁移工具后的重新性能测试，也不是 4210 服务端的测量结果。

## 输入与环境

| 项目 | 5w | 全量 |
| --- | ---: | ---: |
| 数据总数 | 51,740 | 517,401 |
| 参考库 | 41,392 | 413,921 |
| 查询池 | 10,348 | 103,480 |
| 正式查询 | 1,000 | 1,000 |

统一使用 256 位文本 SimHash，切分种子 20260921，分层抽样种子 20260922，
阈值 4/5/6，每查询重复 3 次，PreFuzzDup FPP=0.01。
全量正式查询中 exact_ref 为 718 条，no_exact_ref 为 282 条；这些是正文 SHA 分组，
不代替标签距离真值，也不代表最终协议复用成功。

全量 manifest 记录时间为 2026-09-20 16:54:25 UTC（北京时间次日），
运行环境为 x86_64 Linux/WSL2，内核 6.18.33.2-microsoft-standard-WSL2，
glibc 2.39，Python 3.12.3。数据库在 WSL 原生文件系统 scratch 中运行。
原 manifest 未完整记录 CPU 型号、内存、物理磁盘型号，不能用后来探测值补作当时证据。
Release 构建和命令顺序有日志；OS 页缓存未清空，SQLite 应用页缓存约 1 MiB。
正式计时顺序为 PreFuzzDup t4/t5/t6、SimLESS、FuzzyDedup，之前执行等价抽查。

## 全量结果

| 方案 | t | 匹配率 | mean us | median us | p95 us |
| --- | ---: | ---: | ---: | ---: | ---: |
| PreFuzzDup | 4 | 73.2% | 34.772 | 23.000 | 69.000 |
| SimLESS | 4 | 73.2% | 11336.293 | 11177.447 | 12770.980 |
| FuzzyDedup | 4 | 73.2% | 1219.732 | 1211.213 | 2462.109 |
| PreFuzzDup | 5 | 73.2% | 41.616 | 27.000 | 81.000 |
| SimLESS | 5 | 73.2% | 11336.293 | 11177.447 | 12770.980 |
| FuzzyDedup | 5 | 73.2% | 1419.897 | 1414.376 | 2879.786 |
| PreFuzzDup | 6 | 73.3% | 50.142 | 32.000 | 101.000 |
| SimLESS | 6 | 73.3% | 11336.293 | 11177.447 | 12770.980 |
| FuzzyDedup | 6 | 73.3% | 1612.885 | 1610.114 | 3251.850 |

t=6 时，PreFuzzDup 平均读 35.157 条 posting、做 8.161 次完整距离验证；
FuzzyDedup 平均检查 88,206.758 条记录；SimLESS 扫描 413,921 条。
匹配率相同意味着存在性判定一致，不意味着完成了相同输出任务：分别是全部候选、
全局最小距离和首个匹配。SimLESS 一次求出的最小距离用于多个阈值判定，
各阈值行的相同时延不是三次独立阈值搜索。

t=6 的 5w 平均耗时分别为 7.457、816.935、201.800 us，顺序为
PreFuzzDup、SimLESS、FuzzyDedup。规模扩展同时改变了查询分布和命中率，
不能单靠这两个规模的数据点拟合渐近复杂度。

## 验证与复现边界

全量标签 C++ 校验 517,401/517,401，mismatch=0；切分唯一性与无交集检查通过。
PreFuzzDup 100 条查询的 scan/exact/prefuzz 候选集合抽查通过。
正式数据含 9,000 个 query/repeat/threshold 组合，三方案共 27,000 个匹配标志一致。
不比较 FuzzyDedup 与 SimLESS 的 best_distance，因为首个匹配未必最近。

本实验只测检索，不包含正文处理、标签生成、加密、所有权证明、密文传输或网络。
完整运行步骤见 [工具说明](../tools/README.md)，复杂度见 [分析](algorithm-complexity.md)。
原始证据保存在 `results-local/enron-5w/lookup-experiment/` 和
`results-local/enron-full/lookup-experiment/` 的 summary.csv、run_manifest.json、
inputs/split_summary.json、raw/、logs/；不进入 Git。
文件校验和见 [证据索引](enron-lookup-evidence.json)，用于持有原始文件者核对，
不意味着公开仓库包含原始逐查询结果。
