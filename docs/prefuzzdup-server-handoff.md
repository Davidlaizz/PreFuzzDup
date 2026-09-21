# PreFuzzDup 客户端/服务端交接实验

本文描述把本地已经生成的 Enron 标签输入交给 4210 服务器执行 PreFuzzDup 检索的离线流程。实验只覆盖标签检索，不包含 AES 加解密、FuzzyPoW、密文上传下载或网络通信。

## 总体流程

1. 本地客户端从 `results-local/enron-{5w,full}/lookup-experiment/inputs/` 生成 handoff 包。
2. 本地把 handoff 包提交到专用 Git 分支并推送。
3. 服务器克隆该分支，校验 SHA-256，构建 Release，执行等价性检查和三个阈值的基准。
4. 服务器把结果、日志、环境信息和结果清单提交回同一分支。
5. 本地拉取结果并与已有基线逐行对比。

先跑 5w。5w 的行数、候选数和工作量指标全部一致后，再跑全量。

## 本地客户端打包

前提：

- 仓库在最新 `main`。
- `results-local/enron-5w/lookup-experiment/inputs/` 已存在。
- Python 3.10+ 可用。

```bash
git switch main
git pull
git switch -c codex/prefuzzdup-lookup-handoff-5w

python tools/prefuzzdup-handoff/handoff.py client \
  --scale 5w \
  --source results-local/enron-5w/lookup-experiment/inputs \
  --dest handoff/20260921-prefuzzdup-5w

git add handoff/20260921-prefuzzdup-5w
git commit -m "chore(experiments): package prefuzzdup 5w lookup handoff"
git push -u origin codex/prefuzzdup-lookup-handoff-5w
```

交接工具和本文档已经保存在 `main`；handoff 分支只追加数据包和服务器结果，不合并回 `main`。

生成的包只包含：

- `inputs/reference.csv`
- `inputs/queries_bench_1000.csv`
- `inputs/queries_verify_100.csv`
- `inputs/split_summary.json`
- `handoff-manifest.json`
- `README.md`

不包含原始邮件、正文、数据库、密文或密钥。

## 服务器执行

### 依赖

服务器需要：

- Git
- Python 3.10+
- CMake 3.22+
- C++20 编译器
- OpenSSL 3 开发包
- SQLite3 开发包

Ubuntu 示例：

```bash
sudo apt-get update
sudo apt-get install -y git python3 cmake build-essential libssl-dev sqlite3 libsqlite3-dev pkg-config
```

### 运行

```bash
git clone -b codex/prefuzzdup-lookup-handoff-5w \
  https://github.com/Davidlaizz/PreFuzzDup.git
cd PreFuzzDup

python3 tools/prefuzzdup-handoff/handoff.py server \
  --package handoff/20260921-prefuzzdup-5w \
  --scratch "$HOME/prefuzzdup-5w-scratch"
```

脚本会自动完成：

1. 校验 handoff 清单中的 SHA-256。
2. 校验参考库和查询集行数、ID、标签格式。
3. 配置并构建 `PreFuzzDup/build/prefuzzdup_persistent_lookup`。
4. 用 100 条查询执行 `scan/exact/prefuzz` 等价性检查。
5. 对阈值 `4,5,6` 各执行 1,000 条查询 × 3 次重复。
6. 输出逐查询 CSV、日志、环境信息、数据库大小和结果清单。

### 固定参数

- 标签位数：`256`
- FPP：`0.01`
- 策略：`prefuzz`
- 重复次数：`3`
- 阈值：`4,5,6`
- 页缓存：不清空
- SQLite 应用层缓存：约 `1 MiB`

### 成功检查

确认：

```bash
grep '"status": "passed"' \
  handoff/20260921-prefuzzdup-5w/results/server-result-manifest.json
grep 'equivalence_check=passed' \
  handoff/20260921-prefuzzdup-5w/results/logs/prefuzz_verify.log
wc -l handoff/20260921-prefuzzdup-5w/results/prefuzz_t*.csv
```

期望：

- `server-result-manifest.json` 中 `status` 为 `passed`
- `prefuzz_verify.log` 包含 `equivalence_check=passed`
- `prefuzz_t4.csv`、`prefuzz_t5.csv`、`prefuzz_t6.csv` 各 3,001 行（含表头）

### 回传

```bash
git add handoff/20260921-prefuzzdup-5w/results
git commit -m "chore(experiments): record prefuzzdup 5w server lookup results"
git push
```

不要把 `$HOME/prefuzzdup-5w-scratch` 下的 SQLite 文件加入 Git。

## 本地分析

```bash
git fetch origin
git switch codex/prefuzzdup-lookup-handoff-5w
git pull

python tools/prefuzzdup-handoff/handoff.py analyze \
  --package handoff/20260921-prefuzzdup-5w \
  --baseline results-local/enron-5w/lookup-experiment \
  --output results-local/prefuzzdup-handoff/enron-5w
```

输出：

- `comparison.csv`
- `latency_summary.csv`
- `workload_summary.csv`
- `metadata_comparison.csv`
- `analysis.md`

验收要求：

- 每个 `query_id × threshold × repeat` 的候选数完全一致
- `filter_queries`、`inverted_lookups`、`posting_records_read`、`full_tag_distance_computations` 完全一致
- `analysis.md` 中显示 `Workload disagreements: 0`

时延差异只做描述，不作为正确性判定。

## 全量阶段

5w 验收通过后：

```bash
git switch main
git pull
git switch -c codex/prefuzzdup-lookup-handoff-full

python tools/prefuzzdup-handoff/handoff.py client \
  --scale full \
  --source results-local/enron-full/lookup-experiment/inputs \
  --dest handoff/20260921-prefuzzdup-full

git add handoff/20260921-prefuzzdup-full
git commit -m "chore(experiments): package prefuzzdup full lookup handoff"
git push -u origin codex/prefuzzdup-lookup-handoff-full
```

服务器：

```bash
git clone -b codex/prefuzzdup-lookup-handoff-full \
  https://github.com/Davidlaizz/PreFuzzDup.git
cd PreFuzzDup

python3 tools/prefuzzdup-handoff/handoff.py server \
  --package handoff/20260921-prefuzzdup-full \
  --scratch "$HOME/prefuzzdup-full-scratch"
```

本地分析：

```bash
python tools/prefuzzdup-handoff/handoff.py analyze \
  --package handoff/20260921-prefuzzdup-full \
  --baseline results-local/enron-full/lookup-experiment \
  --output results-local/prefuzzdup-handoff/enron-full
```

## 失败处理

失败时脚本会在 `results/server-result-manifest.json` 写入 `status: failed`，并保留已产生的日志和部分结果。不要删除这些证据或在同一目录直接重跑。

处理顺序：

1. 查看对应 `results/logs/*.log`。
2. 检查依赖、磁盘空间和路径。
3. 保留失败包，另建新的 handoff 包重跑。

本实验是离线批处理交接，不测量网络延迟，也不代表完整端到端协议耗时。
