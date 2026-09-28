# No-SQLite-cache server handoff

本文档给 4110 服务端使用。本机是客户端，4110 是服务端；Git 只负责离线文件交接。

## 1. 克隆分支

```bash
git clone -b codex/no-sqlite-cache-full \
  https://github.com/Davidlaizz/PreFuzzDup.git

cd PreFuzzDup
```

确认当前分支：

```bash
git branch --show-current
```

预期输出：

```text
codex/no-sqlite-cache-full
```

## 2. 环境要求

需要：

- Git
- Python 3.10+
- CMake 3.22+
- C++20 编译器
- OpenSSL 3
- SQLite3 开发库

Ubuntu 示例：

```bash
sudo apt-get update
sudo apt-get install -y git python3 cmake build-essential pkg-config \
  libssl-dev sqlite3 libsqlite3-dev
```

## 3. 执行服务端任务

scratch 必须放在 Linux 原生文件系统，不要放在 `/mnt`。

```bash
python3 tools/lookup-handoff/handoff.py server \
  --package handoff/20260928-no-sqlite-cache-full \
  --scratch "$HOME/no-sqlite-cache-full-scratch" \
  --sqlite-cache-kib 0
```

该命令会：

1. 校验客户端包 SHA-256。
2. 构建三个 lookup benchmark。
3. 执行 PreFuzzDup 100 条等价性抽查。
4. 按固定顺序运行三方案 benchmark。
5. 强制所有查询使用 `--sqlite-cache-kib 0`。
6. 生成日志、环境信息和结果清单。

不要清空 OS page cache：

```bash
# 不要执行
sudo sysctl vm.drop_caches=3
```

## 4. 检查是否成功

```bash
grep '"status": "passed"' \
  handoff/20260928-no-sqlite-cache-full/results/server-result-manifest.json

grep 'equivalence_check=passed' \
  handoff/20260928-no-sqlite-cache-full/results/logs/prefuzzdup-verify.log

grep 'sqlite_cache_kib=0' \
  handoff/20260928-no-sqlite-cache-full/results/logs/prefuzzdup-t4.log \
  handoff/20260928-no-sqlite-cache-full/results/logs/prefuzzdup-t5.log \
  handoff/20260928-no-sqlite-cache-full/results/logs/prefuzzdup-t6.log
```

预期行数：

```text
prefuzzdup_t4.csv          3,000
prefuzzdup_t5.csv          3,000
prefuzzdup_t6.csv          3,000
simless_bench.csv          9,000
fuzzydedup_bench.csv       9,000
```

以上数字不包含 CSV header。

## 5. 回传结果

只提交结果目录，不提交 scratch 或 SQLite：

```bash
git add handoff/20260928-no-sqlite-cache-full/results
git commit -m "chore(experiments): record no-sqlite-cache full lookup results"
git push
```

如果推送要求凭据，使用服务端已有的 GitHub credential helper 或 Personal Access Token。不要把 token 写进仓库文件。

## 6. 失败处理

如果命令失败：

1. 不要删除 `results/`。
2. 保留 `logs/` 和 `server-result-manifest.json`。
3. 将失败结果提交并推送，便于客户端诊断。
4. 不要修改任何结果 CSV。

失败时状态应为：

```json
{
  "status": "failed"
}
```
