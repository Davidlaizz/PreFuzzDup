# 4110 第三候选 proof 验签交接

客户端已审计服务端提交 b0d78ea 的文件摘要、挑战绑定、候选顺序及 token 唯一性，并使用本地真实 client_crypto 完成 186 条任务：signed=87、recovery_failed=99。公开证明位于 client-proof-round002/public；私有正文、历史和运行日志仍在本地 results-local。本轮仍仅运行 PreFuzzDup。

## 更新与检查

在 /home/user/fl/PreFuzzDup 检查工作区，保留已有修改、stash 和失败现场。fetch 并 ff-only 更新 codex/three-scheme-protocol-full，确认 HEAD 等于客户端提供的提交。不要 reset、clean 或强制推送。

```bash
git status --short
git fetch origin
git switch codex/three-scheme-protocol-full
git pull --ff-only
git rev-parse HEAD
df -h "$HOME"
python3 -m unittest discover -s tools/protocol-handoff -p test_server_verify_metadata.py
```

测试覆盖三轮打包及 manifest 绑定；第三轮回执为测试内临时模拟数据，不是正式验签结果。任何检查失败即停止报告，不自行改代码。正式 session 应有 7,950 个 token，其中旧轮 7,764 个已消费、本轮 186 个未消费。禁止重签挑战、重放旧 proof、重建或移动数据库。

## 正式执行一次

沿用正确链接 SQLite 3.45 的原 CLI；work/output 必须不存在。不要并发执行。

```bash
python3 tools/protocol-handoff/server_verify_proofs.py \
  --candidate-round 2 \
  --package handoff/20261008-prefuzzdup-cipher-import \
  --request handoff/20261009-prefuzz-client-run/client-request.json \
  --server-round handoff-results/prefuzz-full-20261009/server-next-round-002 \
  --client-proofs handoff-results/prefuzz-full-20261009/client-proof-round002/public \
  --confirmations handoff-results/prefuzz-full-20261009/client-confirmation-round001/public \
  --store "$HOME/prefuzz-cipher-import-20261008" \
  --session-db "$HOME/prefuzz-full-20261009-round0-r1/session.sqlite" \
  --session-binary "$HOME/prefuzz-protocol-bin/server_session_cli" \
  --work "$HOME/prefuzz-full-20261009-round2-verify-work" \
  --output handoff-results/prefuzz-full-20261009/server-receipts-round002
```

预期 proofs=186、receipts=186，verified=87、client_failed=99；candidate_round=2、status=awaiting_client_recovery。服务端实际验签前，这些只是验收预期。成功后客户端还需解密、相似确认，再决定是否继续候选，当前不代表协议完成。

若出错，保留所有日志和现场，报告 CLI 是否已运行、token 是否已消费；禁止删目录重跑或手工修数。即使错误发生在打包阶段，也不要重复 verify。

## 回传

```bash
git add handoff-results/prefuzz-full-20261009/server-receipts-round002
git diff --cached --name-only
git commit -m "chore(experiments): return prefuzzdup round2 proof receipts"
git push origin codex/three-scheme-protocol-full
git ls-remote origin refs/heads/codex/three-scheme-protocol-full
```

暂存区只允许本轮回执目录，不提交密钥、明文、SQLite、store、blobs 或 scratch。push 失败只重试推送。报告执行代码 HEAD、测试、实际计数、manifest 状态、结果 commit 和远端 tip，然后停止等待客户端。

Git 传输不计入算法耗时；客户端计算实际计时，20 天 TTL 维持原挑战配置。本轮只交接验证，不改变检索、加解密或相似判断算法。
