# 4110 第四候选 proof 验签交接

客户端完成 round003（candidate_rank=3）proof：171 条，signed=105、recovery_failed=66。私有正文、密钥、运行日志和历史留在本地。仅运行 PreFuzzDup。

## 更新与检查

仓库 /home/user/fl/PreFuzzDup，分支 codex/three-scheme-protocol-full。保留本地修改、stash 和失败现场；fetch、ff-only 更新后核对客户端提供的提交。不要 reset、clean、重建 session 或重签挑战。

```bash
git status --short
git fetch origin
git switch codex/three-scheme-protocol-full
git pull --ff-only
git rev-parse HEAD
df -h "$HOME"
python3 -m unittest discover -s tools/protocol-handoff -p test_server_verify_metadata.py
```

测试为 1 项、4 个轮次子用例。本轮回执在测试中模拟，不代表正式验签。未运行全仓测试。
正式 session 应有 8,121 个 token：7,950 已消费、171 未消费。不符即停止。
服务端 round003 原 manifest 的 prior_rounds_checked 仍写为 2，这是签发脚本遗留的元数据常量；三个 confirmations_rank 哈希均存在。本轮不改历史 manifest，不破坏哈希绑定。该计数字段不能作为链校验依据。

## 正式执行一次

沿用原 store、原 session 和正确链接 SQLite 3.45 的 CLI。work/output 必须不存在。禁止并发或重放旧 proof。

```bash
python3 tools/protocol-handoff/server_verify_proofs.py \
  --candidate-round 3 \
  --package handoff/20261008-prefuzzdup-cipher-import \
  --request handoff/20261009-prefuzz-client-run/client-request.json \
  --server-round handoff-results/prefuzz-full-20261009/server-next-round-003 \
  --client-proofs handoff-results/prefuzz-full-20261009/client-proof-round003/public \
  --confirmations handoff-results/prefuzz-full-20261009/client-confirmation-round002/public \
  --store "$HOME/prefuzz-cipher-import-20261008" \
  --session-db "$HOME/prefuzz-full-20261009-round0-r1/session.sqlite" \
  --session-binary "$HOME/prefuzz-protocol-bin/server_session_cli" \
  --work "$HOME/prefuzz-full-20261009-round3-verify-work" \
  --output handoff-results/prefuzz-full-20261009/server-receipts-round003
```

预期 proofs=171、receipts=171、verified=105、client_failed=66；candidate_round=3、status=awaiting_client_recovery。验签成功后仍需客户端解密、相似确认，不代表协议结束。

失败立即停止，保留日志、work、session，报告 CLI 是否启动和 token 是否消费。禁止删目录重跑或补写结果。Git 时间不计入算法时延。

## 回传

```bash
git add handoff-results/prefuzz-full-20261009/server-receipts-round003
git diff --cached --name-only
git commit -m "chore(experiments): return prefuzzdup round3 proof receipts"
git push origin codex/three-scheme-protocol-full
git ls-remote origin refs/heads/codex/three-scheme-protocol-full
```

暂存区只能包含本轮回执目录。不得提交 session、SQLite、store、scratch、密钥或明文。push 失败只重试推送，不重跑 verify。报告 HEAD、测试、实际计数、token 状态、结果 commit 和远端 tip，然后停止等待客户端。
