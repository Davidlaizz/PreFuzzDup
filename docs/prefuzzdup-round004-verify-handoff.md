# 4110 第五候选 proof 验签交接

客户端已完成 round004 proof，共 150 条：signed=99、recovery_failed=51。公开证明在 `handoff-results/prefuzz-full-20261009/client-proof-round004/public`。私有正文、密钥、客户端历史和运行日志不上传。本轮仍只运行 PreFuzzDup。

## 更新与检查

在 /home/user/fl/PreFuzzDup 保留本地修改、stash 和失败现场，fetch 后 ff-only 更新分支。禁止 reset、clean、重建或移动 session、重签挑战、重放旧 proof、并发 verify。

```bash
git status --short
git fetch origin
git switch codex/three-scheme-protocol-full
git pull --ff-only
git rev-parse HEAD
df -h "$HOME"
python3 -m unittest discover -s tools/protocol-handoff -p test_server_verify_metadata.py
```

测试应显示 1 项通过，包含 round000 至 round004 五个轮次子用例。测试回执是临时模拟数据，不是正式验签。未运行全仓测试。

正式 session 在验签前应有 **8,271 个 token：8,121 已消费、150 未消费**。若不一致，立即停止并报告。

2026-10-11 更正：此前写成 8,421/8,271/150，是客户端交接文档重复计入本轮 150 个 token 的错误，不是额外签发要求。已核验公开挑战和既有回执的文件摘要、token 唯一性及覆盖关系：

| 轮次 | 本轮签发 | 累计签发 |
| --- | ---: | ---: |
| round000 | 7,470 | 7,470 |
| round001 | 294 | 7,764 |
| round002 | 186 | 7,950 |
| round003 | 171 | 8,121 |
| round004 | 150 | 8,271 |

前四轮已有 8,121 条对应回执，本轮 150 条尚待正式验签。服务器报告的 8,271/8,121/150 与公开台账一致。此前因错误预期停止且 verify 未启动、work/output 未创建的情况下，更新到本次修正文档的提交后，允许按下述原命令继续执行一次 verify。不得为了满足旧数字补签 token、修改数据库或重新生成 proof。

验签只消费现有 token，不增加 token：成功后的预期是 **8,271 总数、8,271 已消费、0 未消费**。

## 正式验签

沿用原 store、原 session 和正确链接 SQLite 3.45 的 CLI，只执行一次：

```bash
python3 tools/protocol-handoff/server_verify_proofs.py \
  --candidate-round 4 \
  --package handoff/20261008-prefuzzdup-cipher-import \
  --request handoff/20261009-prefuzz-client-run/client-request.json \
  --server-round handoff-results/prefuzz-full-20261009/server-next-round-004 \
  --client-proofs handoff-results/prefuzz-full-20261009/client-proof-round004/public \
  --confirmations handoff-results/prefuzz-full-20261009/client-confirmation-round003/public \
  --store "$HOME/prefuzz-cipher-import-20261008" \
  --session-db "$HOME/prefuzz-full-20261009-round0-r1/session.sqlite" \
  --session-binary "$HOME/prefuzz-protocol-bin/server_session_cli" \
  --work "$HOME/prefuzz-full-20261009-round4-verify-work" \
  --output handoff-results/prefuzz-full-20261009/server-receipts-round004
```

预期：proofs=150、receipts=150、verified=99、client_failed=51；candidate_round=4、status=awaiting_client_recovery。验签成功后仍需客户端 recovery、解密和正文相似确认，不代表协议结束。

recovery_failed 由客户端恢复阶段产生，服务端不得改写为成功或自行解释。失败时保留 stdout、stderr、work 和 session，报告 CLI 是否启动、token 是否消费；禁止删除后重跑或手工修正 CSV。

## 回传

```bash
git add handoff-results/prefuzz-full-20261009/server-receipts-round004
git diff --cached --name-only
git commit -m "chore(experiments): return prefuzzdup round4 proof receipts"
git push origin codex/three-scheme-protocol-full
git ls-remote origin refs/heads/codex/three-scheme-protocol-full
```

暂存区只能包含 `server-receipts-round004/`，不得提交 session、SQLite、store、scratch、密钥或明文。push 失败只重试 push，不重跑 verify。报告 HEAD、测试、实际回执计数、token 状态、结果 commit 和远端 tip，然后停止等待客户端 recovery。
