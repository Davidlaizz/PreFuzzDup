# 4110 第四候选签发交接

客户端已完成 round002 recovery。结果为 accepted=3、similarity_rejected=84、recovery_failed=99；其中 171 条仍存在第四候选，12 条已无可用候选。下一步由 4110 在原 session 上只签发第四候选（candidate_rank=3），仍仅运行 PreFuzzDup。

## 本地验证结果

客户端已拉取服务端 round002 回执并核对摘要、token、任务绑定和 session 历史。第四候选计划通过本地独立候选清单逐条核验：171 条，阈值 t4=45、t5=60、t6=66，全部 `mode=all`、`candidate_rank=3`。`test_server_round2.py` 四项通过；`server_round2.py check --candidate-round 3` 输出 `passed, tasks=171, candidate_rank=3`。

## 4110 执行

在 `/home/user/fl/PreFuzzDup` 保留本地修改、stash 和失败现场，fetch 后 ff-only 更新到分支最新提交。先检查空间；本轮不建索引，只生成小型 TSV、日志和 171 条挑战。不要 reset、clean、重建 session、重跑检索、重签旧挑战或并发运行 issue。

```bash
git status --short
git fetch origin
git switch codex/three-scheme-protocol-full
git pull --ff-only
git rev-parse HEAD
df -h "$HOME"
python3 -m unittest discover -s tools/protocol-handoff -p test_server_round2.py
python3 tools/protocol-handoff/server_round2.py check \
  --candidate-round 3 \
  --package handoff/20261008-prefuzzdup-cipher-import \
  --request handoff/20261009-prefuzz-client-run/client-request.json \
  --root handoff-results/prefuzz-full-20261009
```

check 必须输出 171、rank=3。正式 session 在 round002 验签后应有 7,950 个已消费 token；若数量或状态不符，立即停止并报告。

使用原 store、原 session 和已正确链接 SQLite 3.45 的 CLI，只执行一次：

```bash
python3 tools/protocol-handoff/server_round2.py issue \
  --candidate-round 3 \
  --package handoff/20261008-prefuzzdup-cipher-import \
  --request handoff/20261009-prefuzz-client-run/client-request.json \
  --root handoff-results/prefuzz-full-20261009 \
  --store "$HOME/prefuzz-cipher-import-20261008" \
  --session-db "$HOME/prefuzz-full-20261009-round0-r1/session.sqlite" \
  --session-binary "$HOME/prefuzz-protocol-bin/server_session_cli" \
  --work "$HOME/prefuzz-full-20261009-round3-issue-work" \
  --output handoff-results/prefuzz-full-20261009/server-next-round-003
```

预期输出目录为 `server-next-round-003`，manifest 为 `status=awaiting_client_proofs`、`candidate_round=3`、`next_challenges=171`，分布 t4=45、t5=60、t6=66。失败时保留所有现场，不删除后重跑。

## 回传

```bash
git add handoff-results/prefuzz-full-20261009/server-next-round-003
git diff --cached --name-only
git commit -m "chore(experiments): return prefuzzdup fourth candidate challenges"
git push origin codex/three-scheme-protocol-full
git ls-remote origin refs/heads/codex/three-scheme-protocol-full
```

暂存区只能包含本轮结果目录，不提交 session、SQLite、store、scratch、密钥或明文。push 失败只重试推送，不重跑 issue。回报 HEAD、测试/check、挑战分布、session token 状态、结果 commit 和远端 tip，然后停止等待客户端 proof。
