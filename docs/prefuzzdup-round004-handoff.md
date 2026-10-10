# 4110 第五候选签发 round004

round003 客户端真实确认：171 条中 accepted=6、similarity_rejected=99、recovery_failed=66。105 条 verified 执行解密和相似确认，66 条 client_failed 保留原失败结果。失败项中 150 条有第五候选，15 条耗尽候选。本地待回执为 0。计数包含阈值、重复次数和验证集任务，不是独立文件数。

## 更新和检查

在 /home/user/fl/PreFuzzDup，保留本地修改、stash、失败现场；fetch、ff-only 更新 codex/three-scheme-protocol-full 到客户端指定提交。禁止 reset、clean、重建 session、重放旧 proof、重签旧挑战。

```bash
git status --short
git fetch origin
git switch codex/three-scheme-protocol-full
git pull --ff-only
git rev-parse HEAD
df -h "$HOME"
python3 -m unittest discover -s tools/protocol-handoff -p test_server_round2.py
python3 tools/protocol-handoff/server_round2.py check \
  --candidate-round 4 \
  --package handoff/20261008-prefuzzdup-cipher-import \
  --request handoff/20261009-prefuzz-client-run/client-request.json \
  --root handoff-results/prefuzz-full-20261009
```

预期测试 6 项通过；check 为 passed、tasks=150、candidate_rank=4。仅使用临时模拟 session 测试，不触碰正式库。此次新增第五候选打包和拒绝重复签发测试；不是服务器正式签发。
原 session 应有 8,121 个 token，全部已消费。新 work/output 必须不存在，原 CLI 仍应链接 SQLite 3.45。空间不足即停止，不擅自清理现场。

## 正式签发一次

```bash
python3 tools/protocol-handoff/server_round2.py issue \
  --candidate-round 4 \
  --package handoff/20261008-prefuzzdup-cipher-import \
  --request handoff/20261009-prefuzz-client-run/client-request.json \
  --root handoff-results/prefuzz-full-20261009 \
  --store "$HOME/prefuzz-cipher-import-20261008" \
  --session-db "$HOME/prefuzz-full-20261009-round0-r1/session.sqlite" \
  --session-binary "$HOME/prefuzz-protocol-bin/server_session_cli" \
  --work "$HOME/prefuzz-full-20261009-round4-issue-work" \
  --output handoff-results/prefuzz-full-20261009/server-next-round-004
```

全部 all 模式、candidate_rank=4；t4=36、t5=54、t6=60，合计 150。
manifest：status=awaiting_client_proofs、candidate_round=4、next_challenges=150、prior_rounds_checked=4。
签发后 token 总数应为 8,271，其中已消费 8,121、未消费 150。
修正后的轮次计数仅影响新产物；历史 manifest 保留原样以维护哈希链。

禁止并发执行。任一步失败立即停止并保留日志、work 和 session，报告 CLI 是否运行及 token 状态，不删目录重跑、不手工补写 CSV。仍只运行 PreFuzzDup，不建索引，不测 Git 传输时间。

## 回传

```bash
git add handoff-results/prefuzz-full-20261009/server-next-round-004
git diff --cached --name-only
git commit -m "chore(experiments): return prefuzzdup fifth candidate challenges"
git push origin codex/three-scheme-protocol-full
git ls-remote origin refs/heads/codex/three-scheme-protocol-full
```

只提交本轮结果目录。禁止上传密钥、明文、SQLite、store、scratch。推送失败只重试推送。报告执行 HEAD、测试/check、实际计数、token 状态、结果 commit 和远端 tip，然后停止等待客户端 proof。协议尚未结束。
