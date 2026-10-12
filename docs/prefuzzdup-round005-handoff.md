# 4110 第六候选签发 round005

客户端已完成 round004 recovery：150 条中 accepted=12、similarity_rejected=87、recovery_failed=51。99 条 verified 实际进入客户端解密与正文相似确认；51 条 client_failed 保留失败状态。失败任务中 135 条还有第六候选，3 条候选耗尽。本地待回执为 0。这些是包含阈值和重复次数的任务数，不是独立文件数。

## 前置检查

仓库 /home/user/fl/PreFuzzDup，分支 codex/three-scheme-protocol-full。保留本地修改、stash 和失败现场，fetch 后 ff-only 更新到客户端给出的提交，核对 HEAD。禁止 reset、clean、重建或移动 session、重签旧挑战、重放旧 proof。

```bash
git status --short
git fetch origin
git switch codex/three-scheme-protocol-full
git pull --ff-only
git rev-parse HEAD
df -h "$HOME"
python3 -m unittest discover -s tools/protocol-handoff -p test_server_round2.py
python3 tools/protocol-handoff/server_round2.py check \
  --candidate-round 5 \
  --package handoff/20261008-prefuzzdup-cipher-import \
  --request handoff/20261009-prefuzz-client-run/client-request.json \
  --root handoff-results/prefuzz-full-20261009
```

预期测试 8 项通过，check 输出 passed、tasks=135、candidate_rank=5。测试使用临时模拟 session，不触碰正式库；本次未重跑全仓测试。候选 ID 已与客户端独立候选清单逐条核对。

签发前 token 总数从五轮公开挑战去重计算：7,470+294+186+171+150=8,271。前五轮回执全部返回，因此正式 session 应有 **8,271 总数、8,271 已消费、0 未消费**。本轮签发只新增 135 个，不额外增加其他 token。任何不一致立即停止报告。

原 store 和原 CLI 保持使用；CLI 须仍正确链接 SQLite 3.45。新 work/output 必须不存在；磁盘不足时停止，不擅自清理历史现场。

## 执行一次

```bash
python3 tools/protocol-handoff/server_round2.py issue \
  --candidate-round 5 \
  --package handoff/20261008-prefuzzdup-cipher-import \
  --request handoff/20261009-prefuzz-client-run/client-request.json \
  --root handoff-results/prefuzz-full-20261009 \
  --store "$HOME/prefuzz-cipher-import-20261008" \
  --session-db "$HOME/prefuzz-full-20261009-round0-r1/session.sqlite" \
  --session-binary "$HOME/prefuzz-protocol-bin/server_session_cli" \
  --work "$HOME/prefuzz-full-20261009-round5-issue-work" \
  --output handoff-results/prefuzz-full-20261009/server-next-round-005
```

预期全部 mode=all、candidate_rank=5，共 135 条：t4=33、t5=48、t6=54。
manifest：status=awaiting_client_proofs、candidate_round=5、next_challenges=135、prior_rounds_checked=5。
签发后的预期是 **8,406 总数、8,271 已消费、135 未消费**（8,271+135=8,406）。

禁止并发 issue。本轮不重建索引，只运行 PreFuzzDup。任何失败立即停止并保留日志、work、output 和 session，报告 CLI 是否启动及 token 状态；不得删除后重跑或手工修改结果。不得修改已有历史 manifest。

## 回传

```bash
git add handoff-results/prefuzz-full-20261009/server-next-round-005
git diff --cached --name-only
git commit -m "chore(experiments): return prefuzzdup sixth candidate challenges"
git push origin codex/three-scheme-protocol-full
git ls-remote origin refs/heads/codex/three-scheme-protocol-full
```

暂存区只能包含本轮结果目录，禁止提交 session、SQLite、store、scratch、密钥或明文。push 失败只重试推送，不重跑实验。报告 HEAD、测试/check、实际挑战分布、token 状态、结果 commit 和远端 tip，然后停止等待客户端 proof。Git 传输不计入算法耗时，完整协议尚未结束。
