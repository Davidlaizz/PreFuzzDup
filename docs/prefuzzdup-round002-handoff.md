# 4110 第三候选签发交接

本轮只签发第三候选（rank=2），不检索、不验旧 proof、不重建数据库。客户端已完成第二候选确认，下一步必须由 4110 使用原 session 签发。旧 server_issue_next_candidates.py 不用于本轮。

预期 186 条，全部 all 模式：t4=54、t5=60、t6=72。成功状态 awaiting_client_proofs，不是协议完成。客户端收到后再签名。

## 更新与前置检查

在 /home/user/fl/PreFuzzDup，先检查 git status。若存在上轮两处 manifest_name 本地修正，用 git diff 保存补丁，再仅 stash 该脚本；保留所有历史 stash 和失败现场。不要 reset、clean 或 force push。

```bash
git fetch origin
git switch codex/three-scheme-protocol-full
git pull --ff-only
git rev-parse HEAD
df -h "$HOME"
python3 -m unittest discover -s tools/protocol-handoff -p test_server_round2.py
python3 tools/protocol-handoff/server_round2.py check \
  --package handoff/20261008-prefuzzdup-cipher-import \
  --request handoff/20261009-prefuzz-client-run/client-request.json \
  --root handoff-results/prefuzz-full-20261009
```

任一命令失败即停止并报告，不要自动改代码。check 必须输出 passed、tasks=186、candidate_rank=2；该命令不接触正式 session。测试默认使用临时模拟会话，不触碰原数据库。

此前系统盘余量约 950 MB，本轮不新建索引，只有小型 TSV/日志和 186 条挑战。先检查空间；不足时停止，未经授权不要清理原库、session、失败现场或旧 stash。

## 执行一次

必须使用成功首轮的原始 session 和原 store，以及已正确链接 SQLite 3.45 的原二进制。禁止重编译后误链系统 SQLite。以下 work/output 必须不存在。

```bash
python3 tools/protocol-handoff/server_round2.py issue \
  --package handoff/20261008-prefuzzdup-cipher-import \
  --request handoff/20261009-prefuzz-client-run/client-request.json \
  --root handoff-results/prefuzz-full-20261009 \
  --store "$HOME/prefuzz-cipher-import-20261008" \
  --session-db "$HOME/prefuzz-full-20261009-round0-r1/session.sqlite" \
  --session-binary "$HOME/prefuzz-protocol-bin/server_session_cli" \
  --work "$HOME/prefuzz-full-20261009-round2-issue-work" \
  --output handoff-results/prefuzz-full-20261009/server-next-round-002
```

工具会校验两轮文件摘要、证明/回执/确认链、真实查询资格、失败前缀和候选顺序，并检查原 session 的 7,764 个旧 token 均已消费。若已经追加任何挑战，会拒绝再次签发。禁止同时启动两个 issue 进程。失败后保留现场，报告是否已进入 CLI；不要删除后重跑，也不要自行补写结果。

正常输出包含 challenges/、challenge-metrics.csv、environment.json、issue.stdout/stderr、next-round-manifest.json。检查 status=awaiting_client_proofs、candidate_round=2、next_challenges=186，以及全部 rank=2、all 模式。

```bash
git add handoff-results/prefuzz-full-20261009/server-next-round-002
git diff --cached --name-only
git commit -m "chore(experiments): return prefuzzdup third candidate challenges"
git push origin codex/three-scheme-protocol-full
git ls-remote origin refs/heads/codex/three-scheme-protocol-full
```

暂存区必须只有本轮结果目录。禁止提交 SQLite、store、blobs、work、密钥或明文。回报执行代码提交、原 session 路径、测试/check/issue 状态、分阈值计数、结果 commit、远端 tip。push 失败只重试推送，不重跑实验。

## 本地验证边界

客户端以两轮公开证据检查出 186 条。回归覆盖重复确认、伪造成功、候选排序、完整打包和重复签发拒绝。真实 CLI 测试使用本机 WSL 已导入参考库与新建临时 session，旧 token 使用合成已消费状态；不是 4110 正式挑战，不计入实验时延。服务端原 session 的检查仍必须在 4110 完成。

2026-10-10 本地验证：Windows 默认回归 3 项通过，WSL 真实 CLI 集成回归 3 项通过，既有回执元数据回归 1 项通过；check 输出 passed。186 条任务的参考记录 ID 与本地独立候选清单逐条一致（186/186）。未运行整个仓库的测试套件，本轮没有改动检索或密码学实现。
