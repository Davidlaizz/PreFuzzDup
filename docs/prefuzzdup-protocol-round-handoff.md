# PreFuzzDup 首轮协议交接

更新：2026-10-09。本机是客户端，4110 是服务端，只执行 PreFuzzDup。Git 是离线消息通道，不测 Git 和人工等待时间。不要重新导入已验收的密文，也不要运行 SimLESS/FuzzyDedup。

## 当前交付与边界

参考库 413,921 条标签，正式查询 5,000 条，验证查询 100 条。正式集为 200 完全相同、185 自然近似、815 合成近似、3,800 无匹配；合成近似只跑检索。真实查询共 4,245，合成查询共 855。阈值 4/5/6，nearest/all 两模式，每条 3 次，repeat 从 0 开始；验证集也按同样的重复次数运行。

客户端已重新读正文、核对 SHA、计算实际 C++ 标签，保存 12,735 行标签计时。已在本地准备 3,830 条无候选查询的新上传密文，并另存 11,490 行三次加密计时；仅保留 repeat=0 的密文。这批本地备用密文尚未上传，不能当成服务端已接收。原服务端 2,259 条参考密文不变，后续新上传只进入独立 overlay，不增加本次冻结检索参考库。

客户端公开请求与汇总在 `handoff/20261009-prefuzz-client-run/`。正文、私有清单、临时 TSV、新上传备用密文与逐条客户端计算证据保留在 `results-local/three-scheme-full-protocol/`，不要整目录加入 Git。历史参考密文只记录了 prepare_total_us，不能追溯拆成 AES 单独耗时；新上传测量才提供细分阶段。

本次服务端任务到“完成全量检索并发出第一候选挑战”为止。后续客户端签名、服务端验签、客户端解密确认需要继续 Git 往返；禁止把首轮完成标记为完整协议完成。

## 4110 执行

先保存现有工作；若仓库有不相关未提交改动，不覆盖、丢弃或强行切换。需要 Python 3.10+、CMake、C++20、OpenSSL 3 与 SQLite3 开发库，不需要 PBC/GMP。

```bash
git fetch origin
git switch codex/three-scheme-protocol-full
git pull --ff-only

python3 -m unittest discover -s tools/protocol-handoff -p test_client_messages.py
python3 -m unittest discover -s tools/protocol-handoff -p test_client_prepare.py
python3 -m unittest discover -s tools/protocol-handoff -p test_client_fallback.py

cmake -S PreFuzzDup -B PreFuzzDup/build -DCMAKE_BUILD_TYPE=Release
cmake --build PreFuzzDup/build --target prefuzzdup prefuzzdup_persistent_lookup -j2
./PreFuzzDup/build/prefuzzdup self-test

mkdir -p "$HOME/prefuzz-protocol-bin"
g++ -std=c++20 -O2 -IPreFuzzDup/src \
  tools/protocol-handoff/server_session_cli.cpp -lcrypto -lsqlite3 \
  -o "$HOME/prefuzz-protocol-bin/server_session_cli"

python3 tools/protocol-handoff/server_first_round.py \
  --package handoff/20261008-prefuzzdup-cipher-import \
  --request handoff/20261009-prefuzz-client-run/client-request.json \
  --store "$HOME/prefuzz-cipher-import-20261008" \
  --scratch "$HOME/prefuzz-full-20261009-round0" \
  --output handoff-results/prefuzz-full-20261009/server-round-000 \
  --lookup-binary PreFuzzDup/build/prefuzzdup_persistent_lookup \
  --session-binary "$HOME/prefuzz-protocol-bin/server_session_cli"
```

`--store` 必须指向此前验收的实际导入目录，包含 `import-report.json`、`protocol.sqlite` 和 `blobs/`；若实际路径不同，只替换此参数。scratch 和 output 必须不存在，失败保留现场，换新路径重试并说明原因，不删旧证据。SQLite 放 Linux 原生 scratch，不使用 `/mnt/`。脚本会核对包、请求、导入报告及数据库摘要，失败即停止。

运行顺序为验证集、正式集；各自 threshold 4/5/6，每个阈值 nearest 然后 all。预热和建库时间从原日志单列，不计入逐查询 latency_us。检索设置 `cache_size=0`、`mmap_size=0`，OS 页缓存不清空；挑战会话和公开协议存储是单独数据库，其缓存保持 SQLite 默认，不能把检索缓存设置描述为所有 SQLite 连接均关闭缓存。

## 验收与返回

正常输出应满足：

- 90,000 行正式检索结果，1,800 行验证检索结果；六个验证日志均有 `equivalence_check=passed`。
- 15,390 行合成查询仅检索，不签名、不解密。
- 68,940 行无候选真实查询暂不发挑战。
- 第一批挑战 7,470 条，只发各逻辑查询的第一候选；nearest 只能取第一名，all 后续须按失败结果继续。
- `server-round-manifest.json` 为 `status=awaiting_client_proofs`，不是 complete。

结果包括原始 CSV、stdout/stderr、环境信息、建库和运行命令、数据库大小、挑战耗时、严格白名单挑战包及摘要。challenge_us 包含服务端挑战生成和会话库写入，不包含查询耗时；有效期从真实签发时间起 20 天。不得改写结果值或跳过过期、绑定及一次性消费检查。

```bash
git add handoff-results/prefuzz-full-20261009/server-round-000
git commit -m "chore(experiments): return prefuzzdup full lookup and first challenges"
git push origin codex/three-scheme-protocol-full
```

只提交该结果目录，scratch/session.sqlite 和 server-queue.jsonl 留在服务端。保存整个 scratch，后续验签与候选推进会继续使用。推送失败报告凭据或网络错误，不将本地提交当成回传完成；不要在聊天、命令或日志里打印 token 凭据。

## 客户端收到挑战后

客户端首先运行审计关卡，审计通过才允许运行签名：

```powershell
python tools/protocol-handoff/client_round_audit.py `
  --package handoff/20261008-prefuzzdup-cipher-import `
  --request handoff/20261009-prefuzz-client-run/client-request.json `
  --server-round handoff-results/prefuzz-full-20261009/server-round-000 `
  --inventory results-local/three-scheme-full-protocol/candidate-inventory-v2-20261008 `
  --output results-local/three-scheme-full-protocol/client-round-000-audit
```

审计输出的 `proof_gate=passed` 才是签名入口；`audit-report.json` 和 `challenges.csv` 要与服务端 manifest 一起留存。若任一摘要、候选、重复序号或挑战绑定错误，停止，不修正服务端 CSV。

先拉取服务端结果并核对 manifest 和独立候选真值，再执行客户端签名。下列本地命令使用本轮已冻结的私有状态与二进制，不在服务器运行：

```powershell
python tools/protocol-handoff/client_messages.py sign --state results-local/three-scheme-full-protocol/client-v1-20261009 --package handoff/20261008-prefuzzdup-cipher-import --binary results-local/tool-build/client_crypto --plan results-local/three-scheme-full-protocol/prefuzz-artifacts-v3-20261008 --inventory results-local/three-scheme-full-protocol/candidate-inventory-v2-20261008 --input handoff-results/prefuzz-full-20261009/server-round-000/challenges --output results-local/three-scheme-full-protocol/client-proof-round000
```

`public/` 中只有签名、公开任务字段、状态和计算耗时，才能交付；`local-work/` 和 client-state 不提交。恢复秘密 Q、seed、明文密钥均在客户端内存，不写入服务端消息。失败的真实查询显式返回 recovery_failed 等原因，不能假造成功证明。未进入的计算阶段按状态判断为未执行，不把零占位当作该阶段耗时样本。

客户端只有在服务端回传绑定同一 proof CSV SHA-256 的真实验签结果后，才执行 recover 命令。其输出 public/confirmations.csv 是最终确认消息；局部历史记录会拒绝重复挑战、跨实验重放、跳过前候选或在已接受后继续请求候选。接下来再下发验签和下一候选轮次指令，不要求服务端 agent 自行扩展协议。

解密沿用原 AES-GCM、封装密钥恢复和完整性检查，之后使用原 ASCII 规范化的五词集合 Jaccard，阈值 0.5。不足五词时整个规范化文本为一个片段，两个空文本为 1。相似复用不保证逐字节恢复原查询；相同正文与 SimHash 距离 0 也不是同一个概念。

## 计时口径

标签、FE/密钥恢复、签名、解密、完整性验证、正文确认均有实际计算计时。新上传加密区分 FE、密钥派生、两次 AES-GCM、自检。原始正文提取、文件 I/O、进程启动和 Git 等待不混入这些计算时间。recover 命令会重新计算 Q，单列 key_recovery_us，不声称复用了上一步内存状态。

通信只估算为 `轮次 × 1 ms + 字节数 × 8 / 1e9 秒`，轮次指每个逻辑查询的协议往返次数，不是 Git 提交次数。须注明所用实际消息数量与密文大小，不能当作实测网络时间。Git 打包和传输时间完全不测。当前公开报告仅给出模型参数，不填造尚未发生的完整端到端结果。
