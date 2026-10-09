# 服务端导入验收与下一阶段

日期：2026-10-09。当前仅执行 PreFuzzDup。

最新检查点：客户端批处理准备、签名、解密确认和新上传加密工具已实现并执行本地验收；4,245 条真实查询产生 12,735 行标签计时，3,830 条无候选查询产生 11,490 行加密计时并各保留一份备用密文。18 次真实密文往返及重放拒绝通过，首轮脚本 91,800 行检索输出与独立真值一致。这是本地验证，4110 仍仅完成此前导入。当前执行入口见 [首轮协议交接](prefuzzdup-protocol-round-handoff.md)，公开结果见 [客户端准备摘要](../handoff/20261009-prefuzz-client-run/README.md)。以下内容保留实现过程检查点。

## 服务端返回结果

已 fetch 并以 fast-forward 拉取服务端提交 `a5ccfbf`，未覆盖本地未提交改动。报告为 `handoff-results/20261008-prefuzzdup-cipher-import/server-import-report.json`。

| 项目 | 服务端报告 |
|---|---:|
| 导入状态 | passed |
| 全量参考标签数 | 413,921 |
| 已准备密文记录数 | 2,259 |
| 密文本体字节数 | 14,224,623 |
| 协议 SQLite 字节数 | 1,204,224 |

本地重新校验交接包全部文件摘要。服务端报告中的 handoff_manifest_sha256、records_sha256、code_sha256 分别与本地交接清单、公开记录和导入器代码一致。数据库本体留在服务端，因此未独立复算服务端 db_sha256；不能将报告验收称作远程数据库现场复验。报告没有测试日志和运行环境，不额外声称这些内容已验收。

导入阶段完成。`search_index_created=false`、`crypto_verified_by_server=false`、`handoff_ready=false` 仍是准确状态：没有完成本次两机完整协议。

## 已开始的下一阶段

新增 `tools/protocol-handoff/protocol_store.hpp`，复用原 C++ Record 类型，以 SQLite 只读方式打开稀疏协议存储。按原始参考 ID 取记录，校验其 tag 与检索层给出的参考 tag 一致，读取密文时检查规范路径、大小和 SHA-256。缺失记录返回空，不伪造密文、不创建数据库和索引。

本地 WSL 使用现有模拟导入库验收 2,259 条映射和密文；错误标签、缺失 ID、篡改密文均按预期处理，数据库读前读后摘要不变。测试命令：

```bash
g++ -std=c++20 -O2 -IPreFuzzDup/src \
  tools/protocol-handoff/test_protocol_store.cpp -lcrypto -lsqlite3 \
  -o results-local/tool-build/test_protocol_store
results-local/tool-build/test_protocol_store \
  /home/user/prefuzz-protocol-import-v1-20261008
```

这是本地适配层测试，不是 4110 全量查询耗时，也没有代替原所有权证明。头文件须在原核心代码后包含，与现有工具一致。

## 后续顺序

2026-10-09 第二检查点：新增 `protocol_session.hpp`，已实现独立会话 SQLite、服务端签发挑战、客户端 `client_sign` 和服务端一次性验签函数。绑定包括 run、uid、query_id、mode、原始参考 ID、threshold、0 起始 repeat、query_tag 以及记录身份和公钥；每个挑战有效期独立保存。签名消息沿用原 `Server::challenge_message`，客户端使用原恢复表示、FE、HKDF 与 Ed25519，唯一对外输出是签名。恢复秘密 Q 和 seed 不入服务端库。

新增测试通过：会话重开、20 天 TTL、过期、错误签名、跨上述字段重放、替换记录以及防止把导入库当会话库。原 TTL 测试与 2,259 条存储适配测试也通过。会话头文件仅为内部函数接口；尚无消息序列化、角色 CLI、完整计时、密文授权回传和正文确认。调用方还须从只读存储加载可信记录、核对候选并过滤 synthetic/N/A，不能直接信任外部传入 Record。

```bash
g++ -std=c++20 -O2 -IPreFuzzDup/src \
  tools/protocol-handoff/test_protocol_session.cpp -lcrypto -lsqlite3 \
  -o results-local/tool-build/test_protocol_session
results-local/tool-build/test_protocol_session
```

以下顺序中的第 1 项已有函数级实现，第 2 项已完成计算接口，但仍待文件交接命令接通；不将其计为两机运行成功。

1. 单独建立运行会话状态，保存 run_id、查询、模式、阈值、重复序号、候选和挑战绑定；不修改导入密文库或冻结检索库。
2. 实现服务端挑战消息导出、客户端真实恢复与签名、服务端一次性验签。签发时应用 20 天有效期，真实过期检查保留。
3. 验证通过后返回密文，客户端沿用原恢复/解密逻辑，再做最终正文相似确认并回传。失败与合成查询的 N/A 必须显式记录。
4. 完成阶段耗时、通信估算、独立验收后，再发送新交接任务。当前不要求服务端重复导入或提前发起 5,000 条协议实验。
