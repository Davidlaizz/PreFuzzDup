# PreFuzzDup 密文导入阶段交接

本次仅交付公开字段和密文的完整性校验、服务端稀疏协议存储导入，不代表完整协议已完成。服务端为 4110，客户端为本机；不执行其他两个方案。

## 服务端执行

代码与交接包推送后，在实验分支执行，Python 3.10+ 即可，无需加密私钥或原始邮件：

```bash
git fetch origin
git switch codex/three-scheme-protocol-full
git pull --ff-only
python3 -m unittest discover -s tools/protocol-handoff -p test_cipher_handoff.py
python3 -m unittest discover -s tools/protocol-handoff -p test_import_prefuzz_artifacts.py
python3 tools/protocol-handoff/cipher_handoff.py server \
  --package handoff/20261008-prefuzzdup-cipher-import \
  --output "$HOME/prefuzz-cipher-import-20261008"
```

输出目录必须不存在；失败时保留目录排查，改用新的输出目录重试，不覆盖旧证据。SQLite 和密文副本必须保存在 Linux 原生 scratch。

验收：`status=passed`、`records=2259`、`full_reference_count=413921`、`cipher_bytes=14224623`。`protocol_store_only=true`，`search_index_created=false`、`crypto_verified_by_server=false` 和 `handoff_ready=false` 是预期状态，不能改成 true。导入器验证结构、记录映射和摘要，没有运行解密或所有权证明。

## 返回结果

报告保存在包目录外，避免破坏严格的包文件白名单：

```bash
mkdir -p handoff-results/20261008-prefuzzdup-cipher-import
cp "$HOME/prefuzz-cipher-import-20261008/import-report.json" \
  handoff-results/20261008-prefuzzdup-cipher-import/server-import-report.json
git add handoff-results/20261008-prefuzzdup-cipher-import/server-import-report.json
git commit -m "chore(experiments): record server ciphertext import"
git push
```

不要提交 SQLite、scratch 目录或新增密文副本。客户端核对返回报告中的包 manifest SHA-256。

## 边界与后续

包内保留全部参考标签、5,000 条正式查询、100 条验证查询及公开分组，只有 2,259 条实际协议参考记录具有密文。合成标签只用于检索，不参与真实正文协议。

包配置的挑战有效期是 20 天；导入阶段不签发挑战，也不开始计时。后续适配器须在真实签发时应用该配置，保留过期、绑定、签名及一次性消费检查。计算阶段测真实耗时，Git 与人工等待不计入；通信独立按 RTT 1 ms、1 Gbit/s 估算。

下一阶段实现稀疏协议库适配、分角色挑战/证明消息和恢复确认后，另行发出执行指令。不要用原 `prefuzzdup setup` 覆写此导入库，或把它当作全量检索索引。
