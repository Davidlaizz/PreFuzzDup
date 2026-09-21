# Enron 实验工具

这些工具由已完成的本地实验脚本整理而来。`enron-full` 会导入同级
`enron-5w` 的切分、校验和汇总代码，必须保留两个目录的相对位置。
原始邮件、数据集、数据库和原始运行证据不随仓库分发。

## 环境与无数据测试

Python 3.10+，依赖见 `requirements.txt`（本次 Windows 验证使用 NumPy 2.2.6）。
从仓库根目录运行：

```bash
python -m pip install -r tools/requirements.txt
python -m unittest discover -s tools/enron-5w -v
python -m unittest discover -s tools/enron-full -v
```

两组测试须分别启动，避免同名测试模块互相遮蔽。九个边界夹具在
`fixtures/enron-tag-edge-cases.csv`，只有人工构造的短文本及预期标签，
不含真实邮件。预期值源自原独立 C++ `make_tag()` 校验过的边界用例。

## 数据准备

在 Linux/WSL 中从仓库根目录执行。先按根 README 配置三个 Release 构建。
需要 C++20、OpenSSL 3、SQLite3 开发包；对比方案还需要 GMP、PBC。
使用相同版本的 CMU Enron 2015-05-07 语料，将原压缩包放在根目录
`enron_mail_20150507.tar.gz`，解压邮件位于 `enron_mail_20150507/maildir/`。
准备程序要求全量恰好 517,401 个文件；目标或 staging 已存在时会拒绝覆盖。

```bash
mkdir -p results-local/tool-build
c++ -std=c++20 -O3 -I PreFuzzDup/src tools/enron-5w/verify_tag.cpp -lcrypto -lsqlite3 -o results-local/tool-build/verify_tag
c++ -std=c++20 -O3 -I PreFuzzDup/src tools/enron-full/verify_full_tag.cpp -lcrypto -lsqlite3 -o results-local/tool-build/verify_full_tag
python3 tools/enron-5w/prepare_dataset.py prepare
results-local/tool-build/verify_tag enron_mail_20150507/5wTest.staging
python3 tools/enron-5w/prepare_dataset.py publish
python3 tools/enron-full/prepare_full_dataset.py prepare --workers 8
results-local/tool-build/verify_full_tag enron_mail_20150507/full50wTest.staging enron_mail_20150507/maildir
python3 tools/enron-full/prepare_full_dataset.py publish
```

`publish` 是本地验证后将 staging 重命名为最终数据集，不是网络发布。
5w 的 C++ 校验器核对正文标签，Python 发布阶段重读正文核对 SHA 和大小；
全量 C++ 校验器从原邮件独立重提正文、核对 SHA/大小并验证标签。
这两种校验路径不要混为一谈。准备程序路径从仓库位置推导，无需固定盘符。

## 标签检索与分析

```bash
python3 tools/enron-5w/run_lookup_experiment.py
python3 tools/enron-full/run_full_lookup_experiment.py
python3 tools/enron-5w/analyze_similarity.py
```

先完成 5w，再运行全量：全量扩展比较读取当前仓库
`results-local/enron-5w/lookup-experiment/summary.csv`。
两个 runner 支持 `--repo`、`--dataset`、`--output`；默认分别写入
`results-local/enron-5w/lookup-experiment/` 与 `results-local/enron-full/lookup-experiment/`。
`--output` 必须为空。即使自定义输出，全量扩展比较仍需要上述默认位置的 5w 基线。
`--repo` 指定构建程序所在仓库；数据和输出有独立默认值，切换外部仓库时请一并传入。

数据库和查询副本写入运行用户主目录中的 `enron-5w-lookup-runs/` 或
`enron-full-lookup-runs/`，应保证主目录位于原生 Linux 文件系统；不清空 OS 页缓存。
日志和 CSV 保留在本地输出目录，失败时还应保留终端提示的 scratch 目录。
这些是标签检索实验，不执行完整上传协议或两机通信。
