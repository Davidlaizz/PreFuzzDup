# 加密数据模糊去重实验：PreFuzzDup、SimLESS 与 FuzzyDedup

本仓库包含三套 C++20 科研实验原型，用于研究相似文件的加密存储、模糊所有权证明与候选检索。FuzzyPoW 在这里指模糊所有权证明，不是工作量证明。

各项目可以独立构建。PreFuzzDup 提供本地上传、代表文件存储和用户引用绑定；两个对比项目提供密码学自测、微基准和独立的标签检索实验。

## 方案与目录

| 项目 | 密码学流程 | 候选检索 |
| --- | --- | --- |
| [PreFuzzDup](PreFuzzDup/README.md) | 模糊提取、HKDF、AES-GCM 密钥信封、Ed25519 一次性挑战 | Prefix Filter、分段倒排索引和完整汉明距离校验 |
| [SimLESS](SimLESS/README.md) | 属性访问控制（CP-ABE）、双线性对 FuzzyPoW | 持久化标签全表比较 |
| [FuzzyDedup](FuzzyDedup/README.md) | 模糊密钥再现、不经意传输（OT）和抽样 FuzzyPoW | 汉明重量筛选、三段标签比较与提前终止 |

每个项目包含 `src/`、`CMakeLists.txt` 和使用说明。`PreFuzzDup/examples/` 提供小型 CSV 标签示例。两个对比项目中的 `prefuzzdup_core.cpp` 是保证独立构建所需的本地副本。

## 依赖与环境

- 公共依赖：CMake 3.22+、支持 C++20 的 GCC/Clang、OpenSSL 3 和 SQLite3 开发包。
- SimLESS、FuzzyDedup：额外需要 GMP 和 PBC 0.5.14。
- PreFuzzDup 图片适配：可选 OpenCV 的 `core`、`imgproc`、`imgcodecs` 组件。

以下命令适用于 Linux 或 WSL，从仓库根目录执行。现有编译选项面向 GCC/Clang，未验证原生 Windows/MSVC 构建。

## 快速开始

先构建 PreFuzzDup 并运行内置协议自测：

```bash
cmake -S PreFuzzDup -B PreFuzzDup/build -DCMAKE_BUILD_TYPE=Release
cmake --build PreFuzzDup/build -j
./PreFuzzDup/build/prefuzzdup self-test
```

如果 CMake 找不到 OpenSSL，在配置命令中追加 `-DOPENSSL_ROOT_DIR=/实际安装路径`。图片支持需追加 `-DPREFUZZDUP_ENABLE_MEDIA=ON`；本包未启用视频适配器。

运行随附的 16 位标签示例，对比全表扫描、直接倒排检索和带过滤器的倒排检索：

```bash
./PreFuzzDup/build/prefuzzdup_persistent_lookup \
  --records PreFuzzDup/examples/records.csv \
  --queries PreFuzzDup/examples/queries.csv \
  --db PreFuzzDup/build/example.sqlite \
  --tag-bits 16 --threshold default=1 \
  --strategies scan,exact,prefuzz --repeat 3 --verify-equivalence
```

`--verify-equivalence` 检查三种检索策略的结果是否一致。小型示例用于检查流程，不代表真实数据集上的性能。

## 对比实验

安装 PBC 和 GMP 后，参照各项目 README 分别配置、构建；非标准安装位置通过 `-DPBC_ROOT=...`、`-DGMP_ROOT=...` 指定。构建后可从仓库根目录执行：

```bash
./SimLESS/build/simless self-test
./SimLESS/build/simless benchmark 10
./FuzzyDedup/build/fuzzydedup self-test
./FuzzyDedup/build/fuzzydedup benchmark 3 64
```

对比检索程序使用 256 位标签，需自行准备记录、查询及查询类别文件，不能直接使用上述 16 位示例。具体格式和参数见各项目说明。仓库不包含 Enron 原始数据及完整实验输入，现有内容不足以独立复现全部论文结果。

检索基准不包含文件加密、所有权证明和密文写入开销。比较性能时，应记录数据规模、阈值、重复次数、编译配置和硬件环境，并统一三种方案的测量范围。

## 实现边界

- 这是本地实验原型，未提供完整网络服务、身份管理或生产级安全保障。
- PreFuzzDup 成功复用时恢复已有代表文件，不保存相似版本的差异，不保证逐字节恢复每个上传版本。
- Prefix Filter 的备用表使用精确内存字典，未复现论文中的 SIMD 压缩结构及其内存、吞吐量指标。
- SimLESS 的 Type-A 配对参数用于实验；FuzzyDedup 的 OT 路径面向半诚实模型。具体边界见子项目 README。

## 贡献与文件管理

贡献约定见 [AGENTS.md](AGENTS.md)。构建产物、运行数据库、密文和系统元数据由 `.gitignore` 排除；本地实验输出请放入 `results-local/`。示例 CSV 和构建配置应保留在版本控制中。

## 许可证与引用

当前源码包未附许可证，也未提供可核实的版权所有者声明。正式许可证尚待权利人确认；公开仓库本身不等于授予开源使用、修改或再分发许可。第三方依赖仍受各自许可证约束。

关联论文的正式题名、作者、年份及 DOI/链接尚未提供，因此暂不生成 `CITATION.cff` 或猜测性参考文献。发布前需补齐项目作者、相关方案的论文引用，以及适用的代码来源和版权声明。
