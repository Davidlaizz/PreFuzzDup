# FuzzyDedup 对比实验原型

本目录是可单独构建的 FuzzyDedup 源码包，保留 FuzzyMLE、标签切分优化和基于 1-out-of-2 OT 的概率型 FuzzyPoW，同时提供与当前公平测试一致的持久化标签检索程序。

## 内容

- `src/main.cpp`：FuzzyDedup 主流程，包括域分离标签、模糊密钥再现、FuzzyMLE 对称加密、DH 1-out-of-2 OT 与抽样式 P-FuzzyPoW。
- `src/prefuzzdup_core.cpp`：所需哈希、模糊提取、HKDF 等基础实现的本地副本；只为保证本源码包独立可构建，并不要求另行获取 PreFuzzDup。
- `src/lookup_benchmark.cpp`：持久化标签检索基准。使用时固定为 `--scheme fuzzydedup`，实现汉明重量缩减和三段标签切分的提前终止比较。

## 依赖与构建

需要 CMake 3.22+、C++20、OpenSSL 3、SQLite3、GMP 和 PBC 0.5.14。

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DOPENSSL_ROOT_DIR=/path/to/openssl \
  -DPBC_ROOT=/path/to/pbc-0.5.14 \
  -DGMP_ROOT=/path/to/gmp
cmake --build build -j
./build/fuzzydedup self-test
```

## 运行

```bash
# OT FuzzyPoW 微基准：重复 3 次、每次抽样 64 位
./build/fuzzydedup benchmark 3 64

# 持久化标签表上的查找实验
./build/fuzzydedup_lookup_benchmark \
  --scheme fuzzydedup --records reference.csv --queries queries.csv \
  --labels query_labels.csv --thresholds 4,5,6 --repeat 2 \
  --db fuzzydedup_labels.sqlite --out fuzzydedup_lookup.csv
```

查找实验将标签按汉明重量分块保存于 SQLite，并只读取与查询重量差不超过阈值的块。标签表不被程序整体加载到内存；SQLite 的页缓存约为 1 MiB，操作系统缓存不计为应用层的完整标签驻留。

## 边界

本程序用于学术比较，不是生产部署代码。OT 路径面向半诚实模型；主动恶意安全需要额外接入一致性证明或 malicious-secure OT。网络传输和通用云服务开销应按三种方案相同的口径处理。
