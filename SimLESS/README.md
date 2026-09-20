# SimLESS 对比实验原型

本目录是可单独构建的 SimLESS 源码包，保留论文中的属性访问控制、双线性对密钥封装和 FuzzyPoW，用于与 PreFuzzDup 的密码学开销及检索开销比较。

## 内容

- `src/main.cpp`：SimLESS 主流程，包括 Type-A 双线性对、合取访问策略的 CP-ABE 封装与恢复、模糊秘密再现、双线性对 FuzzyPoW 和 AES-256-GCM。
- `src/prefuzzdup_core.cpp`：主流程所需的哈希、模糊提取、AEAD 等基础实现的本地副本；该副本随本包分发，因此本目录不依赖其他方案源码。
- `src/lookup_benchmark.cpp`：持久化标签表上的检索基准。使用时固定为 `--scheme simless`，其检索逻辑为逐标签全表比较。

## 依赖与构建

需要 CMake 3.22+、C++20、OpenSSL 3、SQLite3、GMP 和 PBC 0.5.14。

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DOPENSSL_ROOT_DIR=/path/to/openssl \
  -DPBC_ROOT=/path/to/pbc-0.5.14 \
  -DGMP_ROOT=/path/to/gmp
cmake --build build -j
./build/simless self-test
```

## 运行

```bash
# 密码学主流程
./build/simless benchmark 10

# 持久化标签表上的查找实验
./build/simless_lookup_benchmark \
  --scheme simless --records reference.csv --queries queries.csv \
  --labels query_labels.csv --thresholds 4,5,6 --repeat 2 \
  --db simless_labels.sqlite --out simless_lookup.csv
```

后三个输入文件为当前 Enron 实验中使用的 `id,type,tag_hex` 记录、查询和查询类别文件；标签固定为 256 位。所有标签存入 SQLite，SQLite 页缓存限制为约 1 MiB；完整标签表不会被程序主动预加载至内存。

## 边界

Type-A 配对参数用于复现实验结构，不能视为生产级参数。该原型不包含网络传输、TLS、账户管理和恶意安全强化；这些公共系统开销应在三种方案中统一加入或统一排除。
