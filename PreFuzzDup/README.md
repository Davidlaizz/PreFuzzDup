# PreFuzzDup 实验原型

本目录为独立的 PreFuzzDup 源码包，对应论文的端到端流程和候选检索实验。它不依赖同级的 SimLESS 或 FuzzyDedup 目录。

## 内容

- `src/main.cpp`：端到端原型，包含标签生成、模糊提取、HKDF、AES-256-GCM 密钥信封、Ed25519 新鲜挑战验证、SQLite 代表记录与引用绑定。
- `src/prefix_filter.hpp`：分桶、最大指纹转移与备用表组成的两级 Prefix Filter；备用表采用内存精确字典，未采用原论文的 SIMD 压缩实现。
- `src/persistent_lookup.cpp`：第六章候选检索基准；Prefix Filter 位于内存，分段倒排项和完整标签位于 SQLite。
- `examples/`：16 位小型检索示例，仅用于检查命令流程。

## 依赖与构建

需要 CMake 3.22+、C++20 编译器、OpenSSL 3 开发包和 SQLite3 开发包。

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DOPENSSL_ROOT_DIR=/path/to/openssl
cmake --build build -j
./build/prefuzzdup self-test
```

若测试图像标签，构建时增加 `-DPREFUZZDUP_ENABLE_MEDIA=ON`；此项需要 OpenCV（core、imgproc、imgcodecs）。视频适配器不在本包中启用。

## 端到端运行

```bash
./build/prefuzzdup setup \
  --db /data/prefuzzdup/server.sqlite \
  --blob-dir /data/prefuzzdup/blobs \
  --capacity 1000000 --fpp 0.01 --threshold text=6,image=8

./build/prefuzzdup upload \
  --db /data/prefuzzdup/server.sqlite \
  --blob-dir /data/prefuzzdup/blobs \
  --uid user-a --type text --file /data/input.txt
```

端到端服务器同样使用内存 Prefix Filter 和 SQLite 分段倒排索引；代表记录及完整标签也保存在 SQLite。启动时从磁盘记录重建过滤器。已有记录时不可直接改变分段距离阈值；达到配置容量时，过滤器在新记录可见前扩容并重建。

## 候选检索基准

记录与查询 CSV 均为 `id,type,tag_hex`，标签使用十六进制表示。下例使用示例数据：

```bash
./build/prefuzzdup_persistent_lookup \
  --records examples/records.csv --queries examples/queries.csv \
  --db index.sqlite --tag-bits 16 --threshold default=1 \
  --strategies scan,exact,prefuzz --repeat 3 --verify-equivalence
```

首次运行将完整标签和分段倒排项写入 SQLite。再次运行时，若记录文件、标签长度及阈值未变化，程序复用磁盘索引；Prefix Filter 每次由持久化倒排项重建并常驻内存。查询时仅在过滤器返回“可能存在”后访问对应倒排项，完整标签从 SQLite 读取并进行汉明距离校验。`index_prepare_us` 包含建库或重建过滤器的时间，不计入逐条查询时延。候选检索测试不包含文件加密、FuzzyPoW 和密文写入开销。

过滤器实现遵循 Prefix Filter 的分桶、前缀不变量和备用表查询流程，备用表使用精确内存字典。因此该原型不复现原论文的 SIMD pocket dictionary 内存占用与吞吐量数据。若 CSV 或阈值改变，程序自动重建磁盘索引，避免沿用旧索引产生漏检。

## 边界

本项目是论文复现实验原型，不是经独立安全审计的生产系统。生产部署仍需补充身份服务、TLS、密钥托管、速率限制、故障恢复和审计。
