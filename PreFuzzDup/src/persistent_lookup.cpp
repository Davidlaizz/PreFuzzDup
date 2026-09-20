#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <sqlite3.h>
#include <openssl/evp.h>

#include "prefix_filter.hpp"

namespace pf {

struct Tag { std::vector<std::uint8_t> bytes; };
struct Item { std::string id; std::string type; Tag tag; };
struct Metrics { std::uint64_t filter_queries = 0, inverted_lookups = 0, posting_records_read = 0, full_tag_distance_computations = 0; };
struct QueryResult { std::vector<std::size_t> candidates; Metrics metrics; };
struct TypeParameters { std::uint32_t delta = 0; };

[[noreturn]] void fail(const std::string& message) { throw std::runtime_error(message); }
std::string trim(std::string value) {
  const auto first = value.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) return {};
  return value.substr(first, value.find_last_not_of(" \t\r\n") - first + 1);
}
std::vector<std::string> split(std::string_view text, char delimiter) {
  std::vector<std::string> result; std::size_t begin = 0;
  while (begin <= text.size()) { const auto end = text.find(delimiter, begin); result.push_back(trim(std::string(text.substr(begin, end == std::string_view::npos ? text.size() - begin : end - begin)))); if (end == std::string_view::npos) break; begin = end + 1; }
  return result;
}
int hex_value(char c) { if (c >= '0' && c <= '9') return c - '0'; if (c >= 'a' && c <= 'f') return c - 'a' + 10; if (c >= 'A' && c <= 'F') return c - 'A' + 10; return -1; }
Tag parse_hex_tag(const std::string& hex, std::size_t bits) {
  if (bits == 0 || bits % 8 != 0 || hex.size() != bits / 4) fail("标签长度与 --tag-bits 不一致。");
  Tag tag; tag.bytes.reserve(hex.size() / 2);
  for (std::size_t i = 0; i < hex.size(); i += 2) { const int hi = hex_value(hex[i]), lo = hex_value(hex[i + 1]); if (hi < 0 || lo < 0) fail("标签含有非十六进制字符。"); tag.bytes.push_back(static_cast<std::uint8_t>((hi << 4) | lo)); }
  return tag;
}
std::vector<Item> load_manifest(const std::string& path, std::size_t bits) {
  std::ifstream input(path); if (!input) fail("无法读取文件：" + path);
  std::vector<Item> items; std::set<std::string> ids; std::string line; std::size_t line_no = 0;
  while (std::getline(input, line)) { ++line_no; line = trim(line); if (line.empty() || line[0] == '#') continue; const auto fields = split(line, ','); if (fields.size() != 3) fail(path + ": 第 " + std::to_string(line_no) + " 行必须为 id,type,tag_hex。"); if (fields[0] == "id" && fields[1] == "type" && fields[2] == "tag_hex") continue; if (fields[0].empty() || fields[1].empty() || fields[2].empty() || !ids.insert(fields[0]).second) fail(path + ": 存在空字段或重复记录标识。"); items.push_back({fields[0], fields[1], parse_hex_tag(fields[2], bits)}); }
  if (items.empty()) fail(path + ": 未读取到记录。"); return items;
}
std::string manifest_digest(const std::string& path, std::size_t bits, const std::string& thresholds) {
  std::ifstream input(path, std::ios::binary); if (!input) fail("无法读取文件：" + path);
  EVP_MD_CTX* ctx = EVP_MD_CTX_new(); if (!ctx) fail("无法初始化索引摘要。");
  const std::string settings = "PreFuzzDup-index-v2|" + std::to_string(bits) + "|" + thresholds + "|";
  if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 || EVP_DigestUpdate(ctx, settings.data(), settings.size()) != 1) { EVP_MD_CTX_free(ctx); fail("索引摘要初始化失败。"); }
  std::array<char, 65536> buffer{};
  while (input) {
    input.read(buffer.data(), buffer.size()); const auto n = input.gcount();
    if (n > 0 && EVP_DigestUpdate(ctx, buffer.data(), static_cast<std::size_t>(n)) != 1) { EVP_MD_CTX_free(ctx); fail("索引摘要计算失败。"); }
  }
  if (!input.eof()) { EVP_MD_CTX_free(ctx); fail("无法完整读取索引输入文件。"); }
  unsigned char digest[EVP_MAX_MD_SIZE]; unsigned int digest_size = 0;
  if (EVP_DigestFinal_ex(ctx, digest, &digest_size) != 1) { EVP_MD_CTX_free(ctx); fail("索引摘要计算失败。"); }
  EVP_MD_CTX_free(ctx);
  constexpr char hex[] = "0123456789abcdef"; std::string out; out.reserve(digest_size * 2);
  for (unsigned int i = 0; i < digest_size; ++i) { out.push_back(hex[digest[i] >> 4]); out.push_back(hex[digest[i] & 15]); }
  return out;
}
std::uint32_t hamming_distance(const Tag& left, const Tag& right) { std::uint32_t result = 0; for (std::size_t i = 0; i < left.bytes.size(); ++i) result += std::popcount(static_cast<unsigned int>(left.bytes[i] ^ right.bytes[i])); return result; }
std::string bit_segment(const Tag& tag, std::size_t start, std::size_t count) {
  std::string result; result.reserve((count + 7) / 8 + 4); const auto length = static_cast<std::uint32_t>(count);
  for (int i = 0; i < 4; ++i) result.push_back(static_cast<char>((length >> (i * 8)) & 0xff));
  std::uint8_t out = 0;
  for (std::size_t i = 0; i < count; ++i) { const auto source = start + i; const bool bit = (tag.bytes[source / 8] >> (7 - source % 8)) & 1U; out = static_cast<std::uint8_t>((out << 1U) | bit); if (i % 8 == 7 || i + 1 == count) { out = static_cast<std::uint8_t>(out << ((8 - ((i + 1) % 8)) % 8)); result.push_back(static_cast<char>(out)); out = 0; } }
  return result;
}

using PrefixFilter = prefuzz::PrefixFilter;

class SqliteDb {
 public:
  explicit SqliteDb(const std::string& path) { if (sqlite3_open_v2(path.c_str(), &db_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) fail("无法打开持久化倒排索引：" + path); sqlite3_busy_timeout(db_, 10000); }
  ~SqliteDb() { if (lookup_) sqlite3_finalize(lookup_); if (tag_) sqlite3_finalize(tag_); if (db_) sqlite3_close(db_); }
  SqliteDb(const SqliteDb&) = delete;
  void exec(const char* sql) { char* error = nullptr; if (sqlite3_exec(db_, sql, nullptr, nullptr, &error) != SQLITE_OK) { const std::string message = error ? error : "SQLite 执行失败"; sqlite3_free(error); fail(message); } }
  sqlite3* get() { return db_; }
  sqlite3_stmt* statement() { return lookup_; }
  void prepare_lookup() {
    if (sqlite3_prepare_v2(db_, "SELECT record_id FROM postings WHERE type=?1 AND segment=?2 AND value=?3", -1, &lookup_, nullptr) != SQLITE_OK) fail("无法准备持久化倒排查询。");
    if (sqlite3_prepare_v2(db_, "SELECT tag FROM records WHERE record_id=?1", -1, &tag_, nullptr) != SQLITE_OK) fail("无法准备磁盘标签查询。");
  }
  Tag read_tag(std::size_t id, std::size_t bits) {
    sqlite3_bind_int64(tag_, 1, static_cast<sqlite3_int64>(id));
    const int code = sqlite3_step(tag_);
    if (code != SQLITE_ROW || sqlite3_column_bytes(tag_, 0) != static_cast<int>(bits / 8)) fail("持久化标签缺失或长度错误。");
    const auto* data = static_cast<const std::uint8_t*>(sqlite3_column_blob(tag_, 0));
    Tag value; value.bytes.assign(data, data + bits / 8);
    sqlite3_reset(tag_); sqlite3_clear_bindings(tag_);
    return value;
  }
 private:
  sqlite3* db_ = nullptr; sqlite3_stmt* lookup_ = nullptr; sqlite3_stmt* tag_ = nullptr;
};

class PersistentIndex {
 public:
  PersistentIndex(std::vector<Item> records, std::size_t bits, std::unordered_map<std::string, TypeParameters> params, TypeParameters defaults, double fpp, const std::string& db_path, const std::string& signature)
      : records_(std::move(records)), bits_(bits), params_(std::move(params)), defaults_(defaults), fpp_(fpp), db_(db_path) { build(signature); }
  QueryResult scan(const Item& query) const { QueryResult result; for (auto id : ids_for_type(query.type)) { ++result.metrics.full_tag_distance_computations; if (hamming_distance(query.tag, db_.read_tag(id, bits_)) <= params_for(query.type).delta) result.candidates.push_back(id); } sort(result.candidates); return result; }
  QueryResult exact(const Item& query) const { return indexed(query, false); }
  QueryResult prefuzz(const Item& query) const { return indexed(query, true); }
  std::size_t records() const { return records_.size(); }
  std::size_t filters_bytes() const { std::size_t total = 0; for (const auto& pair : filters_) total += pair.second.bytes(); return total; }
  bool reused_disk_index() const { return reused_disk_index_; }
 private:
  const TypeParameters& params_for(const std::string& type) const { const auto it = params_.find(type); return it == params_.end() ? defaults_ : it->second; }
  std::size_t segments(const std::string& type) const { return params_for(type).delta + 1U; }
  std::pair<std::size_t, std::size_t> boundary(const std::string& type, std::size_t segment) const { const auto m = segments(type); const auto start = bits_ * segment / m, end = bits_ * (segment + 1) / m; return {start, end - start}; }
  std::string value_for(const Item& item, std::size_t segment) const { const auto [start, length] = boundary(item.type, segment); return bit_segment(item.tag, start, length); }
  static std::string filter_name(const std::string& type, std::size_t segment) { return type + '\x1f' + std::to_string(segment); }
  const std::vector<std::size_t>& ids_for_type(const std::string& type) const { static const std::vector<std::size_t> none; const auto it = by_type_.find(type); return it == by_type_.end() ? none : it->second; }
  void build(const std::string& signature) {
    if (defaults_.delta >= bits_) fail("默认阈值必须小于标签位数。");
    for (const auto& [type, parameters] : params_) if (parameters.delta >= bits_) fail("类型 " + type + " 的阈值必须小于标签位数。");
    db_.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON; PRAGMA temp_store=FILE; PRAGMA cache_size=-1024;");
    db_.exec("CREATE TABLE IF NOT EXISTS index_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);");
    for (std::size_t id = 0; id < records_.size(); ++id) by_type_[records_[id].type].push_back(id);
    sqlite3_stmt* meta = nullptr;
    if (sqlite3_prepare_v2(db_.get(), "SELECT value FROM index_meta WHERE key='manifest_signature'", -1, &meta, nullptr) != SQLITE_OK) fail("无法读取索引版本。");
    reused_disk_index_ = sqlite3_step(meta) == SQLITE_ROW && signature == reinterpret_cast<const char*>(sqlite3_column_text(meta, 0));
    sqlite3_finalize(meta);
    if (reused_disk_index_) {
      sqlite3_stmt* count = nullptr;
      if (sqlite3_prepare_v2(db_.get(), "SELECT count(*) FROM records", -1, &count, nullptr) != SQLITE_OK) fail("持久化标签表缺失，请重新建库。");
      reused_disk_index_ = sqlite3_step(count) == SQLITE_ROW && sqlite3_column_int64(count, 0) == static_cast<sqlite3_int64>(records_.size());
      sqlite3_finalize(count);
      if (reused_disk_index_) {
        std::uint64_t expected = 0;
        for (const auto& [type, ids] : by_type_) expected += ids.size() * segments(type);
        if (sqlite3_prepare_v2(db_.get(), "SELECT count(*) FROM postings", -1, &count, nullptr) != SQLITE_OK) fail("持久化倒排表缺失，请重新建库。");
        reused_disk_index_ = sqlite3_step(count) == SQLITE_ROW && sqlite3_column_int64(count, 0) == static_cast<sqlite3_int64>(expected);
        sqlite3_finalize(count);
      }
    }
    if (!reused_disk_index_) rebuild_disk_index(signature);
    rebuild_filters();
    // Keep only record IDs/types for result ordering. Full tags live in SQLite.
    for (auto& record : records_) std::vector<std::uint8_t>().swap(record.tag.bytes);
    db_.prepare_lookup();
  }
  void rebuild_disk_index(const std::string& signature) {
    db_.exec("BEGIN IMMEDIATE;");
    sqlite3_stmt* record_insert = nullptr; sqlite3_stmt* posting_insert = nullptr;
    try {
      db_.exec("DROP TABLE IF EXISTS postings; DROP TABLE IF EXISTS records;");
      db_.exec("CREATE TABLE records(record_id INTEGER PRIMARY KEY, type TEXT NOT NULL, tag BLOB NOT NULL);"
               "CREATE TABLE postings(type TEXT NOT NULL, segment INTEGER NOT NULL, value BLOB NOT NULL, record_id INTEGER NOT NULL REFERENCES records(record_id), PRIMARY KEY(type,segment,value,record_id)) WITHOUT ROWID;");
      if (sqlite3_prepare_v2(db_.get(), "INSERT INTO records(record_id,type,tag) VALUES(?1,?2,?3)", -1, &record_insert, nullptr) != SQLITE_OK ||
          sqlite3_prepare_v2(db_.get(), "INSERT INTO postings(type,segment,value,record_id) VALUES(?1,?2,?3,?4)", -1, &posting_insert, nullptr) != SQLITE_OK) fail("无法准备持久化索引写入。");
      for (std::size_t id = 0; id < records_.size(); ++id) {
        const auto& record = records_[id];
        sqlite3_bind_int64(record_insert, 1, static_cast<sqlite3_int64>(id));
        sqlite3_bind_text(record_insert, 2, record.type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_blob(record_insert, 3, record.tag.bytes.data(), static_cast<int>(record.tag.bytes.size()), SQLITE_TRANSIENT);
        if (sqlite3_step(record_insert) != SQLITE_DONE) fail("无法写入磁盘标签表。");
        sqlite3_reset(record_insert); sqlite3_clear_bindings(record_insert);
        for (std::size_t j = 0; j < segments(record.type); ++j) {
          const auto value = value_for(record, j);
          sqlite3_bind_text(posting_insert, 1, record.type.c_str(), -1, SQLITE_TRANSIENT);
          sqlite3_bind_int64(posting_insert, 2, static_cast<sqlite3_int64>(j));
          sqlite3_bind_blob(posting_insert, 3, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT);
          sqlite3_bind_int64(posting_insert, 4, static_cast<sqlite3_int64>(id));
          if (sqlite3_step(posting_insert) != SQLITE_DONE) fail("无法写入持久化倒排项。");
          sqlite3_reset(posting_insert); sqlite3_clear_bindings(posting_insert);
        }
      }
      sqlite3_finalize(record_insert); record_insert = nullptr;
      sqlite3_finalize(posting_insert); posting_insert = nullptr;
      sqlite3_stmt* mark = nullptr;
      if (sqlite3_prepare_v2(db_.get(), "INSERT INTO index_meta(key,value) VALUES('manifest_signature',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value", -1, &mark, nullptr) != SQLITE_OK) fail("无法标记索引版本。");
      sqlite3_bind_text(mark, 1, signature.c_str(), -1, SQLITE_TRANSIENT);
      const int status = sqlite3_step(mark); sqlite3_finalize(mark);
      if (status != SQLITE_DONE) fail("无法保存索引版本。");
      db_.exec("COMMIT;");
    } catch (...) { if (record_insert) sqlite3_finalize(record_insert); if (posting_insert) sqlite3_finalize(posting_insert); try { db_.exec("ROLLBACK;"); } catch (...) {} throw; }
  }
  void rebuild_filters() {
    filters_.clear();
    for (const auto& entry : by_type_) for (std::size_t j = 0; j < segments(entry.first); ++j)
      filters_.emplace(filter_name(entry.first, j), PrefixFilter(entry.second.size(), fpp_));
    sqlite3_stmt* values = nullptr;
    if (sqlite3_prepare_v2(db_.get(), "SELECT DISTINCT type,segment,value FROM postings", -1, &values, nullptr) != SQLITE_OK) fail("无法从磁盘索引重建 Prefix Filter。");
    int code = SQLITE_OK;
    while ((code = sqlite3_step(values)) == SQLITE_ROW) {
      const std::string type(reinterpret_cast<const char*>(sqlite3_column_text(values, 0)));
      const auto segment = static_cast<std::size_t>(sqlite3_column_int64(values, 1));
      const auto* data = static_cast<const char*>(sqlite3_column_blob(values, 2));
      const auto length = static_cast<std::size_t>(sqlite3_column_bytes(values, 2));
      const auto it = filters_.find(filter_name(type, segment));
      if (it == filters_.end()) { sqlite3_finalize(values); fail("磁盘索引分段与当前阈值不一致。"); }
      it->second.insert(std::string_view(data, length));
    }
    sqlite3_finalize(values);
    if (code != SQLITE_DONE) fail("Prefix Filter 重建失败。");
  }
  QueryResult indexed(const Item& query, bool with_filter) const {
    QueryResult result; std::unordered_set<std::size_t> seen; std::vector<std::size_t> candidate_ids; sqlite3_stmt* lookup = db_.statement();
    for (std::size_t j = 0; j < segments(query.type); ++j) {
      const auto value = value_for(query, j);
      if (with_filter) { ++result.metrics.filter_queries; const auto filter = filters_.find(filter_name(query.type, j)); if (filter == filters_.end() || !filter->second.contains(value)) continue; }
      ++result.metrics.inverted_lookups;
      sqlite3_bind_text(lookup, 1, query.type.c_str(), -1, SQLITE_TRANSIENT); sqlite3_bind_int64(lookup, 2, static_cast<sqlite3_int64>(j)); sqlite3_bind_blob(lookup, 3, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT);
      int code = SQLITE_OK; while ((code = sqlite3_step(lookup)) == SQLITE_ROW) { const auto id = static_cast<std::size_t>(sqlite3_column_int64(lookup, 0)); if (id >= records_.size()) fail("持久化倒排记录标识越界。"); if (seen.insert(id).second) candidate_ids.push_back(id); ++result.metrics.posting_records_read; }
      if (code != SQLITE_DONE) fail("持久化倒排查询失败。"); sqlite3_reset(lookup); sqlite3_clear_bindings(lookup);
    }
    const auto delta = params_for(query.type).delta;
    for (const auto id : candidate_ids) { ++result.metrics.full_tag_distance_computations; if (hamming_distance(query.tag, db_.read_tag(id, bits_)) <= delta) result.candidates.push_back(id); }
    sort(result.candidates); return result;
  }
  void sort(std::vector<std::size_t>& ids) const { std::sort(ids.begin(), ids.end(), [this](auto left, auto right) { return records_[left].id < records_[right].id; }); }
  std::vector<Item> records_; std::size_t bits_; std::unordered_map<std::string, TypeParameters> params_; TypeParameters defaults_; double fpp_; std::unordered_map<std::string, std::vector<std::size_t>> by_type_; std::unordered_map<std::string, PrefixFilter> filters_; mutable SqliteDb db_; bool reused_disk_index_ = false;
};

enum class Strategy { scan, exact, prefuzz };
std::string name(Strategy strategy) { return strategy == Strategy::scan ? "scan" : strategy == Strategy::exact ? "exact" : "prefuzz"; }
std::vector<Strategy> parse_strategies(const std::string& text) { std::vector<Strategy> result; for (const auto& value : split(text, ',')) { if (value == "scan") result.push_back(Strategy::scan); else if (value == "exact") result.push_back(Strategy::exact); else if (value == "prefuzz") result.push_back(Strategy::prefuzz); else fail("不支持的策略：" + value); } return result; }
std::unordered_map<std::string, TypeParameters> parse_thresholds(const std::string& text, TypeParameters& defaults) { std::unordered_map<std::string, TypeParameters> result; bool got_default = false; for (const auto& entry : split(text, ',')) { const auto position = entry.find('='); if (position == std::string::npos) fail("--threshold 格式错误。"); const auto key = trim(entry.substr(0, position)), value = trim(entry.substr(position + 1)); std::uint32_t delta = 0; const auto converted = std::from_chars(value.data(), value.data() + value.size(), delta); if (converted.ec != std::errc{} || converted.ptr != value.data() + value.size()) fail("阈值必须为非负整数。"); if (key == "default") { defaults = {delta}; got_default = true; } else result[key] = {delta}; } if (!got_default) fail("--threshold 必须包含 default=值。"); return result; }

struct Options { std::string records, queries, db, output, threshold, strategies = "scan,exact,prefuzz"; std::size_t bits = 0, repeat = 1; double fpp = .01; bool verify = false; };
void usage() { std::cout << "用法：prefuzzdup_persistent_retrieval --records records.csv --queries queries.csv --db index.sqlite --tag-bits 256 --threshold default=6 [--fpp 0.01] [--strategies scan,exact,prefuzz] [--repeat 3] [--verify-equivalence] [--out result.csv]\n"; }
Options parse_options(int argc, char** argv) { Options options; for (int i = 1; i < argc; ++i) { const std::string key = argv[i]; if (key == "--help" || key == "-h") { usage(); std::exit(0); } if (key == "--verify-equivalence") { options.verify = true; continue; } if (i + 1 >= argc) fail("参数缺少值：" + key); const std::string value = argv[++i]; if (key == "--records") options.records = value; else if (key == "--queries") options.queries = value; else if (key == "--db") options.db = value; else if (key == "--out") options.output = value; else if (key == "--threshold") options.threshold = value; else if (key == "--strategies") options.strategies = value; else if (key == "--tag-bits") { const auto c = std::from_chars(value.data(), value.data() + value.size(), options.bits); if (c.ec != std::errc{}) fail("--tag-bits 必须为整数。"); } else if (key == "--repeat") { const auto c = std::from_chars(value.data(), value.data() + value.size(), options.repeat); if (c.ec != std::errc{} || options.repeat == 0) fail("--repeat 必须为正整数。"); } else if (key == "--fpp") { char* end = nullptr; options.fpp = std::strtod(value.c_str(), &end); if (end == value.c_str() || *end) fail("--fpp 必须为小数。"); } else fail("未知参数：" + key); } if (options.records.empty() || options.queries.empty() || options.db.empty() || options.threshold.empty() || options.bits == 0) { usage(); fail("缺少必要参数。"); } return options; }
QueryResult run(const PersistentIndex& index, const Item& query, Strategy strategy) { return strategy == Strategy::scan ? index.scan(query) : strategy == Strategy::exact ? index.exact(query) : index.prefuzz(query); }
double p95(std::vector<double> values) { std::sort(values.begin(), values.end()); return values[static_cast<std::size_t>(std::ceil(values.size() * .95)) - 1]; }

int main(int argc, char** argv) {
  try {
    const auto options = parse_options(argc, argv); TypeParameters defaults; const auto parameters = parse_thresholds(options.threshold, defaults); auto records = load_manifest(options.records, options.bits); const auto queries = load_manifest(options.queries, options.bits); const auto strategies = parse_strategies(options.strategies);
    const auto signature = manifest_digest(options.records, options.bits, options.threshold);
    const auto start = std::chrono::steady_clock::now(); PersistentIndex index(std::move(records), options.bits, parameters, defaults, options.fpp, options.db, signature); const auto build_us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count();
    if (options.verify) for (const auto& query : queries) { const auto expected = index.scan(query).candidates; if (index.exact(query).candidates != expected || index.prefuzz(query).candidates != expected) fail("持久化检索与全量扫描候选集合不一致：" + query.id); }
    if (options.verify) std::cout << "equivalence_check=passed (not included in latency measurement)\n";
    std::ofstream file; std::ostream* out = &std::cout; if (!options.output.empty()) { file.open(options.output); if (!file) fail("无法写入输出文件。"); out = &file; }
    *out << "strategy,query_id,type,repeat,latency_us,candidate_count,filter_queries,inverted_lookups,posting_records_read,full_tag_distance_computations\n";
    std::cout << "records=" << index.records() << ", tag_bits=" << options.bits << ", index_prepare_us=" << build_us << ", disk_index_reused=" << (index.reused_disk_index() ? 1 : 0) << ", filter_bytes_estimate=" << index.filters_bytes() << ", sqlite_cache_kib=1024\n";
    for (const auto strategy : strategies) { std::vector<double> latencies; Metrics total; std::uint64_t candidates = 0; for (std::size_t repeat = 0; repeat < options.repeat; ++repeat) for (const auto& query : queries) { const auto now = std::chrono::steady_clock::now(); const auto result = run(index, query, strategy); const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - now).count(); latencies.push_back(elapsed); total.filter_queries += result.metrics.filter_queries; total.inverted_lookups += result.metrics.inverted_lookups; total.posting_records_read += result.metrics.posting_records_read; total.full_tag_distance_computations += result.metrics.full_tag_distance_computations; candidates += result.candidates.size(); *out << name(strategy) << ',' << query.id << ',' << query.type << ',' << repeat << ',' << elapsed << ',' << result.candidates.size() << ',' << result.metrics.filter_queries << ',' << result.metrics.inverted_lookups << ',' << result.metrics.posting_records_read << ',' << result.metrics.full_tag_distance_computations << '\n'; } const auto n = static_cast<double>(latencies.size()); std::cout << name(strategy) << ": queries=" << latencies.size() << ", mean_us=" << std::fixed << std::setprecision(2) << std::accumulate(latencies.begin(), latencies.end(), 0.0) / n << ", p95_us=" << p95(latencies) << ", mean_candidates=" << candidates / n << ", mean_distance_computations=" << total.full_tag_distance_computations / n << ", mean_filter_queries=" << total.filter_queries / n << ", mean_inverted_lookups=" << total.inverted_lookups / n << ", mean_posting_records_read=" << total.posting_records_read / n << '\n'; }
    return 0;
  } catch (const std::exception& error) { std::cerr << "错误：" << error.what() << '\n'; return 1; }
}

}  // namespace pf

int main(int argc, char** argv) { return pf::main(argc, argv); }
