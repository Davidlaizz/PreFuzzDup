// Retrieval-only baselines for the Chapter 6 Enron experiment.
// SimLESS follows its paper: compare every stored tag and retain the minimum.
// FuzzyDedup follows Algorithm 3/4: Hamming-weight reduction plus r=3 tag cutting.

#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <sqlite3.h>

namespace benchmark {

using Tag = std::array<std::uint64_t, 4>;

struct Item {
  std::string id;
  Tag tag{};
  std::uint16_t weight{};
};

struct Query {
  std::string id;
  Tag tag{};
  std::string group;
};

struct Result {
  bool matched{};
  std::uint16_t best_distance{};
  std::uint64_t records_examined{};
  std::uint64_t bits_compared{};
  double latency_us{};
};

[[noreturn]] void fail(const std::string& message) { throw std::runtime_error(message); }

std::vector<std::string> split(std::string_view line) {
  std::vector<std::string> result;
  std::size_t begin = 0;
  while (begin <= line.size()) {
    const auto end = line.find(',', begin);
    std::string field(line.substr(begin, end == std::string_view::npos ? line.size() - begin : end - begin));
    while (!field.empty() && (field.back() == '\r' || field.back() == '\n')) field.pop_back();
    result.push_back(std::move(field));
    if (end == std::string_view::npos) break;
    begin = end + 1;
  }
  return result;
}

int hex_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

Tag parse_tag(const std::string& hex) {
  if (hex.size() != 64) fail("only 256-bit (64 hex character) tags are accepted");
  Tag tag{};
  for (std::size_t word = 0; word < tag.size(); ++word) {
    std::uint64_t value = 0;
    for (std::size_t j = 0; j < 16; ++j) {
      const int digit = hex_value(hex[word * 16 + j]);
      if (digit < 0) fail("non-hexadecimal tag character");
      value = (value << 4U) | static_cast<std::uint64_t>(digit);
    }
    tag[word] = value;
  }
  return tag;
}

std::uint16_t weight(const Tag& tag) {
  std::uint16_t total = 0;
  for (const auto value : tag) total += static_cast<std::uint16_t>(std::popcount(value));
  return total;
}

std::array<std::uint8_t, 32> tag_bytes(const Tag& tag) {
  std::array<std::uint8_t, 32> bytes{};
  for (std::size_t word = 0; word < tag.size(); ++word) {
    for (std::size_t byte = 0; byte < 8; ++byte) {
      bytes[word * 8 + byte] = static_cast<std::uint8_t>(tag[word] >> (56 - byte * 8));
    }
  }
  return bytes;
}

Tag tag_from_bytes(const std::uint8_t* bytes) {
  Tag tag{};
  for (std::size_t word = 0; word < tag.size(); ++word) {
    for (std::size_t byte = 0; byte < 8; ++byte) tag[word] = (tag[word] << 8U) | bytes[word * 8 + byte];
  }
  return tag;
}

std::uint16_t full_distance(const Tag& left, const Tag& right) {
  std::uint16_t total = 0;
  for (std::size_t i = 0; i < left.size(); ++i) total += static_cast<std::uint16_t>(std::popcount(left[i] ^ right[i]));
  return total;
}

// Algorithm 4 uses r-cut.  Here r=3 and distance checks happen after each cut.
// The return value is threshold+1 whenever the record can be rejected early.
std::pair<std::uint16_t, std::uint16_t> three_cut_distance(const Tag& left, const Tag& right,
                                                            std::uint16_t threshold) {
  constexpr std::array<std::pair<std::size_t, std::size_t>, 3> cuts{{{0, 1}, {1, 2}, {2, 4}}};
  std::uint16_t distance = 0;
  std::uint16_t compared_bits = 0;
  for (const auto& [begin, end] : cuts) {
    for (std::size_t i = begin; i < end; ++i) {
      distance += static_cast<std::uint16_t>(std::popcount(left[i] ^ right[i]));
      compared_bits += 64;
    }
    if (distance > threshold) return {static_cast<std::uint16_t>(threshold + 1), compared_bits};
  }
  return {distance, compared_bits};
}

std::vector<Item> load_records(const std::string& path) {
  std::ifstream input(path);
  if (!input) fail("cannot read records: " + path);
  std::vector<Item> records;
  std::string line;
  while (std::getline(input, line)) {
    if (line.empty()) continue;
    auto fields = split(line);
    if (fields.size() != 3) fail("invalid record CSV row");
    if (fields[0] == "id") continue;
    auto tag = parse_tag(fields[2]);
    records.push_back({std::move(fields[0]), tag, weight(tag)});
  }
  if (records.empty()) fail("no records loaded");
  return records;
}

std::unordered_map<std::string, std::string> load_groups(const std::string& path) {
  std::ifstream input(path);
  if (!input) fail("cannot read labels: " + path);
  std::unordered_map<std::string, std::string> groups;
  std::string line;
  while (std::getline(input, line)) {
    if (line.empty()) continue;
    auto fields = split(line);
    if (fields.size() != 4) fail("invalid label CSV row");
    if (fields[0] == "query_id") continue;
    groups.emplace(std::move(fields[0]), std::move(fields[1]));
  }
  return groups;
}

std::vector<Query> load_queries(const std::string& path, const std::string& labels_path) {
  const auto groups = load_groups(labels_path);
  std::ifstream input(path);
  if (!input) fail("cannot read queries: " + path);
  std::vector<Query> queries;
  std::string line;
  while (std::getline(input, line)) {
    if (line.empty()) continue;
    auto fields = split(line);
    if (fields.size() != 3) fail("invalid query CSV row");
    if (fields[0] == "id") continue;
    const auto it = groups.find(fields[0]);
    if (it == groups.end()) fail("query has no group label: " + fields[0]);
    queries.push_back({std::move(fields[0]), parse_tag(fields[2]), it->second});
  }
  if (queries.empty()) fail("no queries loaded");
  return queries;
}

class SimLESSLookup {
 public:
  explicit SimLESSLookup(const std::vector<Item>& records) : records_(records) {}

  Result query(const Query& query, std::uint16_t threshold) const {
    const auto start = std::chrono::steady_clock::now();
    std::uint16_t minimum = 257;
    for (const auto& record : records_) minimum = std::min(minimum, full_distance(query.tag, record.tag));
    const auto stop = std::chrono::steady_clock::now();
    return {minimum <= threshold, minimum, records_.size(), records_.size() * 256ULL,
            std::chrono::duration<double, std::micro>(stop - start).count()};
  }
 private:
  const std::vector<Item>& records_;
};

class FuzzyDedupLookup {
 public:
  explicit FuzzyDedupLookup(std::vector<Item> records) : records_(std::move(records)) {
    std::sort(records_.begin(), records_.end(), [](const Item& a, const Item& b) {
      return a.weight < b.weight;
    });
  }

  Result query(const Query& query, std::uint16_t threshold) const {
    const auto start = std::chrono::steady_clock::now();
    const int qweight = weight(query.tag);
    const auto lower = std::lower_bound(records_.begin(), records_.end(), std::max(0, qweight - static_cast<int>(threshold)),
                                        [](const Item& item, int value) { return item.weight < value; });
    const auto upper = std::upper_bound(records_.begin(), records_.end(), std::min(256, qweight + static_cast<int>(threshold)),
                                        [](int value, const Item& item) { return value < item.weight; });
    std::uint64_t examined = 0, bits = 0;
    std::uint16_t minimum = 257;
    // The paper writes disHam < t.  Supplying user threshold theta is therefore
    // implemented as paper t=theta+1, which makes the accepted radius <= theta.
    for (auto it = lower; it != upper; ++it) {
      ++examined;
      const auto [distance, compared] = three_cut_distance(query.tag, it->tag, threshold);
      bits += compared;
      minimum = std::min(minimum, distance);
      if (distance <= threshold) {
        const auto stop = std::chrono::steady_clock::now();
        return {true, distance, examined, bits, std::chrono::duration<double, std::micro>(stop - start).count()};
      }
    }
    const auto stop = std::chrono::steady_clock::now();
    return {false, minimum, examined, bits, std::chrono::duration<double, std::micro>(stop - start).count()};
  }
 private:
  std::vector<Item> records_;
};

class PersistentLabelTable {
 public:
  PersistentLabelTable(const std::string& path, const std::vector<Item>& records) {
    if (sqlite3_open_v2(path.c_str(), &db_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
      fail("cannot open SQLite label table: " + path);
    }
    exec("PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; PRAGMA temp_store=FILE; PRAGMA cache_size=-1024;");
    exec("DROP TABLE IF EXISTS label_blocks;");
    exec("CREATE TABLE label_blocks(kind TEXT NOT NULL, weight INTEGER NOT NULL, tags BLOB NOT NULL, PRIMARY KEY(kind,weight)) WITHOUT ROWID;");
    sqlite3_stmt* insert = nullptr;
    if (sqlite3_prepare_v2(db_, "INSERT INTO label_blocks(kind,weight,tags) VALUES(?1,?2,?3)", -1, &insert, nullptr) != SQLITE_OK) fail("cannot prepare label insertion");
    exec("BEGIN IMMEDIATE;");
    try {
      std::vector<std::uint8_t> all_tags;
      all_tags.reserve(records.size() * 32);
      std::array<std::vector<std::uint8_t>, 257> weight_blocks;
      for (const auto& record : records) {
        const auto bytes = tag_bytes(record.tag);
        all_tags.insert(all_tags.end(), bytes.begin(), bytes.end());
        auto& block = weight_blocks[record.weight];
        block.insert(block.end(), bytes.begin(), bytes.end());
      }
      auto insert_block = [&](const char* kind, int weight, const std::vector<std::uint8_t>& bytes) {
        sqlite3_bind_text(insert, 1, kind, -1, SQLITE_STATIC);
        sqlite3_bind_int(insert, 2, weight);
        sqlite3_bind_blob(insert, 3, bytes.data(), static_cast<int>(bytes.size()), SQLITE_TRANSIENT);
        if (sqlite3_step(insert) != SQLITE_DONE) fail("cannot insert label block");
        sqlite3_reset(insert);
        sqlite3_clear_bindings(insert);
      };
      insert_block("all", 0, all_tags);
      for (int current_weight = 0; current_weight <= 256; ++current_weight) {
        if (!weight_blocks[current_weight].empty()) insert_block("weight", current_weight, weight_blocks[current_weight]);
      }
      exec("COMMIT;");
    } catch (...) {
      sqlite3_finalize(insert);
      try { exec("ROLLBACK;"); } catch (...) {}
      throw;
    }
    sqlite3_finalize(insert);
    if (sqlite3_prepare_v2(db_, "SELECT tags FROM label_blocks WHERE kind='all' AND weight=0", -1, &scan_, nullptr) != SQLITE_OK) fail("cannot prepare label scan");
    if (sqlite3_prepare_v2(db_, "SELECT tags FROM label_blocks WHERE kind='weight' AND weight BETWEEN ?1 AND ?2 ORDER BY weight", -1, &weight_query_, nullptr) != SQLITE_OK) fail("cannot prepare Hamming-weight query");
  }

  ~PersistentLabelTable() {
    if (scan_) sqlite3_finalize(scan_);
    if (weight_query_) sqlite3_finalize(weight_query_);
    if (db_) sqlite3_close(db_);
  }
  PersistentLabelTable(const PersistentLabelTable&) = delete;

  sqlite3_stmt* scan_statement() const { return scan_; }
  sqlite3_stmt* weight_statement() const { return weight_query_; }
  static void reset(sqlite3_stmt* statement) {
    sqlite3_reset(statement);
    sqlite3_clear_bindings(statement);
  }

 private:
  void exec(const char* sql) {
    char* error = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &error) != SQLITE_OK) {
      const std::string message = error == nullptr ? "SQLite failure" : error;
      sqlite3_free(error);
      fail(message);
    }
  }
  sqlite3* db_{};
  sqlite3_stmt* scan_{};
  sqlite3_stmt* weight_query_{};
};

class PersistentSimLESSLookup {
 public:
  PersistentSimLESSLookup(const std::string& path, const std::vector<Item>& records) : labels_(path, records) {}
  Result query(const Query& query, std::uint16_t threshold) const {
    const auto start = std::chrono::steady_clock::now();
    auto* statement = labels_.scan_statement();
    std::uint16_t minimum = 257;
    std::uint64_t examined = 0;
    int status = SQLITE_OK;
    while ((status = sqlite3_step(statement)) == SQLITE_ROW) {
      const auto* bytes = static_cast<const std::uint8_t*>(sqlite3_column_blob(statement, 0));
      const int size = sqlite3_column_bytes(statement, 0);
      if (bytes == nullptr || size % 32 != 0) fail("invalid SimLESS tag block");
      for (int offset = 0; offset < size; offset += 32) {
        minimum = std::min(minimum, full_distance(query.tag, tag_from_bytes(bytes + offset)));
        ++examined;
      }
    }
    PersistentLabelTable::reset(statement);
    if (status != SQLITE_DONE) fail("persistent SimLESS scan failed");
    const auto stop = std::chrono::steady_clock::now();
    return {minimum <= threshold, minimum, examined, examined * 256ULL,
            std::chrono::duration<double, std::micro>(stop - start).count()};
  }
 private:
  PersistentLabelTable labels_;
};

class PersistentFuzzyDedupLookup {
 public:
  PersistentFuzzyDedupLookup(const std::string& path, const std::vector<Item>& records) : labels_(path, records) {}
  Result query(const Query& query, std::uint16_t threshold) const {
    const auto start = std::chrono::steady_clock::now();
    const auto query_weight = static_cast<int>(weight(query.tag));
    auto* statement = labels_.weight_statement();
    sqlite3_bind_int(statement, 1, std::max(0, query_weight - static_cast<int>(threshold)));
    sqlite3_bind_int(statement, 2, std::min(256, query_weight + static_cast<int>(threshold)));
    std::uint64_t examined = 0, bits = 0;
    std::uint16_t minimum = 257;
    int status = SQLITE_OK;
    while ((status = sqlite3_step(statement)) == SQLITE_ROW) {
      const auto* bytes = static_cast<const std::uint8_t*>(sqlite3_column_blob(statement, 0));
      const int size = sqlite3_column_bytes(statement, 0);
      if (bytes == nullptr || size % 32 != 0) fail("invalid FuzzyDedup tag block");
      for (int offset = 0; offset < size; offset += 32) {
        const auto tag = tag_from_bytes(bytes + offset);
        ++examined;
        const auto [distance, compared] = three_cut_distance(query.tag, tag, threshold);
        bits += compared;
        minimum = std::min(minimum, distance);
        if (distance <= threshold) {
          PersistentLabelTable::reset(statement);
          const auto stop = std::chrono::steady_clock::now();
          return {true, distance, examined, bits, std::chrono::duration<double, std::micro>(stop - start).count()};
        }
      }
    }
    PersistentLabelTable::reset(statement);
    if (status != SQLITE_DONE) fail("persistent FuzzyDedup query failed");
    const auto stop = std::chrono::steady_clock::now();
    return {false, minimum, examined, bits, std::chrono::duration<double, std::micro>(stop - start).count()};
  }
 private:
  PersistentLabelTable labels_;
};

struct Options {
  std::string records, queries, labels, output, scheme, database;
  std::vector<int> thresholds;
  int repeat = 2;
};

std::vector<int> parse_threshold_list(const std::string& text) {
  std::vector<int> values;
  std::size_t start = 0;
  while (start <= text.size()) {
    const auto end = text.find(',', start);
    const auto part = text.substr(start, end == std::string::npos ? std::string::npos : end - start);
    if (part.empty()) fail("empty threshold value");
    const int value = std::stoi(part);
    if (value < 0 || value > 256) fail("threshold must be in [0,256]");
    values.push_back(value);
    if (end == std::string::npos) break;
    start = end + 1;
  }
  return values;
}

Options parse_options(int argc, char** argv) {
  Options options;
  for (int i = 1; i < argc; ++i) {
    const std::string key = argv[i];
    if (key == "--help") {
      std::cout << "comparative_lookup --scheme simless|fuzzydedup --records reference.csv --queries queries.csv --labels query_labels.csv --thresholds 4,5,6 --repeat 2 --db labels.sqlite --out details.csv\n";
      std::exit(0);
    }
    if (i + 1 >= argc) fail("missing value for " + key);
    const std::string value = argv[++i];
    if (key == "--scheme") options.scheme = value;
    else if (key == "--records") options.records = value;
    else if (key == "--queries") options.queries = value;
    else if (key == "--labels") options.labels = value;
    else if (key == "--threshold" || key == "--thresholds") options.thresholds = parse_threshold_list(value);
    else if (key == "--repeat") options.repeat = std::stoi(value);
    else if (key == "--out") options.output = value;
    else if (key == "--db") options.database = value;
    else fail("unknown option: " + key);
  }
  if (options.records.empty() || options.queries.empty() || options.labels.empty() || options.output.empty() ||
      (options.scheme != "simless" && options.scheme != "fuzzydedup") || options.database.empty() || options.thresholds.empty() || options.repeat <= 0) {
    fail("missing or invalid required options");
  }
  return options;
}

template <typename Lookup>
void execute(const Options& options, const Lookup& lookup, const std::vector<Query>& queries) {
  std::ofstream output(options.output);
  if (!output) fail("cannot write output: " + options.output);
  output << "scheme,threshold,repeat,query_id,group,latency_us,matched,best_distance,records_examined,bits_compared\n";
  std::map<std::pair<int, std::string>, std::pair<double, std::uint64_t>> summary;
  for (int repeat = 0; repeat < options.repeat; ++repeat) {
    for (std::size_t query_index = 0; query_index < queries.size(); ++query_index) {
      const auto& query = queries[query_index];
      // SimLESS always scans the whole label table to obtain the minimum
      // distance.  Threshold changes only the final decision, not this scan.
      // Measure that scan once and reuse the same measured lookup for each
      // threshold so thermal drift cannot masquerade as a threshold effect.
      std::optional<Result> shared_simless_result;
      if (options.scheme == "simless" && options.thresholds.size() > 1) {
        shared_simless_result = lookup.query(query, 0);
      }
      // Rotate the threshold order so a threshold is not tied to one thermal state.
      for (std::size_t offset = 0; offset < options.thresholds.size(); ++offset) {
        const int threshold = options.thresholds[(query_index + static_cast<std::size_t>(repeat) + offset) % options.thresholds.size()];
        auto result = shared_simless_result ? *shared_simless_result
                                            : lookup.query(query, static_cast<std::uint16_t>(threshold));
        result.matched = result.best_distance <= threshold;
        output << options.scheme << ',' << threshold << ',' << repeat << ',' << query.id << ',' << query.group << ','
               << std::fixed << std::setprecision(3) << result.latency_us << ',' << (result.matched ? 1 : 0) << ','
               << result.best_distance << ',' << result.records_examined << ',' << result.bits_compared << '\n';
        auto& [sum, count] = summary[{threshold, query.group}];
        sum += result.latency_us;
        ++count;
      }
    }
  }
  for (const auto& [key, value] : summary) {
    std::cout << options.scheme << " threshold=" << key.first << " group=" << key.second
              << " mean_us=" << value.first / static_cast<double>(value.second) << " samples=" << value.second << '\n';
  }
}

}  // namespace benchmark

int main(int argc, char** argv) {
  try {
    const auto options = benchmark::parse_options(argc, argv);
    const auto records = benchmark::load_records(options.records);
    const auto queries = benchmark::load_queries(options.queries, options.labels);
    if (options.scheme == "simless") benchmark::execute(options, benchmark::PersistentSimLESSLookup(options.database, records), queries);
    else benchmark::execute(options, benchmark::PersistentFuzzyDedupLookup(options.database, records), queries);
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "error: " << error.what() << '\n';
    return 1;
  }
}
