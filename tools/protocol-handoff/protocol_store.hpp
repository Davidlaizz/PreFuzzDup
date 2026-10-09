#pragma once

// Include after the original PreFuzzDup core. No search index or session state
// is created here: this adapter reads the separately imported public records.
class ProtocolStore {
 public:
  explicit ProtocolStore(const fs::path& root) : root_(fs::canonical(root)) {
    if (sqlite3_open_v2((root_ / "protocol.sqlite").c_str(), &db_, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
      if (db_) sqlite3_close(db_);
      fail("cannot open imported protocol store read-only");
    }
  }
  ~ProtocolStore() { sqlite3_close(db_); }
  ProtocolStore(const ProtocolStore&) = delete;
  ProtocolStore& operator=(const ProtocolStore&) = delete;

  std::optional<Record> get_record(const std::string& original_id, std::span<const std::uint8_t> expected_tag) {
    Query q(db_, original_id);
    if (!q.found) return std::nullopt;
    Record r{q.text(0), q.text(1), q.text(10), q.blob(2), q.blob(3), q.blob(4),
             q.blob(5), q.blob(6), q.blob(7), q.blob(8), q.blob(9)};
    if (r.type != "text" || r.tag.size() != 32 || !equal_ct(r.tag, expected_tag) ||
        r.helper.size() != kHelperBytes || r.vk.size() != 32 || r.nfile.size() != 12 ||
        r.nwrap.size() != 12 || r.ctag.size() != 16 || r.wrap.size() != 32 || r.wtag.size() != 16)
      fail("malformed protocol record or index/protocol tag mismatch");
    if (r.rid.size() != 32 || r.rid.find_first_not_of("0123456789abcdef") != std::string::npos ||
        r.path != "blobs/" + r.rid + ".bin") fail("noncanonical ciphertext path");
    return r;
  }

  Bytes read_ciphertext(const std::string& original_id, const Record& record) {
    const auto stored = get_record(original_id, record.tag);
    if (!stored || stored->rid != record.rid || stored->path != record.path)
      fail("ciphertext record mapping mismatch");
    const auto path = fs::canonical(root_ / stored->path);
    if (path != root_ / stored->path) fail("ciphertext symlink outside canonical path");
    auto ciphertext = read_file(path);
    Query q(db_, original_id);
    if (!q.found || q.size() < 0 || static_cast<std::uint64_t>(q.size()) != ciphertext.size() ||
        hex(sha256(ciphertext)) != q.text(12)) fail("ciphertext size/hash mismatch");
    return ciphertext;
  }

 private:
  struct Query {
    sqlite3_stmt* stmt = nullptr;
    bool found = false;
    Query(sqlite3* db, const std::string& id) {
      const char* sql = "SELECT rid,type,tag,helper,vk,nfile,nwrap,ctag,wrap,wtag,"
                        "cipher_path,cipher_bytes,cipher_sha256 FROM protocol_records WHERE record_id=?1";
      if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
        fail("invalid imported protocol schema");
      if (sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        sqlite3_finalize(stmt); fail("protocol ID bind failed");
      }
      const auto status = sqlite3_step(stmt);
      if (status != SQLITE_ROW && status != SQLITE_DONE) {
        sqlite3_finalize(stmt); fail("protocol record read failed");
      }
      found = status == SQLITE_ROW;
    }
    ~Query() { sqlite3_finalize(stmt); }
    Query(const Query&) = delete;
    Query& operator=(const Query&) = delete;
    std::string text(int col) const {
      const auto* p = sqlite3_column_text(stmt, col);
      return p ? reinterpret_cast<const char*>(p) : "";
    }
    Bytes blob(int col) const {
      const auto* p = static_cast<const std::uint8_t*>(sqlite3_column_blob(stmt, col));
      return p ? Bytes(p, p + sqlite3_column_bytes(stmt, col)) : Bytes{};
    }
    std::int64_t size() const { return sqlite3_column_int64(stmt, 11); }
  };
  fs::path root_;
  sqlite3* db_ = nullptr;
};
