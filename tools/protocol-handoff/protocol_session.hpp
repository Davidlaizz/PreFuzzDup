#pragma once

namespace {

// Include after main.cpp. Session state is separate from both reference stores.
struct Attempt {
  std::string run, uid, query_id, mode, original_id;
  int threshold, repeat;
  Bytes query_tag;
};

Bytes attempt_binding(const Attempt& a, const Record& r) {
  if (a.run.empty() || a.uid.empty() || a.query_id.empty() || a.original_id.empty() ||
      (a.mode != "nearest" && a.mode != "all") || a.threshold < 4 || a.threshold > 6 ||
      a.repeat < 0 || a.repeat > 2 || a.query_tag.size() != 32 || r.tag.size() != 32)
    fail("invalid protocol attempt");
  return hash_fields("PreFuzzDup/offline-attempt/v1", {bytes(a.run), bytes(a.uid), bytes(a.query_id),
    bytes(a.mode), bytes(a.original_id), bytes(std::to_string(a.threshold)),
    bytes(std::to_string(a.repeat)), a.query_tag, Server::record_hash(r), r.vk});
}

// Only this signature is exported. Q and the signing seed stay in client memory.
std::optional<Bytes> client_sign(const Attempt& a, const Record& r, std::span<const std::uint8_t> token,
                                 std::span<const std::uint8_t> body, const FuzzyExtractor& fe) {
  attempt_binding(a, r);
  if (token.size() != 32 || !equal_ct(make_tag(body, r.type), a.query_tag) ||
      hamming(a.query_tag, r.tag) > a.threshold) return std::nullopt;
  auto R = fe.rep(recovery_representation(body, r.type), r.helper);
  if (!R) return std::nullopt;
  const auto Q = hkdf_extract(Bytes(32, 0), *R);
  const auto kp = seed_keygen(proof_seed(Q, r));
  if (!equal_ct(kp.vk, r.vk)) return std::nullopt;
  return sign_ed(kp.seed, Server::challenge_message(a.uid, r, a.query_tag, token));
}

class ProtocolSession {
 public:
  explicit ProtocolSession(const fs::path& path, int ttl_seconds = 1728000) : db_(checked_path(path)), ttl_(ttl_seconds) {
    if (ttl_ <= 0 || ttl_ > 1728000) fail("invalid session TTL");
    // Refuse accidental use of either imported storage or the original index DB.
    Stmt tables(db_, "SELECT count(*) FROM sqlite_master WHERE name IN ('records','postings','protocol_records')");
    if (!tables.step_row() || tables.col_int(0)) fail("session database must be separate");
    db_.exec("CREATE TABLE IF NOT EXISTS protocol_challenges("
             "token BLOB PRIMARY KEY,binding BLOB NOT NULL,message BLOB NOT NULL,"
             "vk BLOB NOT NULL,expires INTEGER NOT NULL,used INTEGER NOT NULL DEFAULT 0)");
  }

  Bytes issue(const Attempt& a, const Record& r) {
    const auto binding = attempt_binding(a, r);
    if (r.vk.size() != 32 || hamming(a.query_tag, r.tag) > a.threshold) fail("ineligible candidate");
    const auto token = random_bytes(32);
    const auto message = Server::challenge_message(a.uid, r, a.query_tag, token);
    Stmt q(db_, "INSERT INTO protocol_challenges(token,binding,message,vk,expires) VALUES(?1,?2,?3,?4,unixepoch()+?5)");
    q.blob(1, token); q.blob(2, binding); q.blob(3, message); q.blob(4, r.vk); q.integer(5, ttl_); q.done();
    return token;
  }

  bool consume(const Attempt& a, const Record& r, std::span<const std::uint8_t> token,
               std::span<const std::uint8_t> signature) {
    const auto binding = attempt_binding(a, r);
    bool permitted = false;
    Bytes message, vk;
    db_.exec("BEGIN IMMEDIATE");
    try {
      Stmt q(db_, "SELECT binding,message,vk,expires,used FROM protocol_challenges WHERE token=?1");
      q.blob(1, token);
      if (q.step_row()) {
        permitted = equal_ct(binding, q.col_blob(0)) && q.col_int(3) >= std::time(nullptr) && q.col_int(4) == 0;
        message = q.col_blob(1); vk = q.col_blob(2);
        Stmt used(db_, "UPDATE protocol_challenges SET used=1 WHERE token=?1");
        used.blob(1, token); used.done();
      }
      db_.exec("COMMIT");
    } catch (...) { try { db_.exec("ROLLBACK"); } catch (...) {} throw; }
    return permitted && signature.size() == 64 && verify_ed(vk, message, signature);
  }

 private:
  static fs::path checked_path(const fs::path& path) {
    if (fs::is_symlink(path)) fail("session database cannot be a symlink");
    return path;
  }
  Db db_;
  int ttl_;
};

}  // namespace
