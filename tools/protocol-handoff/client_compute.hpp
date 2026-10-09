#pragma once
#include <set>

namespace {
using ClientClock = std::chrono::steady_clock;
double elapsed_us(ClientClock::time_point start) {
  return std::chrono::duration<double, std::micro>(ClientClock::now() - start).count();
}

std::set<std::string> five_word_shingles(std::span<const std::uint8_t> body) {
  const auto normalized = normalize_text(body);
  std::istringstream in(normalized);
  std::vector<std::string> words;
  for (std::string word; in >> word;) words.push_back(word);
  if (words.size() < 5) return {normalized};
  std::set<std::string> shingles;
  for (std::size_t i = 0; i + 5 <= words.size(); ++i) {
    std::string shingle = words[i];
    for (int j = 1; j < 5; ++j) shingle += " " + words[i + j];
    shingles.insert(shingle);
  }
  return shingles;
}

double five_word_jaccard(std::span<const std::uint8_t> left, std::span<const std::uint8_t> right) {
  const auto a = five_word_shingles(left), b = five_word_shingles(right);
  std::size_t intersection = 0;
  for (const auto& shingle : a) intersection += b.count(shingle);
  return static_cast<double>(intersection) / (a.size() + b.size() - intersection);
}

struct SignResult {
  std::string status;
  Bytes signature;
  double tag_check_us = 0, key_recovery_us = 0, sign_us = 0;
};

SignResult client_sign_timed(const Record& r, const std::string& uid, std::span<const std::uint8_t> body,
                             std::span<const std::uint8_t> tag, std::span<const std::uint8_t> token,
                             const FuzzyExtractor& fe) {
  SignResult result;
  auto start = ClientClock::now();
  const auto actual_tag = make_tag(body, r.type);
  result.tag_check_us = elapsed_us(start);
  if (!equal_ct(tag, actual_tag)) { result.status = "query_tag_mismatch"; return result; }
  if (token.size() != 32) fail("challenge token must be 32 bytes");
  start = ClientClock::now();
  const auto R = fe.rep(recovery_representation(body, r.type), r.helper);
  if (!R) { result.key_recovery_us = elapsed_us(start); result.status = "recovery_failed"; return result; }
  const auto Q = hkdf_extract(Bytes(32, 0), *R);
  const auto kp = seed_keygen(proof_seed(Q, r));
  result.key_recovery_us = elapsed_us(start);
  if (!equal_ct(kp.vk, r.vk)) { result.status = "verification_key_mismatch"; return result; }
  start = ClientClock::now();
  result.signature = sign_ed(kp.seed, Server::challenge_message(uid, r, tag, token));
  result.sign_us = elapsed_us(start);
  result.status = "signed";
  return result;
}

struct RecoverResult {
  std::string status;
  double tag_check_us = 0, key_recovery_us = 0, decrypt_us = 0, integrity_us = 0, confirm_us = 0;
  double jaccard = -1;
};

RecoverResult client_recover(const Record& r, std::span<const std::uint8_t> body,
                            std::span<const std::uint8_t> query_tag, std::span<const std::uint8_t> cipher,
                            int threshold, const FuzzyExtractor& fe) {
  if (threshold < 4 || threshold > 6) fail("invalid recovery threshold");
  RecoverResult result;
  auto start = ClientClock::now();
  const auto actual_tag = make_tag(body, r.type);
  result.tag_check_us = elapsed_us(start);
  if (!equal_ct(query_tag, actual_tag)) { result.status = "query_tag_mismatch"; return result; }
  start = ClientClock::now();
  const auto R = fe.rep(recovery_representation(body, r.type), r.helper);
  if (!R) { result.key_recovery_us = elapsed_us(start); result.status = "recovery_failed"; return result; }
  const auto Q = hkdf_extract(Bytes(32, 0), *R);
  result.key_recovery_us = elapsed_us(start);
  start = ClientClock::now();
  const auto ad = Server::aad(r);
  const auto key = aead_decrypt(wrap_key(Q, r), r.nwrap, r.wrap, r.wtag, ad);
  const auto plain = key ? aead_decrypt(*key, r.nfile, cipher, r.ctag, ad) : std::nullopt;
  result.decrypt_us = elapsed_us(start);
  if (!plain) { result.status = "decrypt_failed"; return result; }
  start = ClientClock::now();
  const auto recovered_tag = make_tag(*plain, r.type);
  const auto Rr = fe.rep(recovery_representation(*plain, r.type), r.helper);
  const bool valid = equal_ct(recovered_tag, r.tag) && hamming(query_tag, recovered_tag) <= threshold &&
                     Rr && equal_ct(hkdf_extract(Bytes(32, 0), *Rr), Q);
  result.integrity_us = elapsed_us(start);
  if (!valid) { result.status = "integrity_failed"; return result; }
  start = ClientClock::now();
  result.jaccard = five_word_jaccard(body, *plain);
  result.confirm_us = elapsed_us(start);
  result.status = result.jaccard >= 0.5 ? "accepted" : "similarity_rejected";
  return result;
}
}  // namespace
