#define PREFUZZDUP_AS_LIBRARY
#include "main.cpp"
#include "client_compute.hpp"
#include "protocol_session.hpp"

namespace {
Bytes decode(const std::string& text) {
  if (text.size() % 2 || text.find_first_not_of("0123456789abcdef") != std::string::npos) fail("invalid hex");
  Bytes value;
  for (std::size_t i = 0; i < text.size(); i += 2) value.push_back(std::stoul(text.substr(i, 2), nullptr, 16));
  return value;
}
void identifier(const std::string& text) {
  if (text.empty() || text.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != std::string::npos)
    fail("invalid identifier");
}
std::vector<std::vector<std::string>> tsv(const fs::path& path, std::size_t count) {
  std::ifstream in(path);
  if (!in) fail("cannot read TSV");
  std::vector<std::vector<std::string>> rows;
  for (std::string line; std::getline(in, line);) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    std::vector<std::string> fields;
    std::size_t begin = 0, end;
    while ((end = line.find('\t', begin)) != std::string::npos) {
      fields.push_back(line.substr(begin, end - begin)); begin = end + 1;
    }
    fields.push_back(line.substr(begin));
    if (fields.size() != count) fail("invalid canonical TSV field count");
    rows.push_back(std::move(fields));
  }
  if (!in.eof()) fail("TSV read failed");
  return rows;
}
struct Body { Bytes plain, tag; };
std::map<std::string, Body> bodies(const fs::path& path) {
  std::map<std::string, Body> out;
  for (const auto& row : tsv(path, 4)) {
    identifier(row[0]);
    Body body{decode(row[3]), decode(row[2])};
    if (hex(sha256(body.plain)) != row[1] || body.tag.size() != 32 || !out.emplace(row[0], std::move(body)).second)
      fail("body digest/tag/ID mismatch");
  }
  return out;
}
struct PublicRecord { Record record; std::string digest; std::uint64_t size; };
std::map<std::string, PublicRecord> records(const fs::path& path) {
  std::map<std::string, PublicRecord> out;
  for (const auto& row : tsv(path, 15)) {
    identifier(row[0]);
    Record r{row[1], row[2], row[11], decode(row[3]), decode(row[4]), decode(row[5]), decode(row[6]),
             decode(row[7]), decode(row[8]), decode(row[9]), decode(row[10])};
    if (r.rid.size() != 32 || decode(r.rid).size() != 16 || r.type != "text" ||
        r.tag.size() != 32 || r.helper.size() != kHelperBytes || r.vk.size() != 32 ||
        r.nfile.size() != 12 || r.nwrap.size() != 12 || r.ctag.size() != 16 ||
        r.wrap.size() != 32 || r.wtag.size() != 16 || r.path != "blobs/" + r.rid + ".bin" ||
        decode(row[13]).size() != 32) fail("malformed public record");
    if (!out.emplace(row[0], PublicRecord{r, row[13], std::stoull(row[12])}).second) fail("duplicate reference ID");
  }
  return out;
}
std::ofstream output_file(const fs::path& path) {
  if (fs::exists(path)) fail("output exists");
  std::ofstream out(path);
  if (!out) fail("cannot create output");
  out << std::setprecision(17);
  return out;
}
void finish(std::ofstream& out) { out.close(); if (!out) fail("output write failed"); }
}

#ifndef PREFUZZDUP_CLIENT_WORKER_AS_LIBRARY
int main(int argc, char** argv) {
  try {
    if (argc < 4) fail("usage: client_crypto tag BODIES OUT | sign BODIES RECORDS TASKS OUT | recover BODIES RECORDS TASKS ARTIFACTS OUT");
    const std::string mode = argv[1];
    const auto local = bodies(argv[2]);
    if (mode == "tag" && argc == 4) {
      auto out = output_file(argv[3]); out << "query_id,repeat,tag_hex,tag_us\n";
      for (const auto& [id, body] : local) for (int repeat = 0; repeat < 3; ++repeat) {
        const auto start = ClientClock::now(); const auto tag = make_tag(body.plain, "text");
        const auto us = elapsed_us(start);
        if (!equal_ct(tag, body.tag)) fail("C++ body/tag mismatch: " + id);
        out << id << ',' << repeat << ',' << hex(tag) << ',' << us << '\n';
      }
      finish(out); return 0;
    }
    if (!((mode == "sign" && argc == 6) || (mode == "recover" && argc == 7))) fail("invalid client command");
    const auto refs = records(argv[3]);
    const auto tasks = tsv(argv[4], 9);
    auto out = output_file(argv[argc - 1]);
    out << "run,uid,query_id,mode,record_id,threshold,repeat,query_tag,token,status,";
    if (mode == "sign") out << "signature,tag_check_us,key_recovery_us,sign_us\n";
    else out << "jaccard,tag_check_us,key_recovery_us,decrypt_us,integrity_us,confirm_us\n";
    FuzzyExtractor fe;
    std::unordered_set<std::string> tokens;
    for (const auto& row : tasks) {
      for (int i : {0, 1, 2, 4}) identifier(row[i]);
      Attempt a{row[0], row[1], row[2], row[3], row[4], std::stoi(row[5]), std::stoi(row[6]), decode(row[7])};
      const auto token = decode(row[8]);
      if (token.size() != 32 || !tokens.insert(row[8]).second) fail("invalid/duplicate token");
      const auto& body = local.at(a.query_id);
      const auto& ref = refs.at(a.original_id);
      const auto& r = ref.record;
      attempt_binding(a, r);
      if (!equal_ct(a.query_tag, body.tag) || hamming(a.query_tag, r.tag) > a.threshold) fail("ineligible candidate");
      for (const auto& field : row) out << field << ',';
      if (mode == "sign") {
        const auto result = client_sign_timed(r, a.uid, body.plain, a.query_tag, token, fe);
        out << result.status << ',' << hex(result.signature) << ',' << result.tag_check_us << ','
            << result.key_recovery_us << ',' << result.sign_us << '\n';
      } else {
        const auto root = fs::canonical(argv[5]);
        const auto path = fs::canonical(root / r.path);
        if (path != root / r.path) fail("noncanonical cipher path");
        const auto cipher = read_file(path);
        if (cipher.size() != ref.size || hex(sha256(cipher)) != ref.digest) fail("cipher transfer integrity failed");
        const auto result = client_recover(r, body.plain, a.query_tag, cipher, a.threshold, fe);
        out << result.status << ',' << (result.jaccard < 0 ? "" : std::to_string(result.jaccard)) << ','
            << result.tag_check_us << ',' << result.key_recovery_us << ',' << result.decrypt_us << ','
            << result.integrity_us << ',' << result.confirm_us << '\n';
      }
    }
    finish(out);
  } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
#endif
