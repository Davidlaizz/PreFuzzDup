#define PREFUZZDUP_AS_LIBRARY
#include "main.cpp"
#include "protocol_store.hpp"
#include "protocol_session.hpp"

namespace {
Bytes wire_hex(const std::string& text) {
  if (text.size() % 2 || text.find_first_not_of("0123456789abcdef") != std::string::npos) fail("invalid hex");
  Bytes value;
  for (std::size_t i = 0; i < text.size(); i += 2) value.push_back(std::stoul(text.substr(i, 2), nullptr, 16));
  return value;
}
std::vector<std::vector<std::string>> wire_rows(const fs::path& path, std::size_t count) {
  std::ifstream in(path);
  if (!in) fail("cannot read canonical TSV");
  std::vector<std::vector<std::string>> rows;
  for (std::string line; std::getline(in, line);) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    std::vector<std::string> fields;
    std::size_t begin = 0, end;
    while ((end = line.find('\t', begin)) != std::string::npos) {
      fields.push_back(line.substr(begin, end - begin)); begin = end + 1;
    }
    fields.push_back(line.substr(begin));
    if (fields.size() != count) fail("invalid TSV field count");
    rows.push_back(std::move(fields));
  }
  if (!in.eof()) fail("TSV read failed");
  return rows;
}
}

int main(int argc, char** argv) {
  try {
    if (argc != 7) fail("usage: server_session_cli issue|verify STORE SESSION_DB RECORDS_TSV TASKS_TSV NEW_OUTPUT_CSV");
    const std::string mode(argv[1]);
    if (mode != "issue" && mode != "verify") fail("unknown server mode");
    if (fs::exists(argv[6])) fail("output already exists");
    ProtocolStore store(argv[2]);
    ProtocolSession session(argv[3]);
    std::map<std::string, Bytes> tags;
    for (const auto& row : wire_rows(argv[4], 15)) {
      if (!tags.emplace(row[0], wire_hex(row[3])).second) fail("duplicate public record");
    }
    const auto rows = wire_rows(argv[5], mode == "issue" ? 9 : 14);
    std::ofstream out(argv[6]);
    if (!out) fail("cannot create output");
    out << std::setprecision(17) << "run,uid,query_id,mode,record_id,threshold,repeat,query_tag,token,status,"
        << (mode == "issue" ? "challenge_us" : "verify_us") << '\n';
    for (const auto& row : rows) {
      const Attempt a{row[0], row[1], row[2], row[3], row[4], std::stoi(row[5]), std::stoi(row[6]), wire_hex(row[7])};
      const auto record = store.get_record(a.original_id, tags.at(a.original_id));
      if (!record) fail("missing imported record");
      auto token = wire_hex(row[8]);
      std::string status;
      const auto start = std::chrono::steady_clock::now();
      if (mode == "issue") {
        if (!token.empty()) fail("issue request must not supply token");
        token = session.issue(a, *record); status = "issued";
      } else {
        if (token.size() != 32) fail("invalid challenge token");
        if (row[9] != "signed" && row[9] != "recovery_failed" && row[9] != "verification_key_mismatch")
          fail("invalid client status");
        const auto signature = wire_hex(row[10]);
        if ((row[9] == "signed" && signature.size() != 64) || (row[9] != "signed" && !signature.empty()))
          fail("status/signature mismatch");
        const bool verified = session.consume(a, *record, token, signature);
        status = row[9] == "signed" ? (verified ? "verified" : "rejected") : "client_failed";
      }
      const auto us = std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - start).count();
      for (int i = 0; i < 8; ++i) out << row[i] << ',';
      out << hex(token) << ',' << status << ',' << us << '\n';
    }
    out.close(); if (!out) fail("output write failed");
  } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
