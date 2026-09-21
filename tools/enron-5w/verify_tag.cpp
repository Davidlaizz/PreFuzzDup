// Temporary verifier. It includes the existing PreFuzzDup translation unit and
// calls its make_tag()/simhash_text() implementation directly; no algorithm is
// reimplemented here.
#define main prefuzzdup_original_main
#include "main.cpp"
#undef main

#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {

std::string strip_eol(std::string s) {
  while (!s.empty() && (s.back() == '\r' || s.back() == '\n')) s.pop_back();
  return s;
}

std::vector<std::string> split_line(const std::string& line) {
  std::vector<std::string> out;
  std::istringstream stream(line);
  std::string item;
  while (std::getline(stream, item, ',')) out.push_back(item);
  return out;
}

int hex_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  fail("invalid lowercase hex character: " + std::string(1, c));
}

Bytes parse_hex(const std::string& s) {
  if (s.size() % 2) fail("hex string has odd length");
  Bytes out;
  out.reserve(s.size() / 2);
  for (std::size_t i = 0; i + 1 < s.size(); i += 2)
    out.push_back(static_cast<std::uint8_t>((hex_value(s[i]) << 4) | hex_value(s[i + 1])));
  return out;
}

std::ifstream open_csv(const fs::path& path) {
  std::ifstream stream(path);
  if (!stream) fail("cannot open " + path.string());
  return stream;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc != 2) {
      std::cerr << "usage: verify_tag <staging-dir>\n";
      return 2;
    }
    const fs::path dir = argv[1];

    std::vector<std::string> tag_ids, tag_values, tag_types;
    {
      std::ifstream stream = open_csv(dir / "tags.csv");
      std::string line;
      std::getline(stream, line);
      if (strip_eol(line) != "id,type,tag_hex") fail("tags.csv header mismatch");
      while (std::getline(stream, line)) {
        const auto fields = split_line(strip_eol(line));
        if (fields.size() != 3) fail("tags.csv row must have 3 fields");
        tag_ids.push_back(fields[0]);
        tag_types.push_back(fields[1]);
        tag_values.push_back(fields[2]);
      }
    }

    std::unordered_map<std::string, std::string> body_paths;
    std::size_t manifest_rows = 0;
    {
      std::ifstream stream = open_csv(dir / "manifest.csv");
      std::string line;
      std::getline(stream, line);
      if (strip_eol(line) !=
          "id,mailbox,source_path,body_path,body_sha256,body_size_bytes,normalized_word_count")
        fail("manifest.csv header mismatch");
      while (std::getline(stream, line)) {
        const auto fields = split_line(strip_eol(line));
        if (fields.size() != 7) fail("manifest.csv row must have 7 fields");
        if (!body_paths.emplace(fields[0], fields[3]).second)
          fail("duplicate manifest id: " + fields[0]);
        ++manifest_rows;
      }
    }
    if (manifest_rows != tag_ids.size()) fail("tags.csv and manifest.csv row counts differ");

    std::size_t edge_checked = 0, edge_matched = 0;
    {
      std::ifstream stream = open_csv(dir / "edge_cases.csv");
      std::string line;
      std::getline(stream, line);
      if (strip_eol(line) != "name,input_hex,expected_hex") fail("edge_cases.csv header mismatch");
      while (std::getline(stream, line)) {
        const auto fields = split_line(strip_eol(line));
        if (fields.size() != 3) fail("edge_cases.csv row must have 3 fields");
        const Bytes input = parse_hex(fields[1]);
        const std::string actual = hex(make_tag(input, "text"));
        ++edge_checked;
        if (actual == fields[2]) ++edge_matched;
        else std::cerr << "edge mismatch " << fields[0] << ": cpp=" << actual << " expected=" << fields[2] << "\n";
      }
    }

    std::size_t bodies_checked = 0, bodies_matched = 0, mismatches = 0;
    std::vector<std::string> mismatch_samples;
    std::unordered_set<std::string> seen_ids;
    for (std::size_t i = 0; i < tag_ids.size(); ++i) {
      if (!seen_ids.insert(tag_ids[i]).second) fail("duplicate tags.csv id: " + tag_ids[i]);
      const auto found = body_paths.find(tag_ids[i]);
      if (found == body_paths.end()) fail("id missing from manifest: " + tag_ids[i]);
      if (tag_types[i] != "text") fail("non-text type for " + tag_ids[i]);
      const Bytes body = read_file(dir / found->second);
      const std::string actual = hex(make_tag(body, "text"));
      ++bodies_checked;
      if (actual == tag_values[i]) {
        ++bodies_matched;
      } else {
        ++mismatches;
        if (mismatch_samples.size() < 20)
          mismatch_samples.push_back(tag_ids[i] + " cpp=" + actual + " python=" + tag_values[i]);
      }
      if ((i + 1) % 10000 == 0) std::cerr << "  verified " << (i + 1) << "/" << tag_ids.size() << "\n";
    }

    std::ofstream report(dir / "cpp_verification.json");
    if (!report) fail("cannot write cpp_verification.json");
    report << "{\n"
           << "  \"verifier\": \"tools/enron-5w/verify_tag.cpp\",\n"
           << "  \"verifies_by_including\": \"PreFuzzDup/src/main.cpp make_tag/simhash_text\",\n"
           << "  \"tag_rows\": " << tag_ids.size() << ",\n"
           << "  \"manifest_rows\": " << manifest_rows << ",\n"
           << "  \"edge_cases_checked\": " << edge_checked << ",\n"
           << "  \"edge_cases_matched\": " << edge_matched << ",\n"
           << "  \"bodies_checked\": " << bodies_checked << ",\n"
           << "  \"bodies_matched\": " << bodies_matched << ",\n"
           << "  \"mismatch_count\": " << mismatches << ",\n"
           << "  \"mismatches\": [";
    for (std::size_t i = 0; i < mismatch_samples.size(); ++i)
      report << (i ? ", " : "") << "\"" << mismatch_samples[i] << "\"";
    report << "]\n}\n";

    std::cout << "edge_cases " << edge_matched << "/" << edge_checked
              << ", bodies " << bodies_matched << "/" << bodies_checked
              << ", mismatches " << mismatches << "\n";
    return mismatches == 0 && edge_matched == edge_checked ? 0 : 1;
  } catch (const std::exception& error) {
    std::cerr << "ERROR: " << error.what() << "\n";
    return 1;
  }
}
