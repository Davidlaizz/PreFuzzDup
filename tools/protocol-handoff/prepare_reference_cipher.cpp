#define PREFUZZDUP_AS_LIBRARY
#include "main.cpp"

Bytes decode_hex(const std::string& text) {
  if (text.size() % 2) fail("odd hex length");
  Bytes value;
  auto digit = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    fail("invalid hex");
  };
  for (std::size_t i = 0; i < text.size(); i += 2)
    value.push_back((digit(text[i]) << 4) | digit(text[i + 1]));
  return value;
}

int main(int argc, char** argv) {
  try {
    if (argc != 3) fail("usage: prepare_reference_cipher INPUT_TSV NEW_OUTPUT_DIR");
    const fs::path dest = argv[2];
    if (fs::exists(dest)) fail("output exists");
    fs::create_directories(dest / "blobs");
    std::ifstream input(argv[1]);
    if (!input) fail("cannot read input");
    std::ofstream output(dest / "records.csv");
    output << "record_id,protocol_rid,type,tag_hex,helper_hex,vk_hex,nfile_hex,nwrap_hex,ctag_hex,wrap_hex,wtag_hex,cipher_path,cipher_bytes,cipher_sha256,prepare_total_us\n";
    FuzzyExtractor fe;
    std::unordered_set<std::string> seen;
    std::size_t count = 0;
    for (std::string line; std::getline(input, line);) {
      std::istringstream stream(line);
      std::vector<std::string> fields;
      for (std::string field; std::getline(stream, field, '\t');) fields.push_back(field);
      if (fields.size() != 4) fail("invalid input row");
      const auto& id = fields[0];
      if (id.empty() || id.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != std::string::npos || !seen.insert(id).second)
        fail("invalid or duplicate record ID");
      const auto body = decode_hex(fields[3]);
      const auto tag = make_tag(body, "text");
      if (hex(sha256(body)) != fields[1] || hex(tag) != fields[2]) fail("body/tag mismatch: " + id);
      const auto start = std::chrono::steady_clock::now();
      auto upload = prepare_upload("text", body, tag, fe);
      const auto us = std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - start).count();
      const auto& r = upload.record;
      const auto path = dest / "blobs" / r.path;
      if (fs::exists(path)) fail("protocol ID collision");
      write_file(path, upload.ciphertext);
      output << id << ',' << r.rid << ",text," << hex(r.tag) << ',' << hex(r.helper) << ','
             << hex(r.vk) << ',' << hex(r.nfile) << ',' << hex(r.nwrap) << ',' << hex(r.ctag)
             << ',' << hex(r.wrap) << ',' << hex(r.wtag) << ",blobs/" << r.path << ','
             << upload.ciphertext.size() << ',' << hex(sha256(upload.ciphertext)) << ',' << us << '\n';
      if (++count % 250 == 0) std::cerr << "prepared " << count << '\n';
    }
    if (!input.eof() || count == 0) fail("input read failure or empty input");
    output.close();
    if (!output) fail("output write failure");
    std::cout << "prepared=" << count << " local_aead_self_check=passed\n";
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
