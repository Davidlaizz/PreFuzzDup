#define PREFUZZDUP_AS_LIBRARY
#include "main.cpp"
#include "protocol_store.hpp"

int main(int argc, char** argv) {
  if (argc != 2) fail("usage: test_protocol_store IMPORT_DIRECTORY");
  const fs::path root(argv[1]);
  const auto before = sha256(read_file(root / "protocol.sqlite"));
  ProtocolStore store(root);
  Db db(root / "protocol.sqlite");
  Stmt rows(db, "SELECT record_id,rid,tag FROM protocol_records");
  int count = 0;
  while (rows.step_row()) {
    const auto record = store.get_record(rows.col_text(0), rows.col_blob(2));
    if (!record || record->rid != rows.col_text(1)) fail("original ID mapping lost");
    store.read_ciphertext(rows.col_text(0), *record);
    auto wrong_tag = rows.col_blob(2); wrong_tag[0] ^= 1;
    bool rejected = false;
    try { store.get_record(rows.col_text(0), wrong_tag); }
    catch (const std::exception&) { rejected = true; }
    if (!rejected) fail("index/protocol tag mismatch accepted");
    ++count;
  }
  if (count != 2259) fail("unexpected record count");
  if (store.get_record("missing", Bytes(32))) fail("missing record fabricated");
  Stmt tables(db, "SELECT count(*) FROM sqlite_master WHERE name IN ('postings','records','challenges')");
  if (!tables.step_row() || tables.col_int(0) != 0) fail("import store changed into search/session DB");
  if (!equal_ct(before, sha256(read_file(root / "protocol.sqlite")))) fail("read adapter modified DB");
  const auto temp = fs::temp_directory_path() / ("protocol-store-test-" + hex(random_bytes(8)));
  fs::create_directories(temp / "blobs");
  try {
    fs::copy_file(root / "protocol.sqlite", temp / "protocol.sqlite");
    Stmt first(db, "SELECT record_id,tag FROM protocol_records LIMIT 1");
    if (!first.step_row()) fail("empty test store");
    ProtocolStore damaged(temp);
    const auto record = damaged.get_record(first.col_text(0), first.col_blob(1));
    auto cipher = store.read_ciphertext(first.col_text(0), *record);
    if (cipher.empty()) cipher.push_back(1); else cipher[0] ^= 1;
    write_file(temp / record->path, cipher);
    bool rejected = false;
    try { damaged.read_ciphertext(first.col_text(0), *record); }
    catch (const std::exception&) { rejected = true; }
    if (!rejected) fail("tampered ciphertext accepted");
  } catch (...) { fs::remove_all(temp); throw; }
  fs::remove_all(temp);
  std::cout << "passed: 2259 ID/tag mappings, ciphertext hashes, missing record and mismatched tags\n";
}
