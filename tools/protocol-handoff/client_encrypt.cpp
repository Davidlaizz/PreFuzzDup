#define PREFUZZDUP_CLIENT_WORKER_AS_LIBRARY
#include "client_crypto.cpp"

int main(int argc, char** argv) {
  try {
    if (argc != 4) fail("usage: client_encrypt PRIVATE_BODIES_TSV SELECTED_IDS_TSV NEW_OUTPUT_DIR");
    const auto local = bodies(argv[1]);
    const fs::path dest(argv[3]);
    if (fs::exists(dest)) fail("output exists");
    fs::create_directories(dest / "blobs");
    auto records_out = output_file(dest / "records.csv");
    auto metrics_out = output_file(dest / "encryption-metrics.csv");
    records_out << "record_id,protocol_rid,type,tag_hex,helper_hex,vk_hex,nfile_hex,nwrap_hex,ctag_hex,wrap_hex,wtag_hex,cipher_path,cipher_bytes,cipher_sha256,prepare_total_us\n";
    metrics_out << "query_id,repeat,fe_us,derive_us,encrypt_us,self_check_us,prepare_total_us,retained_ciphertext\n";
    FuzzyExtractor fe;
    std::unordered_set<std::string> seen;
    for (const auto& row : tsv(argv[2], 1)) {
      identifier(row[0]);
      if (!seen.insert(row[0]).second) fail("duplicate query ID");
      const auto& body = local.at(row[0]);
      if (!equal_ct(make_tag(body.plain, "text"), body.tag)) fail("body/tag mismatch");
      for (int repeat = 0; repeat < 3; ++repeat) {
        UploadMetrics metrics;
        const auto start = ClientClock::now();
        auto upload = prepare_upload("text", body.plain, body.tag, fe, &metrics);
        const auto total = elapsed_us(start);
        metrics_out << row[0] << ',' << repeat << ',' << metrics.fe_us << ',' << metrics.derive_us << ','
                    << metrics.encrypt_us << ',' << metrics.self_check_us << ',' << total << ',' << (repeat == 0) << '\n';
        if (repeat != 0) continue;
        const auto& r = upload.record;
        if (fs::exists(dest / "blobs" / r.path)) fail("random record ID collision");
        write_file(dest / "blobs" / r.path, upload.ciphertext);
        records_out << row[0] << ',' << r.rid << ",text," << hex(r.tag) << ',' << hex(r.helper) << ','
                    << hex(r.vk) << ',' << hex(r.nfile) << ',' << hex(r.nwrap) << ',' << hex(r.ctag) << ','
                    << hex(r.wrap) << ',' << hex(r.wtag) << ",blobs/" << r.path << ',' << upload.ciphertext.size()
                    << ',' << hex(sha256(upload.ciphertext)) << ',' << total << '\n';
      }
    }
    finish(records_out); finish(metrics_out);
  } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
