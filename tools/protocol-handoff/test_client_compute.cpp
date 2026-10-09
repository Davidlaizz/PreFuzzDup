#define PREFUZZDUP_AS_LIBRARY
#include "main.cpp"
#include "client_compute.hpp"

int main() {
  FuzzyExtractor fe;
  auto body = bytes("alpha beta gamma delta epsilon zeta");
  auto tag = make_tag(body, "text");
  UploadMetrics metrics;
  auto upload = prepare_upload("text", body, tag, fe, &metrics);
  if (metrics.fe_us <= 0 || metrics.derive_us <= 0 || metrics.encrypt_us <= 0 || metrics.self_check_us <= 0)
    fail("upload phase timing missing");
  auto recovered = client_recover(upload.record, body, tag, upload.ciphertext, 6, fe);
  if (recovered.status != "accepted" || recovered.jaccard != 1) fail("valid recovery failed");
  auto bad = upload.ciphertext; bad[0] ^= 1;
  if (client_recover(upload.record, body, tag, bad, 6, fe).status != "decrypt_failed") fail("tamper accepted");
  auto wrong = tag; wrong[0] ^= 1;
  if (client_recover(upload.record, body, wrong, upload.ciphertext, 6, fe).status != "query_tag_mismatch")
    fail("unrelated body used for confirmation");
  if (five_word_jaccard(bytes("a b c d e f"), bytes("a b c d e g")) != 1.0 / 3.0) fail("wrong shingle size");
  if (five_word_jaccard(bytes("a b"), bytes("a c")) != 0) fail("short-body rule inconsistent");
  if (five_word_jaccard({}, {}) != 1) fail("empty-body rule inconsistent");
  auto sign = client_sign_timed(upload.record, "alice", body, tag, random_bytes(32), fe);
  if (sign.status != "signed" || sign.signature.size() != 64) fail("signature generation failed");
  if (client_sign_timed(upload.record, "alice", body, wrong, random_bytes(32), fe).status != "query_tag_mismatch")
    fail("signer accepted forged tag");
  std::cout << "client signature, AEAD recovery, tamper, tag and five-word confirmation passed\n";
}
