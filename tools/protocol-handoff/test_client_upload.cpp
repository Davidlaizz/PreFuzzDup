#define PREFUZZDUP_AS_LIBRARY
#include "main.cpp"

int main() {
  FuzzyExtractor fe;
  const auto body = bytes("alpha beta gamma delta epsilon");
  const auto tag = make_tag(body, "text");
  const auto a = prepare_upload("text", body, tag, fe);
  const auto b = prepare_upload("text", body, tag, fe);
  if (a.record.rid == b.record.rid) fail("distinct records were merged");
  const auto R = fe.rep(recovery_representation(body, "text"), a.record.helper);
  if (!R) fail("recovery failed");
  const auto Q = hkdf_extract(Bytes(32, 0), *R);
  const auto ad = Server::aad(a.record);
  const auto kd = aead_decrypt(wrap_key(Q, a.record), a.record.nwrap,
                             a.record.wrap, a.record.wtag, ad);
  if (!kd) fail("unwrap failed");
  const auto plain = aead_decrypt(*kd, a.record.nfile, a.ciphertext, a.record.ctag, ad);
  if (!plain || *plain != body) fail("client roundtrip failed");
  auto damaged = a.ciphertext;
  damaged[0] ^= 1;
  if (aead_decrypt(*kd, a.record.nfile, damaged, a.record.ctag, ad)) fail("tamper accepted");
  std::cout << "client upload roundtrip, distinct records and tamper rejection passed\n";
}
