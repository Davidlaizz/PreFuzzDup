#define PREFUZZDUP_AS_LIBRARY
#include "main.cpp"
#include "protocol_session.hpp"

int main() {
  const auto root = fs::temp_directory_path() / ("role-test-" + hex(random_bytes(8)));
  fs::create_directories(root);
  try {
    FuzzyExtractor fe;
    const auto body = bytes("alpha beta gamma delta epsilon");
    const auto tag = make_tag(body, "text");
    const auto upload = prepare_upload("text", body, tag, fe);
    const auto& r = upload.record;
    Attempt a{"run1", "alice", "q1", "all", "ref1", 6, 0, tag};
    Bytes token;
    {
      ProtocolSession s(root / "session.sqlite");
      token = s.issue(a, r);
    }
    const auto sig = client_sign(a, r, token, body, fe);
    if (!sig) fail("eligible client cannot sign");
    ProtocolSession s(root / "session.sqlite");
    if (!s.consume(a, r, token, *sig)) fail("reopened session rejected proof");
    if (s.consume(a, r, token, *sig)) fail("replay accepted");
    for (int field = 0; field < 8; ++field) {
      auto other = a;
      switch (field) {
        case 0: other.run = "run2"; break;
        case 1: other.uid = "bob"; break;
        case 2: other.query_id = "q2"; break;
        case 3: other.mode = "nearest"; break;
        case 4: other.original_id = "ref2"; break;
        case 5: other.threshold = 5; break;
        case 6: other.repeat = 1; break;
        case 7: other.query_tag[0] ^= 1; break;
      }
      auto t = s.issue(a, r);
      auto proof = client_sign(a, r, t, body, fe);
      if (s.consume(other, r, t, *proof)) fail("cross-attempt replay accepted");
      if (s.consume(a, r, t, *proof)) fail("failed attempt not consumed");
    }
    token = s.issue(a, r);
    auto bad = *client_sign(a, r, token, body, fe); bad[0] ^= 1;
    if (s.consume(a, r, token, bad)) fail("invalid signature accepted");
    token = s.issue(a, r);
    auto substituted = r; substituted.vk[0] ^= 1;
    if (s.consume(a, substituted, token, *client_sign(a, r, token, body, fe)))
      fail("substituted record accepted");
    token = s.issue(a, r);
    {
      Db db(root / "session.sqlite");
      Stmt ttl(db, "SELECT expires-unixepoch() FROM protocol_challenges WHERE token=?1");
      ttl.blob(1, token);
      if (!ttl.step_row() || ttl.col_int(0) < 1727995 || ttl.col_int(0) > 1728000) fail("wrong TTL");
    }
    { Db db(root / "session.sqlite"); db.exec("UPDATE protocol_challenges SET expires=unixepoch()-1"); }
    if (s.consume(a, r, token, *client_sign(a, r, token, body, fe))) fail("expired proof accepted");
    if (client_sign(a, r, token, bytes("different plaintext"), fe)) fail("body/tag mismatch accepted");
    { Db db(root / "session.sqlite"); Stmt q(db, "SELECT count(*) FROM sqlite_master WHERE name IN ('records','postings','protocol_records')");
      if (!q.step_row() || q.col_int(0)) fail("session creates reference/index tables"); }
    { Db db(root / "import.sqlite"); db.exec("CREATE TABLE protocol_records(id TEXT)"); }
    bool rejected = false;
    try { ProtocolSession wrong(root / "import.sqlite"); }
    catch (const std::exception&) { rejected = true; }
    if (!rejected) fail("import database used as session state");
  } catch (...) { fs::remove_all(root); throw; }
  fs::remove_all(root);
  std::cout << "role-separated proof, persistence, TTL, binding, signature and replay tests passed\n";
}
