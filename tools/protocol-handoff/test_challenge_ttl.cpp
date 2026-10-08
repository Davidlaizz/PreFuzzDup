#define PREFUZZDUP_AS_LIBRARY
#include "main.cpp"

int main() {
  const auto root = fs::temp_directory_path() / ("ttl-test-" + hex(random_bytes(8)));
  fs::create_directories(root);
  try {
    const auto path = root / "state.sqlite";
    {
      Server s(path, root / "blobs");
      s.setup(10, 0.01, {{"text", 6}}, 1728000);
    }
    Server s(path, root / "blobs");
    s.open_existing();
    FuzzyExtractor fe;
    const auto body = bytes("alpha beta gamma delta epsilon");
    const auto tag = make_tag(body, "text");
    const auto upload = prepare_upload("text", body, tag, fe);
    const auto& r = upload.record;
    const auto R = fe.rep(recovery_representation(body, "text"), r.helper);
    const auto seed = proof_seed(hkdf_extract(Bytes(32, 0), *R), r);
    const auto c = s.issue_challenge("alice", r.rid, tag);
    Db db(path);
    {
    Stmt q(db, "SELECT expires-unixepoch() FROM challenges");
    if (!q.step_row() || q.col_int(0) < 1727995 || q.col_int(0) > 1728000)
      fail("20-day TTL must survive reopening");
    }
    auto sig = sign_ed(seed, Server::challenge_message("alice", r, tag, c.token));
    if (!s.consume_verify("alice", r, tag, c.token, sig)) fail("valid proof rejected");
    if (s.consume_verify("alice", r, tag, c.token, sig)) fail("replay accepted");
    const auto expired = s.issue_challenge("alice", r.rid, tag);
    db.exec("UPDATE challenges SET expires=unixepoch()-1");
    sig = sign_ed(seed, Server::challenge_message("alice", r, tag, expired.token));
    if (s.consume_verify("alice", r, tag, expired.token, sig)) fail("expiry bypassed");
    const auto bound = s.issue_challenge("alice", r.rid, tag);
    sig = sign_ed(seed, Server::challenge_message("alice", r, tag, bound.token));
    if (s.consume_verify("bob", r, tag, bound.token, sig)) fail("binding bypassed");
    bool rejected = false;
    try { s.setup(10, 0.01, {{"text", 6}}, 0); }
    catch (const std::exception&) { rejected = true; }
    if (!rejected) fail("zero TTL accepted");
    db.exec("DELETE FROM meta WHERE k='challenge_ttl_seconds'");
    s.open_existing();
    s.issue_challenge("legacy", r.rid, tag);
    Stmt legacy(db, "SELECT expires-unixepoch() FROM challenges WHERE uid='legacy'");
    if (!legacy.step_row() || legacy.col_int(0) < 115 || legacy.col_int(0) > 120)
      fail("legacy database must retain 120-second default");
  } catch (...) { fs::remove_all(root); throw; }
  fs::remove_all(root);
  std::cout << "challenge TTL, persistence, expiry, binding and replay passed\n";
}
