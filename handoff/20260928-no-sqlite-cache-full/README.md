# Three-scheme full lookup handoff

This package contains only derived 256-bit SimHash tags and query IDs/groups.
It does not contain Enron messages, bodies, body hashes, SQLite databases,
ciphertext, or private keys.

Cache mode: `no_sqlite_cache` (`--sqlite-cache-kib 0`).
The OS page cache is intentionally kept warm and is shared by all schemes.

From a Linux server repository root, run:

```bash
python3 tools/lookup-handoff/handoff.py server \
  --package handoff/20260928-no-sqlite-cache-full \
  --scratch "$HOME/three-scheme-full-scratch" \
  --sqlite-cache-kib 0
```

The command verifies all hashes, builds the three lookup binaries, runs
PreFuzzDup equivalence checking, executes thresholds 4, 5, and 6, and writes
results and logs under `handoff/20260928-no-sqlite-cache-full/results/`. Commit that directory after
a successful run. This offline batch experiment does not measure Git transfer,
network communication, or the complete cryptographic protocol.
