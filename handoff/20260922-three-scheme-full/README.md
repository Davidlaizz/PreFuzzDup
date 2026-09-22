# Three-scheme full lookup handoff

This package contains only derived 256-bit SimHash tags and query IDs/groups.
It does not contain Enron messages, bodies, body hashes, SQLite databases,
ciphertext, or private keys.

From a Linux server repository root, run:

```bash
python3 tools/lookup-handoff/handoff.py server \
  --package D:/woskspace/fl/方案代码/handoff/20260922-three-scheme-full \
  --scratch "$HOME/three-scheme-full-scratch"
```

The command verifies all hashes, builds the three lookup binaries, runs
PreFuzzDup equivalence checking, executes thresholds 4, 5, and 6, and writes
results and logs under `D:/woskspace/fl/方案代码/handoff/20260922-three-scheme-full/results/`. Commit that directory after
a successful run. This offline batch experiment does not measure Git transfer,
network communication, or the complete cryptographic protocol.
