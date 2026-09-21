# PreFuzzDup 5w lookup handoff

This package contains only the tags required to reproduce the PreFuzzDup
persistent lookup benchmark. It does not contain Enron messages, bodies,
SQLite databases, ciphertext, or private keys.

## Server execution

From the repository root:

```bash
python3 tools/prefuzzdup-handoff/handoff.py server \
  --package D:/woskspace/fl/方案代码/handoff/20260921-prefuzzdup-5w \
  --scratch "$HOME/prefuzzdup-5w-scratch"
```

The command verifies input hashes, builds the Release binary, runs the
100-query equivalence check, and then runs thresholds 4, 5, and 6 with 3
repeats each. Results and logs are written under `D:/woskspace/fl/方案代码/handoff/20260921-prefuzzdup-5w/results/`.

After a successful run, commit and push the `results/` directory on this
handoff branch. This offline batch experiment does not measure network
communication or the complete upload protocol.
