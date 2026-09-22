# Three-scheme full lookup client/server handoff

This is an offline batch experiment. The local machine acts as the client and
4210 acts as the server. A Git branch carries derived tags and returned CSVs.
It does not measure network, Git, cryptographic, or end-to-end latency.

## Scope

- Schemes: PreFuzzDup, SimLESS, and FuzzyDedup.
- Data: Enron full derived 256-bit text SimHash tags.
- Queries: 1,000 benchmark queries and 100 verification queries.
- Thresholds: 4, 5, and 6, with 3 repeats.
- Git payload: tags, IDs, redacted query groups, results, logs, and manifests.
- Git does not carry original mail, bodies, SQLite files, ciphertext, or keys.

## Client: create and publish

Run from the repository root on the client:

```bash
git switch main
git pull
git switch -c codex/three-scheme-lookup-handoff-full

python tools/lookup-handoff/handoff.py client \
  --scale full \
  --source results-local/enron-full/lookup-experiment/inputs \
  --baseline results-local/enron-full/lookup-experiment \
  --dest handoff/20260922-three-scheme-full

git add tools/lookup-handoff docs/three-scheme-lookup-handoff.md \
  SimLESS/CMakeLists.txt FuzzyDedup/CMakeLists.txt \
  handoff/20260922-three-scheme-full
git commit -m "feat(experiments): add three-scheme full lookup handoff"
git push -u origin codex/three-scheme-lookup-handoff-full
```

## Server: execute on 4210

Install system dependencies:

```bash
sudo apt-get update
sudo apt-get install -y git python3 cmake build-essential pkg-config \
  libssl-dev sqlite3 libsqlite3-dev
```

Clone and run:

```bash
git clone -b codex/three-scheme-lookup-handoff-full \
  https://github.com/Davidlaizz/PreFuzzDup.git
cd PreFuzzDup

python3 tools/lookup-handoff/handoff.py server \
  --package handoff/20260922-three-scheme-full \
  --scratch "$HOME/three-scheme-full-scratch"
```

The scratch directory must be on a native Linux filesystem. Do not use `/mnt`.
Do not clear the OS page cache. The script fails if any command fails or if
cross-scheme matched results disagree.

Check success:

```bash
grep '"status": "passed"' \
  handoff/20260922-three-scheme-full/results/server-result-manifest.json
grep 'equivalence_check=passed' \
  handoff/20260922-three-scheme-full/results/logs/prefuzzdup-verify.log
wc -l handoff/20260922-three-scheme-full/results/*bench*.csv
wc -l handoff/20260922-three-scheme-full/results/prefuzzdup_t*.csv
```

Expected row counts exclude headers:

- `prefuzzdup_t4.csv`, `prefuzzdup_t5.csv`, `prefuzzdup_t6.csv`: 3,000 each.
- `simless_bench.csv`: 9,000.
- `fuzzydedup_bench.csv`: 9,000.

Commit and return the result directory:

```bash
git add handoff/20260922-three-scheme-full/results
git commit -m "chore(experiments): record three-scheme full server lookup results"
git push
```

Never commit `$HOME/three-scheme-full-scratch` or SQLite databases.

## Client: retrieve and analyze

```bash
git fetch origin
git switch codex/three-scheme-lookup-handoff-full
git pull

python tools/lookup-handoff/handoff.py analyze \
  --package handoff/20260922-three-scheme-full \
  --baseline results-local/enron-full/lookup-experiment \
  --output results-local/three-scheme-handoff/enron-full
```

Outputs are `comparison.csv`, `latency_summary.csv`,
`workload_summary.csv`, `metadata_comparison.csv`, and `analysis.md`.
The analysis passes only when all 3,000 unique workload keys per scheme agree,
all matched decisions agree across schemes, and no returned file hash differs.
Latency is reported but is not a correctness condition.

This branch is a temporary experiment branch and is not merged into `main`.
