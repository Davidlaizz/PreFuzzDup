#!/usr/bin/env python3
"""Package, execute, and analyze the full three-scheme lookup handoff."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import platform
import re
import shlex
import statistics
import subprocess
import sys
import time
import unittest
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence


SCALE = "full"
THRESHOLDS = (4, 5, 6)
REPEAT = 3
FPP = "0.01"
TAG_BITS = 256
BENCHMARK_QUERY_COUNT = 1_000
VERIFY_QUERY_COUNT = 100
EXPECTED_COUNTS = {
    "total_records": 517_401,
    "reference_count": 413_921,
    "benchmark_count": BENCHMARK_QUERY_COUNT,
    "verify_count": VERIFY_QUERY_COUNT,
}
INPUT_FILES = (
    "reference.csv",
    "queries_bench_1000.csv",
    "queries_verify_100.csv",
    "query_groups_bench_1000.csv",
    "query_groups_verify_100.csv",
    "split_summary.json",
)
SOURCE_LABELS = "query_labels_bench_1000.csv"
GROUP_HEADER = ["query_id", "group", "payload_digest", "source_ref"]
PREFUZZ_HEADER = [
    "strategy",
    "query_id",
    "type",
    "repeat",
    "latency_us",
    "candidate_count",
    "filter_queries",
    "inverted_lookups",
    "posting_records_read",
    "full_tag_distance_computations",
]
COMPARATIVE_HEADER = [
    "scheme",
    "threshold",
    "repeat",
    "query_id",
    "group",
    "latency_us",
    "matched",
    "best_distance",
    "records_examined",
    "bits_compared",
]
PREFUZZ_WORKLOAD_METRICS = (
    "candidate_count",
    "filter_queries",
    "inverted_lookups",
    "posting_records_read",
    "full_tag_distance_computations",
)
COMPARATIVE_WORKLOAD_METRICS = (
    "matched",
    "best_distance",
    "records_examined",
    "bits_compared",
)
METADATA_METRICS = (
    "index_prepare_us",
    "disk_index_reused",
    "filter_bytes_estimate",
    "sqlite_cache_kib",
)
RESULT_ROWS_PER_SCHEME = BENCHMARK_QUERY_COUNT * REPEAT * len(THRESHOLDS)
RESULT_KEYS_PER_SCHEME = RESULT_ROWS_PER_SCHEME


def fail(message: str) -> None:
    raise RuntimeError(message)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as target:
        json.dump(value, target, indent=2, sort_keys=True)
        target.write("\n")


def read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, dict):
        fail(f"expected a JSON object: {path}")
    return value


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames is None:
            fail(f"empty CSV: {path}")
        return list(reader)


def write_csv(path: Path, fieldnames: Sequence[str], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as target:
        writer = csv.DictWriter(target, fieldnames=list(fieldnames), lineterminator="\n", extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def require_empty_directory(path: Path, label: str) -> None:
    if path.exists() and any(path.iterdir()):
        fail(f"{label} already exists and is not empty: {path}")
    path.mkdir(parents=True, exist_ok=True)


def validate_tag_csv(path: Path, expected_count: int) -> list[dict[str, str]]:
    rows = read_csv(path)
    if rows and list(rows[0]) != ["id", "type", "tag_hex"]:
        fail(f"unexpected CSV header: {path}")
    if len(rows) != expected_count:
        fail(f"expected {expected_count} rows in {path}, got {len(rows)}")
    ids: set[str] = set()
    for row in rows:
        record_id = row["id"]
        if not record_id or record_id in ids:
            fail(f"missing or duplicate ID in {path}: {record_id}")
        ids.add(record_id)
        if row["type"] != "text":
            fail(f"non-text tag in {path}: {record_id}")
        tag = row["tag_hex"]
        if len(tag) != TAG_BITS // 4 or any(character not in "0123456789abcdef" for character in tag):
            fail(f"invalid {TAG_BITS}-bit tag in {path}: {record_id}")
    return rows


def validate_split_summary(path: Path) -> dict[str, Any]:
    summary = read_json(path)
    for key, expected in EXPECTED_COUNTS.items():
        if summary.get(key) != expected:
            fail(f"split_summary {key} is {summary.get(key)!r}, expected {expected!r}")
    files = summary.get("files")
    if not isinstance(files, dict):
        fail("split_summary has no files inventory")
    for name in ("reference.csv", "queries_bench_1000.csv", "queries_verify_100.csv"):
        if name not in files:
            fail(f"split_summary files inventory is missing {name}")
    return summary


def validate_source_labels(path: Path, query_rows: list[dict[str, str]]) -> dict[str, str]:
    rows = read_csv(path)
    if rows and list(rows[0]) != ["query_id", "group", "body_sha256", "source_id"]:
        fail(f"unexpected source label header: {path}")
    if len(rows) != len(query_rows):
        fail(f"expected {len(query_rows)} source labels in {path}, got {len(rows)}")
    groups: dict[str, str] = {}
    query_ids = {row["id"] for row in query_rows}
    for row in rows:
        query_id = row["query_id"]
        if query_id in groups:
            fail(f"duplicate source label: {query_id}")
        if query_id not in query_ids:
            fail(f"source label does not match a query: {query_id}")
        if row["group"] not in {"exact_ref", "no_exact_ref"}:
            fail(f"invalid benchmark group for {query_id}: {row['group']}")
        groups[query_id] = row["group"]
    if set(groups) != query_ids:
        fail("source label IDs differ from benchmark query IDs")
    return groups


def package_readme(package_name: str) -> str:
    return f"""# Three-scheme full lookup handoff

This package contains only derived 256-bit SimHash tags and query IDs/groups.
It does not contain Enron messages, bodies, body hashes, SQLite databases,
ciphertext, or private keys.

From a Linux server repository root, run:

```bash
python3 tools/lookup-handoff/handoff.py server \\
  --package {package_name} \\
  --scratch "$HOME/three-scheme-full-scratch"
```

The command verifies all hashes, builds the three lookup binaries, runs
PreFuzzDup equivalence checking, executes thresholds 4, 5, and 6, and writes
results and logs under `{package_name}/results/`. Commit that directory after
a successful run. This offline batch experiment does not measure Git transfer,
network communication, or the complete cryptographic protocol.
"""


def validate_baseline(baseline: Path) -> dict[str, Any]:
    required = [
        baseline / "run_manifest.json",
        *(baseline / "raw" / f"prefuzz_t{threshold}.csv" for threshold in THRESHOLDS),
        baseline / "raw" / "simless_lookup.csv",
        baseline / "raw" / "fuzzydedup_lookup.csv",
    ]
    missing = [path for path in required if not path.is_file()]
    if missing:
        fail(f"baseline is missing files: {', '.join(str(path) for path in missing)}")
    manifest = read_json(baseline / "run_manifest.json")
    if manifest.get("repeat") != REPEAT:
        fail(f"baseline repeat is {manifest.get('repeat')!r}, expected {REPEAT}")
    return {
        "run_manifest_sha256": sha256_file(baseline / "run_manifest.json"),
        "raw_files": {
            path.name: {"sha256": sha256_file(path), "size_bytes": path.stat().st_size}
            for path in sorted((baseline / "raw").glob("*.csv"))
        },
    }


def create_client_package(source: Path, destination: Path, baseline: Path, repo: Path) -> dict[str, Any]:
    require_empty_directory(destination, "destination")
    reference = validate_tag_csv(source / "reference.csv", EXPECTED_COUNTS["reference_count"])
    benchmark = validate_tag_csv(source / "queries_bench_1000.csv", BENCHMARK_QUERY_COUNT)
    verify = validate_tag_csv(source / "queries_verify_100.csv", VERIFY_QUERY_COUNT)
    split = validate_split_summary(source / "split_summary.json")
    benchmark_groups = validate_source_labels(source / SOURCE_LABELS, benchmark)

    reference_ids = {row["id"] for row in reference}
    benchmark_ids = {row["id"] for row in benchmark}
    verify_ids = {row["id"] for row in verify}
    if len(reference_ids) != len(reference):
        fail("reference.csv contains duplicate IDs")
    if len(benchmark_ids) != len(benchmark) or len(verify_ids) != len(verify):
        fail("query files contain duplicate IDs")
    if reference_ids & (benchmark_ids | verify_ids):
        fail("reference and query IDs overlap")
    benchmark_by_id = {row["id"]: row for row in benchmark}
    for query_id in benchmark_ids & verify_ids:
        verify_row = next(row for row in verify if row["id"] == query_id)
        benchmark_row = benchmark_by_id[query_id]
        if (benchmark_row["type"], benchmark_row["tag_hex"]) != (verify_row["type"], verify_row["tag_hex"]):
            fail(f"overlapping benchmark/verify IDs have different tags: {query_id}")

    inputs = destination / "inputs"
    inputs.mkdir(parents=True)
    copied_names = ("reference.csv", "queries_bench_1000.csv", "queries_verify_100.csv", "split_summary.json")
    for name in copied_names:
        data = (source / name).read_bytes()
        (inputs / name).write_bytes(data)

    write_csv(
        inputs / "query_groups_bench_1000.csv",
        GROUP_HEADER,
        (
            {
                "query_id": row["id"],
                "group": benchmark_groups[row["id"]],
                "payload_digest": "",
                "source_ref": "",
            }
            for row in benchmark
        ),
    )
    write_csv(
        inputs / "query_groups_verify_100.csv",
        GROUP_HEADER,
        ({"query_id": row["id"], "group": "verify", "payload_digest": "", "source_ref": ""} for row in verify),
    )

    input_files: dict[str, dict[str, Any]] = {}
    for name in INPUT_FILES:
        path = inputs / name
        input_files[name] = {"sha256": sha256_file(path), "size_bytes": path.stat().st_size}

    baseline_inventory = validate_baseline(baseline)
    expected_outputs = [
        "results/prefuzzdup_verify.csv",
        *(f"results/prefuzzdup_t{threshold}.csv" for threshold in THRESHOLDS),
        "results/simless_verify.csv",
        "results/simless_bench.csv",
        "results/fuzzydedup_verify.csv",
        "results/fuzzydedup_bench.csv",
        "results/environment.json",
        "results/server-result-manifest.json",
    ]
    completed = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, text=True, capture_output=True, check=False)
    manifest = {
        "schema_version": 1,
        "package_type": "three_scheme_lookup_handoff",
        "scale": SCALE,
        "created_utc": utc_now(),
        "source_git_commit": completed.stdout.strip() if completed.returncode == 0 else "unknown",
        "thresholds": list(THRESHOLDS),
        "repeat": REPEAT,
        "fpp": FPP,
        "tag_bits": TAG_BITS,
        "expected_counts": EXPECTED_COUNTS,
        "group_counts": {
            "benchmark": {
                group: sum(group == value for value in benchmark_groups.values())
                for group in ("exact_ref", "no_exact_ref")
            },
            "verify": VERIFY_QUERY_COUNT,
        },
        "expected_result_rows_per_scheme": RESULT_ROWS_PER_SCHEME,
        "expected_outputs": expected_outputs,
        "inputs": input_files,
        "baseline": baseline_inventory,
        "split_summary": split,
    }
    write_json(destination / "handoff-manifest.json", manifest)
    (destination / "README.md").write_text(package_readme(destination.as_posix().replace("\\", "/")), encoding="utf-8", newline="\n")
    return manifest


def verify_package(package: Path) -> dict[str, Any]:
    manifest_path = package / "handoff-manifest.json"
    if not manifest_path.is_file():
        fail(f"missing handoff manifest: {manifest_path}")
    manifest = read_json(manifest_path)
    if manifest.get("package_type") != "three_scheme_lookup_handoff":
        fail("unsupported handoff package type")
    if manifest.get("schema_version") != 1 or manifest.get("scale") != SCALE:
        fail("unsupported handoff schema or scale")
    if manifest.get("thresholds") != list(THRESHOLDS):
        fail("handoff thresholds must be [4, 5, 6]")
    if manifest.get("repeat") != REPEAT or manifest.get("fpp") != FPP or manifest.get("tag_bits") != TAG_BITS:
        fail("handoff fixed parameters do not match")

    recorded = manifest.get("inputs")
    if not isinstance(recorded, dict) or set(recorded) != set(INPUT_FILES):
        fail("handoff input manifest is incomplete")
    for name in INPUT_FILES:
        path = package / "inputs" / name
        if not path.is_file():
            fail(f"missing package input: {path}")
        digest = sha256_file(path)
        expected = str(recorded[name].get("sha256", ""))
        if digest != expected:
            fail(f"SHA-256 mismatch for {path}: {digest} != {expected}")

    reference = validate_tag_csv(package / "inputs" / "reference.csv", EXPECTED_COUNTS["reference_count"])
    benchmark = validate_tag_csv(package / "inputs" / "queries_bench_1000.csv", BENCHMARK_QUERY_COUNT)
    verify = validate_tag_csv(package / "inputs" / "queries_verify_100.csv", VERIFY_QUERY_COUNT)
    validate_split_summary(package / "inputs" / "split_summary.json")
    validate_group_csv(package / "inputs" / "query_groups_bench_1000.csv", benchmark, {"exact_ref", "no_exact_ref"})
    validate_group_csv(package / "inputs" / "query_groups_verify_100.csv", verify, {"verify"})
    return manifest


def validate_group_csv(path: Path, query_rows: list[dict[str, str]], allowed_groups: set[str]) -> dict[str, str]:
    rows = read_csv(path)
    if rows and list(rows[0]) != GROUP_HEADER:
        fail(f"unexpected query group header: {path}")
    if len(rows) != len(query_rows):
        fail(f"expected {len(query_rows)} rows in {path}, got {len(rows)}")
    expected_ids = {row["id"] for row in query_rows}
    groups: dict[str, str] = {}
    for row in rows:
        query_id = row["query_id"]
        if query_id in groups or query_id not in expected_ids:
            fail(f"unexpected or duplicate query group: {query_id}")
        if row["group"] not in allowed_groups:
            fail(f"invalid group for {query_id}: {row['group']}")
        if row["payload_digest"] or row["source_ref"]:
            fail(f"redacted group fields are not empty for {query_id}")
        groups[query_id] = row["group"]
    if set(groups) != expected_ids:
        fail(f"query group IDs differ: {path}")
    return groups


def validate_prefuzz_csv(path: Path, expected_rows: int, threshold: int, query_ids: set[str]) -> list[dict[str, str]]:
    rows = read_csv(path)
    if not rows or list(rows[0]) != PREFUZZ_HEADER:
        fail(f"unexpected PreFuzzDup output header: {path}")
    if len(rows) != expected_rows:
        fail(f"expected {expected_rows} rows in {path}, got {len(rows)}")
    seen: set[tuple[str, int]] = set()
    for row in rows:
        if row["strategy"] != "prefuzz" or row["type"] != "text":
            fail(f"unexpected strategy or type in {path}")
        query_id = row["query_id"]
        repeat = int(row["repeat"])
        key = (query_id, repeat)
        if query_id not in query_ids or key in seen:
            fail(f"unexpected or duplicate PreFuzzDup result key in {path}: {key}")
        seen.add(key)
        if not (0 <= repeat < REPEAT):
            fail(f"repeat outside range in {path}: {repeat}")
        if float(row["latency_us"]) < 0 or any(int(row[metric]) < 0 for metric in PREFUZZ_WORKLOAD_METRICS):
            fail(f"negative PreFuzzDup metric in {path}")
        if int(row["filter_queries"]) != threshold + 1:
            fail(f"unexpected filter query count in {path}: {row['filter_queries']}")
        row["threshold"] = str(threshold)
    return rows


def validate_comparative_csv(
    path: Path,
    scheme: str,
    expected_rows: int,
    repeat_count: int,
    query_ids: set[str],
    allowed_groups: set[str],
    reference_count: int,
) -> list[dict[str, str]]:
    rows = read_csv(path)
    if not rows or list(rows[0]) != COMPARATIVE_HEADER:
        fail(f"unexpected comparative output header: {path}")
    if len(rows) != expected_rows:
        fail(f"expected {expected_rows} rows in {path}, got {len(rows)}")
    seen: set[tuple[str, int, int]] = set()
    for row in rows:
        if row["scheme"] != scheme:
            fail(f"unexpected scheme in {path}: {row['scheme']}")
        threshold = int(row["threshold"])
        repeat = int(row["repeat"])
        query_id = row["query_id"]
        key = (threshold, repeat, query_id)
        if threshold not in THRESHOLDS or query_id not in query_ids or key in seen:
            fail(f"unexpected or duplicate comparative result key in {path}: {key}")
        seen.add(key)
        if not (0 <= repeat < repeat_count) or row["group"] not in allowed_groups:
            fail(f"invalid repeat or group in {path}")
        if float(row["latency_us"]) < 0:
            fail(f"negative latency in {path}")
        if row["matched"] not in {"0", "1"}:
            fail(f"invalid matched value in {path}")
        if any(int(row[metric]) < 0 for metric in COMPARATIVE_WORKLOAD_METRICS[1:]):
            fail(f"negative comparative metric in {path}")
        if int(row["records_examined"]) > reference_count:
            fail(f"records examined exceeds reference count in {path}")
    return rows


def comparative_command(
    binary: Path,
    scheme: str,
    records: Path,
    queries: Path,
    groups: Path,
    database: Path,
    output: Path,
    repeat: int,
) -> list[str]:
    return [
        binary.as_posix(),
        "--scheme",
        scheme,
        "--records",
        records.as_posix(),
        "--queries",
        queries.as_posix(),
        "--labels",
        groups.as_posix(),
        "--thresholds",
        ",".join(str(value) for value in THRESHOLDS),
        "--repeat",
        str(repeat),
        "--db",
        database.as_posix(),
        "--out",
        output.as_posix(),
    ]


def prefuzz_command(
    binary: Path,
    records: Path,
    queries: Path,
    database: Path,
    output: Path,
    threshold: int,
    repeat: int,
    verify: bool = False,
) -> list[str]:
    command = [
        binary.as_posix(),
        "--records",
        records.as_posix(),
        "--queries",
        queries.as_posix(),
        "--db",
        database.as_posix(),
        "--tag-bits",
        str(TAG_BITS),
        "--threshold",
        f"default={threshold}",
        "--fpp",
        FPP,
        "--strategies",
        "prefuzz",
        "--repeat",
        str(repeat),
    ]
    if verify:
        command.append("--verify-equivalence")
    command.extend(["--out", output.as_posix()])
    return command


def parse_prefuzz_metadata(stdout: str) -> dict[str, Any]:
    line = next((line for line in stdout.splitlines() if line.startswith("records=")), "")
    if not line:
        fail("PreFuzzDup metadata line was not found")
    result: dict[str, Any] = {}
    for item in line.split(","):
        key, separator, value = item.partition("=")
        if not separator:
            continue
        key, value = key.strip(), value.strip()
        if re.fullmatch(r"-?\d+", value):
            result[key] = int(value)
        elif re.fullmatch(r"-?(?:\d+\.\d*|\d*\.\d+)", value):
            result[key] = float(value)
        else:
            result[key] = value
    if not set(METADATA_METRICS).issubset(result):
        fail(f"PreFuzzDup metadata is incomplete: {line}")
    return result


def first_line(command: Sequence[str], cwd: Path) -> str:
    try:
        completed = subprocess.run(list(command), cwd=cwd, text=True, capture_output=True, check=True)
        return completed.stdout.splitlines()[0] if completed.stdout else ""
    except (OSError, subprocess.CalledProcessError, IndexError):
        return ""


def read_first_match(path: Path, pattern: str) -> str:
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            match = re.search(pattern, line)
            if match:
                return match.group(1)
    except OSError:
        pass
    return ""


def collect_environment(repo: Path) -> dict[str, Any]:
    return {
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": sys.version,
        "uname": first_line(["uname", "-a"], repo),
        "compiler": first_line(["c++", "--version"], repo),
        "cmake": first_line(["cmake", "--version"], repo),
        "sqlite_package": first_line(["pkg-config", "--modversion", "sqlite3"], repo),
        "cpu_model": read_first_match(Path("/proc/cpuinfo"), r"^model name\s*:\s*(.+)$"),
        "memory_total": read_first_match(Path("/proc/meminfo"), r"^MemTotal\s*:\s*(.+)$"),
        "page_cache_cleared": False,
        "sqlite_application_cache_kib": 1024,
        "git_transfer_measured": False,
    }


def run_logged(
    path: Path,
    command: Sequence[str],
    cwd: Path,
    phase: str,
    commands: list[dict[str, Any]],
) -> subprocess.CompletedProcess[str]:
    path.parent.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    completed = subprocess.run(list(command), cwd=cwd, text=True, capture_output=True, check=False)
    elapsed = time.perf_counter() - started
    with path.open("w", encoding="utf-8", newline="\n") as target:
        target.write("$ " + shlex.join(command) + "\n")
        target.write(f"cwd: {cwd}\n\n[stdout]\n{completed.stdout}\n[stderr]\n{completed.stderr}\n")
        target.write(f"[exit-code] {completed.returncode}\n[wall-seconds] {elapsed:.6f}\n")
    commands.append(
        {
            "phase": phase,
            "command": list(command),
            "exit_code": completed.returncode,
            "wall_seconds": elapsed,
            "log": path.relative_to(path.parents[3]).as_posix(),
        }
    )
    if completed.returncode != 0:
        fail(f"command failed with exit code {completed.returncode}; log: {path}")
    return completed


def git_commit(repo: Path) -> str:
    completed = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, text=True, capture_output=True, check=False)
    return completed.stdout.strip() if completed.returncode == 0 else "unknown"


def file_inventory(root: Path, exclude: Path | None = None) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path == exclude:
            continue
        result[path.relative_to(root).as_posix()] = {
            "sha256": sha256_file(path),
            "size_bytes": path.stat().st_size,
        }
    return result


def build_project(
    repo: Path,
    project: str,
    target: str,
    logs: Path,
    commands: list[dict[str, Any]],
) -> Path:
    source = repo / project
    build = source / "build"
    configure = ["cmake", "-S", source.as_posix(), "-B", build.as_posix(), "-DCMAKE_BUILD_TYPE=Release"]
    build_command = ["cmake", "--build", build.as_posix(), "--target", target, "-j"]
    run_logged(logs / f"build-{project.lower()}-configure.log", configure, repo, f"configure_{project}", commands)
    run_logged(logs / f"build-{project.lower()}.log", build_command, repo, f"build_{project}", commands)
    binary = {
        "PreFuzzDup": "prefuzzdup_persistent_lookup",
        "SimLESS": "simless_lookup_benchmark",
        "FuzzyDedup": "fuzzydedup_lookup_benchmark",
    }[target_target_project(target)]
    executable = build / binary
    if not executable.is_file():
        fail(f"lookup binary was not produced: {executable}")
    return executable


def target_target_project(target: str) -> str:
    if target.startswith("prefuzzdup"):
        return "PreFuzzDup"
    if target.startswith("simless"):
        return "SimLESS"
    if target.startswith("fuzzydedup"):
        return "FuzzyDedup"
    fail(f"unknown lookup target: {target}")


def percentile_nearest(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(round(quantile * (len(ordered) - 1)))))
    return ordered[index]


def load_prefuzz_result(package: Path, threshold: int) -> dict[tuple[int, int, str], dict[str, str]]:
    rows = read_csv(package / "results" / f"prefuzzdup_t{threshold}.csv")
    result: dict[tuple[int, int, str], dict[str, str]] = {}
    for row in rows:
        row["threshold"] = str(threshold)
        key = result_key(row)
        if key in result:
            fail(f"duplicate server PreFuzzDup result: {key}")
        result[key] = row
    return result


def load_comparative_result(package: Path, scheme: str) -> dict[tuple[int, int, str], dict[str, str]]:
    rows = read_csv(package / "results" / f"{scheme}_bench.csv")
    result: dict[tuple[int, int, str], dict[str, str]] = {}
    for row in rows:
        key = result_key(row)
        if key in result:
            fail(f"duplicate server {scheme} result: {key}")
        result[key] = row
    return result


def load_prefuzz_baseline(baseline: Path, threshold: int) -> dict[tuple[int, int, str], dict[str, str]]:
    rows = read_csv(baseline / "raw" / f"prefuzz_t{threshold}.csv")
    result: dict[tuple[int, int, str], dict[str, str]] = {}
    for row in rows:
        row["threshold"] = str(threshold)
        key = result_key(row)
        if key in result:
            fail(f"duplicate baseline PreFuzzDup result: {key}")
        result[key] = row
    return result


def load_comparative_baseline(baseline: Path, scheme: str) -> dict[tuple[int, int, str], dict[str, str]]:
    rows = read_csv(baseline / "raw" / f"{scheme}_lookup.csv")
    result: dict[tuple[int, int, str], dict[str, str]] = {}
    for row in rows:
        key = result_key(row)
        if key in result:
            fail(f"duplicate baseline {scheme} result: {key}")
        result[key] = row
    return result


def verify_result_inventory(package: Path, server_manifest: dict[str, Any]) -> None:
    results = package / "results"
    recorded = server_manifest.get("result_files")
    if not isinstance(recorded, dict):
        fail("server result manifest has no result file inventory")
    actual = file_inventory(results, results / "server-result-manifest.json")
    if set(actual) != set(recorded):
        fail("server result inventory differs from returned files")
    for name, expected in recorded.items():
        path = results / name
        if sha256_file(path) != expected.get("sha256"):
            fail(f"server result SHA-256 mismatch: {name}")


def analyze_results(package: Path, baseline: Path, output: Path) -> bool:
    handoff_manifest = verify_package(package)
    server_manifest_path = package / "results" / "server-result-manifest.json"
    if not server_manifest_path.is_file():
        fail(f"missing server result manifest: {server_manifest_path}")
    server_manifest = read_json(server_manifest_path)
    if server_manifest.get("status") != "passed":
        fail(f"server result status is {server_manifest.get('status')!r}")
    verify_result_inventory(package, server_manifest)

    workload_by_scheme = {
        "prefuzzdup": PREFUZZ_WORKLOAD_METRICS,
        "simless": COMPARATIVE_WORKLOAD_METRICS,
        "fuzzydedup": COMPARATIVE_WORKLOAD_METRICS,
    }
    server: dict[str, dict[tuple[int, int, str], dict[str, str]]] = {}
    base: dict[str, dict[tuple[int, int, str], dict[str, str]]] = {}
    for threshold in THRESHOLDS:
        for key, value in load_prefuzz_result(package, threshold).items():
            server.setdefault("prefuzzdup", {})[key] = value
        for key, value in load_prefuzz_baseline(baseline, threshold).items():
            base.setdefault("prefuzzdup", {})[key] = value
    for scheme in ("simless", "fuzzydedup"):
        server[scheme] = load_comparative_result(package, scheme)
        base[scheme] = load_comparative_baseline(baseline, scheme)

    comparison_rows: list[dict[str, Any]] = []
    workload_disagreements = 0
    matched_disagreements = 0
    group_disagreements = 0
    missing_keys: list[str] = []
    matched_by_scheme: dict[str, dict[tuple[int, int, str], bool]] = {}

    all_keys = set(server["prefuzzdup"]) | set(base["prefuzzdup"])
    for scheme in workload_by_scheme:
        all_keys |= set(server[scheme]) | set(base[scheme])
    if len(all_keys) != RESULT_KEYS_PER_SCHEME:
        missing_keys.append(f"expected {RESULT_KEYS_PER_SCHEME} unique keys, got {len(all_keys)}")

    for scheme, metrics in workload_by_scheme.items():
        matched_by_scheme[scheme] = {}
        for key in sorted(all_keys):
            server_row = server[scheme].get(key)
            baseline_row = base[scheme].get(key)
            if server_row is None or baseline_row is None:
                missing_keys.append(f"{scheme}:{key}")
                continue
            threshold, repeat, query_id = key
            if scheme == "prefuzzdup":
                matches = int(server_row["candidate_count"]) > 0
                baseline_matches = int(baseline_row["candidate_count"]) > 0
            else:
                matches = server_row["matched"] == "1"
                baseline_matches = baseline_row["matched"] == "1"
            matched_by_scheme[scheme][key] = matches
            row: dict[str, Any] = {
                "scheme": scheme,
                "threshold": threshold,
                "repeat": repeat,
                "query_id": query_id,
                "group": server_row.get("group", ""),
                "matched": int(matches),
                "baseline_matched": int(baseline_matches),
                "matched_match": matches == baseline_matches,
                "server_latency_us": float(server_row["latency_us"]),
                "baseline_latency_us": float(baseline_row["latency_us"]),
            }
            if row["matched_match"]:
                workload_disagreements += 0
            else:
                matched_disagreements += 1
            if row["group"] != baseline_row.get("group", ""):
                group_disagreements += 1
            workload_match = True
            for metric in metrics:
                server_value = int(server_row[metric])
                baseline_value = int(baseline_row[metric])
                metric_match = server_value == baseline_value
                workload_match = workload_match and metric_match
                row[f"server_{metric}"] = server_value
                row[f"baseline_{metric}"] = baseline_value
                row[f"{metric}_match"] = int(metric_match)
                if not metric_match:
                    workload_disagreements += 1
            row["workload_match"] = int(workload_match)
            comparison_rows.append(row)

    cross_scheme_disagreements = 0
    for key in sorted(all_keys):
        values = [matched_by_scheme.get(scheme, {}).get(key) for scheme in ("prefuzzdup", "simless", "fuzzydedup")]
        if any(value is None for value in values) or len(set(values)) != 1:
            cross_scheme_disagreements += 1

    latency_rows: list[dict[str, Any]] = []
    workload_summary_rows: list[dict[str, Any]] = []
    for scheme, metrics in workload_by_scheme.items():
        for threshold in THRESHOLDS:
            keys = {key for key in all_keys if key[0] == threshold}
            server_values = [float(server[scheme][key]["latency_us"]) for key in keys if key in server[scheme]]
            baseline_values = [float(base[scheme][key]["latency_us"]) for key in keys if key in base[scheme]]
            if len(server_values) != BENCHMARK_QUERY_COUNT * REPEAT or len(baseline_values) != BENCHMARK_QUERY_COUNT * REPEAT:
                continue
            latency_rows.append(
                {
                    "scheme": scheme,
                    "threshold": threshold,
                    "samples": len(server_values),
                    "server_mean_us": statistics.fmean(server_values),
                    "server_p50_us": percentile_nearest(server_values, 0.50),
                    "server_p95_us": percentile_nearest(server_values, 0.95),
                    "server_p99_us": percentile_nearest(server_values, 0.99),
                    "baseline_mean_us": statistics.fmean(baseline_values),
                    "baseline_p50_us": percentile_nearest(baseline_values, 0.50),
                    "baseline_p95_us": percentile_nearest(baseline_values, 0.95),
                    "baseline_p99_us": percentile_nearest(baseline_values, 0.99),
                    "mean_delta_us": statistics.fmean(server_values) - statistics.fmean(baseline_values),
                    "mean_ratio": statistics.fmean(server_values) / statistics.fmean(baseline_values),
                }
            )
            for metric in metrics:
                server_metric_values = [int(server[scheme][key][metric]) for key in keys if key in server[scheme]]
                baseline_metric_values = [int(base[scheme][key][metric]) for key in keys if key in base[scheme]]
                if len(server_metric_values) != BENCHMARK_QUERY_COUNT * REPEAT:
                    continue
                workload_summary_rows.append(
                    {
                        "scheme": scheme,
                        "threshold": threshold,
                        "metric": metric,
                        "samples": len(server_metric_values),
                        "server_mean": statistics.fmean(server_metric_values),
                        "baseline_mean": statistics.fmean(baseline_metric_values),
                        "exact_match_rate": sum(a == b for a, b in zip(server_metric_values, baseline_metric_values))
                        / len(server_metric_values),
                    }
                )

    metadata_rows: list[dict[str, Any]] = []
    baseline_manifest = read_json(baseline / "run_manifest.json")
    server_metadata = server_manifest.get("prefuzz_metadata", {})
    baseline_metadata = baseline_manifest.get("prefuzz_metadata", {})
    for threshold in THRESHOLDS:
        for metric in METADATA_METRICS:
            metadata_rows.append(
                {
                    "kind": "metadata",
                    "name": f"prefuzz_t{threshold}.{metric}",
                    "server_value": server_metadata.get(str(threshold), {}).get(metric),
                    "baseline_value": baseline_metadata.get(str(threshold), {}).get(metric),
                }
            )
        metadata_rows.append(
            {
                "kind": "database",
                "name": f"prefuzz_t{threshold}.sqlite_size_bytes",
                "server_value": server_manifest.get("database_files", {}).get(f"prefuzzdup_t{threshold}.sqlite"),
                "baseline_value": baseline_manifest.get("database_files", {}).get(f"prefuzz_t{threshold}.sqlite"),
            }
        )

    require_empty_directory(output, "analysis output")
    comparison_fields = [
        "scheme", "threshold", "repeat", "query_id", "group", "matched", "baseline_matched", "matched_match",
        "workload_match", "server_latency_us", "baseline_latency_us",
    ]
    for scheme, metrics in workload_by_scheme.items():
        comparison_fields.extend(f"server_{metric}" for metric in metrics)
        comparison_fields.extend(f"baseline_{metric}" for metric in metrics)
        comparison_fields.extend(f"{metric}_match" for metric in metrics)
    write_csv(output / "comparison.csv", comparison_fields, comparison_rows)
    write_csv(
        output / "latency_summary.csv",
        list(latency_rows[0]) if latency_rows else ["scheme", "threshold", "samples"],
        latency_rows,
    )
    write_csv(
        output / "workload_summary.csv",
        list(workload_summary_rows[0]) if workload_summary_rows else ["scheme", "threshold", "metric", "samples"],
        workload_summary_rows,
    )
    write_csv(
        output / "metadata_comparison.csv",
        ["kind", "name", "server_value", "baseline_value"],
        metadata_rows,
    )

    passed = not (missing_keys or workload_disagreements or matched_disagreements or group_disagreements or cross_scheme_disagreements)
    lines = [
        "# Three-scheme full handoff analysis",
        "",
        f"- Scale: `{handoff_manifest.get('scale')}`",
        f"- Unique result keys per scheme: `{RESULT_KEYS_PER_SCHEME}`",
        f"- Workload disagreements: `{workload_disagreements}`",
        f"- Server/baseline matched disagreements: `{matched_disagreements}`",
        f"- Cross-scheme matched disagreements: `{cross_scheme_disagreements}`",
        f"- Group disagreements: `{group_disagreements}`",
        f"- Missing keys: `{len(missing_keys)}`",
        f"- Verification: `{server_manifest.get('status')}`",
        "",
        "Git transfer time was not measured. OS page cache was not cleared.",
        "SQLite application cache was approximately 1 MiB. Commands ran in a fixed order.",
        "PreFuzzDup returns all candidates, SimLESS finds the global minimum distance,",
        "and FuzzyDedup returns at its first match; latency is descriptive only.",
    ]
    if missing_keys:
        lines.extend(["", "## Missing Samples", ""])
        lines.extend(f"- {value}" for value in missing_keys[:20])
    (output / "analysis.md").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return passed


def parse_arguments() -> argparse.Namespace:
    repo = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    client = subparsers.add_parser("client", help="create a full three-scheme handoff package")
    client.add_argument("--scale", choices=(SCALE,), required=True)
    client.add_argument("--source", type=Path, required=True)
    client.add_argument("--baseline", type=Path, required=True)
    client.add_argument("--dest", type=Path, required=True)
    client.add_argument("--repo", type=Path, default=repo)

    server = subparsers.add_parser("server", help="verify and execute a handoff package")
    server.add_argument("--package", type=Path, required=True)
    server.add_argument("--scratch", type=Path, required=True)
    server.add_argument("--repo", type=Path, default=repo)

    analyze = subparsers.add_parser("analyze", help="compare server results with the local full baseline")
    analyze.add_argument("--package", type=Path, required=True)
    analyze.add_argument("--baseline", type=Path, required=True)
    analyze.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        if arguments.command == "client":
            if arguments.scale != SCALE:
                fail(f"unsupported scale: {arguments.scale}")
            manifest = create_client_package(
                arguments.source.resolve(),
                arguments.dest.resolve(),
                arguments.baseline.resolve(),
                arguments.repo.resolve(),
            )
            print(f"handoff package complete: {arguments.dest}")
            print(f"source git commit: {manifest['source_git_commit']}")
        elif arguments.command == "server":
            run_server(arguments.package.resolve(), arguments.scratch.resolve(), arguments.repo.resolve())
            print("server handoff complete")
        else:
            passed = analyze_results(
                arguments.package.resolve(), arguments.baseline.resolve(), arguments.output.resolve()
            )
            print(f"analysis complete: {arguments.output}")
            if not passed:
                print("analysis found workload or matched disagreements", file=sys.stderr)
                return 2
        return 0
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def result_key(row: dict[str, str]) -> tuple[int, int, str]:
    return int(row["threshold"]), int(row["repeat"]), row["query_id"]


def check_cross_scheme(
    prefuzz_rows: list[dict[str, str]],
    simless_rows: list[dict[str, str]],
    fuzzydedup_rows: list[dict[str, str]],
) -> None:
    def matched(rows: list[dict[str, str]], candidate_mode: bool) -> dict[tuple[int, int, str], bool]:
        result: dict[tuple[int, int, str], bool] = {}
        for row in rows:
            key = result_key(row)
            if key in result:
                fail(f"duplicate benchmark result key: {key}")
            result[key] = int(row["candidate_count"]) > 0 if candidate_mode else row["matched"] == "1"
        return result

    prefuzz_matches = matched(prefuzz_rows, True)
    simless_matches = matched(simless_rows, False)
    fuzzydedup_matches = matched(fuzzydedup_rows, False)
    keys = prefuzz_matches.keys() | simless_matches.keys() | fuzzydedup_matches.keys()
    if len(keys) != RESULT_KEYS_PER_SCHEME:
        fail(f"expected {RESULT_KEYS_PER_SCHEME} cross-scheme keys, got {len(keys)}")
    disagreements = [
        key
        for key in keys
        if prefuzz_matches.get(key) != simless_matches.get(key) or prefuzz_matches.get(key) != fuzzydedup_matches.get(key)
    ]
    if disagreements:
        sample = ", ".join(str(key) for key in sorted(disagreements)[:5])
        fail(f"cross-scheme matched disagreements: {len(disagreements)}; sample: {sample}")


def run_server(package: Path, scratch: Path, repo: Path) -> None:
    manifest = verify_package(package)
    results = package / "results"
    require_empty_directory(results, "results")
    logs = results / "logs"
    scratch = scratch.resolve()
    if scratch.as_posix().startswith("/mnt/"):
        fail(f"scratch must use a native Linux filesystem, not /mnt: {scratch}")
    scratch.mkdir(parents=True, exist_ok=True)

    commands: list[dict[str, Any]] = []
    metadata: dict[str, dict[str, Any]] = {}
    failure: str | None = None
    try:
        prefuzz = build_project(repo, "PreFuzzDup", "prefuzzdup_persistent_lookup", logs, commands)
        simless = build_project(repo, "SimLESS", "simless_lookup_benchmark", logs, commands)
        fuzzydedup = build_project(repo, "FuzzyDedup", "fuzzydedup_lookup_benchmark", logs, commands)

        inputs = package / "inputs"
        reference_rows = read_csv(inputs / "reference.csv")
        benchmark_rows = read_csv(inputs / "queries_bench_1000.csv")
        verify_rows = read_csv(inputs / "queries_verify_100.csv")
        reference_ids = {row["id"] for row in reference_rows}
        benchmark_ids = {row["id"] for row in benchmark_rows}
        verify_ids = {row["id"] for row in verify_rows}
        benchmark_groups = validate_group_csv(
            inputs / "query_groups_bench_1000.csv", benchmark_rows, {"exact_ref", "no_exact_ref"}
        )

        verify_command = prefuzz_command(
            prefuzz,
            inputs / "reference.csv",
            inputs / "queries_verify_100.csv",
            scratch / "prefuzzdup_verify.sqlite",
            results / "prefuzzdup_verify.csv",
            threshold=6,
            repeat=1,
            verify=True,
        )
        completed = run_logged(logs / "prefuzzdup-verify.log", verify_command, repo, "prefuzzdup_verify", commands)
        if "equivalence_check=passed" not in completed.stdout:
            fail("PreFuzzDup equivalence check did not pass")
        validate_prefuzz_csv(results / "prefuzzdup_verify.csv", VERIFY_QUERY_COUNT, 6, verify_ids)

        prefuzz_rows: list[dict[str, str]] = []
        for threshold in THRESHOLDS:
            output = results / f"prefuzzdup_t{threshold}.csv"
            command = prefuzz_command(
                prefuzz,
                inputs / "reference.csv",
                inputs / "queries_bench_1000.csv",
                scratch / f"prefuzzdup_t{threshold}.sqlite",
                output,
                threshold=threshold,
                repeat=REPEAT,
            )
            completed = run_logged(logs / f"prefuzzdup-t{threshold}.log", command, repo, f"prefuzzdup_t{threshold}", commands)
            metadata[str(threshold)] = parse_prefuzz_metadata(completed.stdout)
            prefuzz_rows.extend(validate_prefuzz_csv(output, BENCHMARK_QUERY_COUNT * REPEAT, threshold, benchmark_ids))

        simless_verify = comparative_command(
            simless,
            "simless",
            inputs / "reference.csv",
            inputs / "queries_verify_100.csv",
            inputs / "query_groups_verify_100.csv",
            scratch / "simless_verify.sqlite",
            results / "simless_verify.csv",
            repeat=1,
        )
        run_logged(logs / "simless-verify.log", simless_verify, repo, "simless_verify", commands)
        validate_comparative_csv(
            results / "simless_verify.csv",
            "simless",
            VERIFY_QUERY_COUNT * len(THRESHOLDS),
            1,
            verify_ids,
            {"verify"},
            len(reference_rows),
        )

        simless_bench = comparative_command(
            simless,
            "simless",
            inputs / "reference.csv",
            inputs / "queries_bench_1000.csv",
            inputs / "query_groups_bench_1000.csv",
            scratch / "simless_bench.sqlite",
            results / "simless_bench.csv",
            repeat=REPEAT,
        )
        run_logged(logs / "simless-bench.log", simless_bench, repo, "simless_bench", commands)
        simless_rows = validate_comparative_csv(
            results / "simless_bench.csv",
            "simless",
            RESULT_ROWS_PER_SCHEME,
            REPEAT,
            benchmark_ids,
            set(benchmark_groups.values()),
            len(reference_rows),
        )

        fuzzydedup_verify = comparative_command(
            fuzzydedup,
            "fuzzydedup",
            inputs / "reference.csv",
            inputs / "queries_verify_100.csv",
            inputs / "query_groups_verify_100.csv",
            scratch / "fuzzydedup_verify.sqlite",
            results / "fuzzydedup_verify.csv",
            repeat=1,
        )
        run_logged(logs / "fuzzydedup-verify.log", fuzzydedup_verify, repo, "fuzzydedup_verify", commands)
        validate_comparative_csv(
            results / "fuzzydedup_verify.csv",
            "fuzzydedup",
            VERIFY_QUERY_COUNT * len(THRESHOLDS),
            1,
            verify_ids,
            {"verify"},
            len(reference_rows),
        )

        fuzzydedup_bench = comparative_command(
            fuzzydedup,
            "fuzzydedup",
            inputs / "reference.csv",
            inputs / "queries_bench_1000.csv",
            inputs / "query_groups_bench_1000.csv",
            scratch / "fuzzydedup_bench.sqlite",
            results / "fuzzydedup_bench.csv",
            repeat=REPEAT,
        )
        run_logged(logs / "fuzzydedup-bench.log", fuzzydedup_bench, repo, "fuzzydedup_bench", commands)
        fuzzydedup_rows = validate_comparative_csv(
            results / "fuzzydedup_bench.csv",
            "fuzzydedup",
            RESULT_ROWS_PER_SCHEME,
            REPEAT,
            benchmark_ids,
            set(benchmark_groups.values()),
            len(reference_rows),
        )
        check_cross_scheme(prefuzz_rows, simless_rows, fuzzydedup_rows)

        environment = collect_environment(repo)
        write_json(results / "environment.json", environment)
        (results / "README.md").write_text(
            "Full three-scheme server lookup results. Keep logs and manifests with these CSVs;\n"
            "scratch SQLite files remain on the server and are not part of the handoff.\n",
            encoding="utf-8",
            newline="\n",
        )
    except Exception as error:
        failure = str(error)
        raise
    finally:
        database_files = {
            path.name: path.stat().st_size
            for path in sorted(scratch.glob("*.sqlite"))
            if path.exists()
        }
        result_manifest = {
            "schema_version": 1,
            "package_type": "three_scheme_lookup_handoff_result",
            "status": "failed" if failure else "passed",
            "failure": failure,
            "created_utc": utc_now(),
            "scale": SCALE,
            "source_handoff_manifest_sha256": sha256_file(package / "handoff-manifest.json"),
            "server_git_commit": git_commit(repo),
            "thresholds": list(THRESHOLDS),
            "repeat": REPEAT,
            "expected_result_rows_per_scheme": RESULT_ROWS_PER_SCHEME,
            "prefuzz_metadata": metadata,
            "database_files": database_files,
            "commands": commands,
            "environment": collect_environment(repo),
            "notes": [
                "Git transfer time was not measured.",
                "OS page cache was not cleared.",
                "SQLite application page cache is approximately 1 MiB.",
                "Commands ran in the fixed order recorded in commands.",
                "Latency differences are descriptive; workload equality is required.",
            ],
        }
        if results.exists():
            result_manifest["result_files"] = file_inventory(results, results / "server-result-manifest.json")
        write_json(results / "server-result-manifest.json", result_manifest)


if __name__ == "__main__":
    raise SystemExit(main())
