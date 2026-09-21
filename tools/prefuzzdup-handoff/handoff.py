#!/usr/bin/env python3
"""Package, execute, and analyze PreFuzzDup lookup handoff experiments."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import platform
import re
import shlex
import shutil
import statistics
import subprocess
import sys
import unittest
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence


INPUT_FILES = (
    "reference.csv",
    "queries_bench_1000.csv",
    "queries_verify_100.csv",
    "split_summary.json",
)
THRESHOLDS = (4, 5, 6)
REPEAT = 3
FPP = "0.01"
TAG_BITS = 256
BENCHMARK_QUERY_COUNT = 1_000
VERIFY_QUERY_COUNT = 100
SCALE_COUNTS = {
    "5w": {"total_records": 51_740, "reference_count": 41_392},
    "full": {"total_records": 517_401, "reference_count": 413_921},
}
LOOKUP_HEADER = [
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
WORKLOAD_METRICS = (
    "candidate_count",
    "filter_queries",
    "inverted_lookups",
    "posting_records_read",
    "full_tag_distance_computations",
)
METADATA_METRICS = (
    "index_prepare_us",
    "disk_index_reused",
    "filter_bytes_estimate",
    "sqlite_cache_kib",
)


def fail(message: str) -> None:
    raise RuntimeError(message)


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
        writer = csv.DictWriter(
            target,
            fieldnames=list(fieldnames),
            lineterminator="\n",
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(rows)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def git_commit(repo: Path) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        return "unknown"
    return completed.stdout.strip()


def require_empty_output(path: Path, label: str) -> None:
    if path.exists() and any(path.iterdir()):
        fail(f"{label} already exists and is not empty: {path}")


def validate_tag_csv(path: Path, expected_count: int) -> None:
    rows = read_csv(path)
    if rows and list(rows[0]) != ["id", "type", "tag_hex"]:
        fail(f"unexpected CSV header: {path}")
    if len(rows) != expected_count:
        fail(f"expected {expected_count} rows in {path}, got {len(rows)}")
    ids = {row["id"] for row in rows}
    if len(ids) != len(rows):
        fail(f"duplicate query/reference IDs: {path}")
    for row in rows:
        tag = row["tag_hex"]
        if row["type"] != "text":
            fail(f"non-text tag in {path}: {row['id']}")
        if len(tag) != TAG_BITS // 4 or any(c not in "0123456789abcdef" for c in tag):
            fail(f"invalid {TAG_BITS}-bit tag in {path}: {row['id']}")


def validate_client_inputs(source: Path, scale: str) -> dict[str, Any]:
    for name in INPUT_FILES:
        if not (source / name).is_file():
            fail(f"missing handoff input: {source / name}")

    split = read_json(source / "split_summary.json")
    expected = SCALE_COUNTS[scale]
    expected_split = {
        **expected,
        "benchmark_count": BENCHMARK_QUERY_COUNT,
        "verify_count": VERIFY_QUERY_COUNT,
    }
    for key, value in expected_split.items():
        if split.get(key) != value:
            fail(f"split_summary {key} is {split.get(key)!r}, expected {value!r}")

    validate_tag_csv(source / "reference.csv", expected["reference_count"])
    validate_tag_csv(source / "queries_bench_1000.csv", BENCHMARK_QUERY_COUNT)
    validate_tag_csv(source / "queries_verify_100.csv", VERIFY_QUERY_COUNT)
    return split


def package_readme(scale: str, package_name: str, scratch_name: str) -> str:
    return f"""# PreFuzzDup {scale} lookup handoff

This package contains only the tags required to reproduce the PreFuzzDup
persistent lookup benchmark. It does not contain Enron messages, bodies,
SQLite databases, ciphertext, or private keys.

## Server execution

From the repository root:

```bash
python3 tools/prefuzzdup-handoff/handoff.py server \\
  --package {package_name} \\
  --scratch "$HOME/{scratch_name}"
```

The command verifies input hashes, builds the Release binary, runs the
100-query equivalence check, and then runs thresholds 4, 5, and 6 with 3
repeats each. Results and logs are written under `{package_name}/results/`.

After a successful run, commit and push the `results/` directory on this
handoff branch. This offline batch experiment does not measure network
communication or the complete upload protocol.
"""


def create_client_package(scale: str, source: Path, destination: Path, repo: Path) -> None:
    if scale not in SCALE_COUNTS:
        fail(f"unsupported scale: {scale}")
    require_empty_output(destination, "destination")
    split = validate_client_inputs(source, scale)

    inputs_dir = destination / "inputs"
    inputs_dir.mkdir(parents=True)
    input_records: dict[str, dict[str, Any]] = {}
    for name in INPUT_FILES:
        target = inputs_dir / name
        shutil.copy2(source / name, target)
        input_records[name] = {
            "sha256": sha256_file(target),
            "size_bytes": target.stat().st_size,
        }

    expected_outputs = ["results/prefuzz_verify.csv"]
    expected_outputs.extend(f"results/prefuzz_t{threshold}.csv" for threshold in THRESHOLDS)
    manifest = {
        "schema_version": 1,
        "package_type": "prefuzzdup_lookup_handoff",
        "scale": scale,
        "created_utc": utc_now(),
        "source_git_commit": git_commit(repo),
        "source_experiment": f"results-local/enron-{scale}/lookup-experiment/inputs",
        "thresholds": list(THRESHOLDS),
        "repeat": REPEAT,
        "fpp": FPP,
        "tag_bits": TAG_BITS,
        "expected_rows_per_threshold": BENCHMARK_QUERY_COUNT * REPEAT,
        "expected_verify_rows": VERIFY_QUERY_COUNT,
        "expected_outputs": expected_outputs,
        "inputs": input_records,
        "split_summary": split,
    }
    write_json(destination / "handoff-manifest.json", manifest)
    package_name = destination.as_posix().replace("\\", "/")
    (destination / "README.md").write_text(
        package_readme(scale, package_name, f"prefuzzdup-{scale}-scratch"),
        encoding="utf-8",
        newline="\n",
    )


def verify_package(package: Path) -> dict[str, Any]:
    manifest_path = package / "handoff-manifest.json"
    if not manifest_path.is_file():
        fail(f"missing handoff manifest: {manifest_path}")
    manifest = read_json(manifest_path)
    if manifest.get("package_type") != "prefuzzdup_lookup_handoff":
        fail("unsupported handoff package type")
    if manifest.get("schema_version") != 1:
        fail("unsupported handoff schema version")
    scale = str(manifest.get("scale"))
    if scale not in SCALE_COUNTS:
        fail(f"unsupported package scale: {scale}")
    if manifest.get("thresholds") != list(THRESHOLDS):
        fail("handoff thresholds must be [4, 5, 6]")
    if manifest.get("repeat") != REPEAT or manifest.get("fpp") != FPP:
        fail("handoff repeat or fpp does not match the fixed experiment")
    if manifest.get("tag_bits") != TAG_BITS:
        fail("handoff tag bits must be 256")

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

    validate_client_inputs(package / "inputs", scale)
    return manifest


def log_command(path: Path, command: Sequence[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    path.parent.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        list(command),
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )
    with path.open("w", encoding="utf-8", newline="\n") as target:
        target.write("$ " + shlex.join(command) + "\n")
        target.write(f"cwd: {cwd}\n\n")
        target.write("[stdout]\n")
        target.write(completed.stdout)
        target.write("\n[stderr]\n")
        target.write(completed.stderr)
        target.write(f"\n[exit-code] {completed.returncode}\n")
    if completed.returncode != 0:
        fail(f"command failed with exit code {completed.returncode}; log: {path}")
    return completed


def lookup_command(
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
        key = key.strip()
        value = value.strip()
        if re.fullmatch(r"-?\d+", value):
            result[key] = int(value)
        elif re.fullmatch(r"-?(?:\d+\.\d*|\d*\.\d+)", value):
            result[key] = float(value)
        else:
            result[key] = value
    required = {"records", "tag_bits", *METADATA_METRICS}
    if not required.issubset(result):
        fail(f"PreFuzzDup metadata is incomplete: {line}")
    return result


def validate_lookup_output(path: Path, expected_rows: int, threshold: int) -> list[dict[str, str]]:
    rows = read_csv(path)
    if not rows or list(rows[0]) != LOOKUP_HEADER:
        fail(f"unexpected lookup output header: {path}")
    if len(rows) != expected_rows:
        fail(f"expected {expected_rows} rows in {path}, got {len(rows)}")
    for row in rows:
        if row["strategy"] != "prefuzz" or row["type"] != "text":
            fail(f"unexpected strategy or type in {path}")
        if int(row["repeat"]) < 0 or int(row["repeat"]) >= REPEAT:
            fail(f"repeat outside the fixed range in {path}")
        if int(row["latency_us"]) < 0:
            fail(f"negative latency in {path}")
        if any(int(row[metric]) < 0 for metric in WORKLOAD_METRICS):
            fail(f"negative workload metric in {path}")
        if int(row["filter_queries"]) != threshold + 1:
            fail(f"unexpected filter query count in {path}: {row['filter_queries']}")
    return rows


def first_line(command: Sequence[str], cwd: Path) -> str:
    try:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            text=True,
            capture_output=True,
            check=True,
        )
        return completed.stdout.splitlines()[0] if completed.stdout else ""
    except (OSError, subprocess.CalledProcessError, IndexError):
        return ""


def read_first_match(path: Path, pattern: str) -> str:
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            match = re.search(pattern, line)
            if match:
                return match.group(1)
    except OSError:
        pass
    return ""


def collect_environment(repo: Path) -> dict[str, Any]:
    cpu_model = read_first_match(Path("/proc/cpuinfo"), r"^model name\s*:\s*(.+)$")
    memory_total = read_first_match(Path("/proc/meminfo"), r"^MemTotal:\s*(.+)$")
    return {
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": sys.version,
        "uname": first_line(["uname", "-a"], repo),
        "compiler": first_line(["c++", "--version"], repo),
        "sqlite_package": first_line(["pkg-config", "--modversion", "sqlite3"], repo),
        "cpu_model": cpu_model,
        "memory_total": memory_total,
        "page_cache_cleared": False,
        "sqlite_application_cache_kib": 1024,
    }


def file_inventory(root: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            result[path.relative_to(root).as_posix()] = {
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
    return result


def run_server(package: Path, scratch: Path, repo: Path) -> None:
    manifest = verify_package(package)
    results = package / "results"
    require_empty_output(results, "results")
    logs = results / "logs"
    results.mkdir(parents=True)
    logs.mkdir()
    scratch.mkdir(parents=True, exist_ok=True)

    commands: list[dict[str, Any]] = []
    metadata: dict[str, dict[str, Any]] = {}
    database_files: dict[str, int] = {}
    failure: str | None = None
    try:
        build_source = repo / "PreFuzzDup"
        build_dir = build_source / "build"
        configure = ["cmake", "-S", build_source.as_posix(), "-B", build_dir.as_posix(),
                     "-DCMAKE_BUILD_TYPE=Release"]
        build = ["cmake", "--build", build_dir.as_posix(), "-j"]
        log_command(logs / "build-configure.log", configure, repo)
        log_command(logs / "build.log", build, repo)
        commands.extend(
            {"phase": name, "command": command}
            for name, command in (("configure", configure), ("build", build))
        )

        binary = build_dir / "prefuzzdup_persistent_lookup"
        if not binary.is_file():
            fail(f"lookup binary was not produced: {binary}")
        inputs = package / "inputs"

        verify_command = lookup_command(
            binary,
            inputs / "reference.csv",
            inputs / "queries_verify_100.csv",
            scratch / "prefuzz_verify.sqlite",
            results / "prefuzz_verify.csv",
            threshold=6,
            repeat=1,
            verify=True,
        )
        verify_completed = log_command(logs / "prefuzz_verify.log", verify_command, repo)
        commands.append({"phase": "verify", "command": verify_command})
        if "equivalence_check=passed" not in verify_completed.stdout:
            fail("PreFuzzDup equivalence check did not pass")
        validate_lookup_output(results / "prefuzz_verify.csv", VERIFY_QUERY_COUNT, 6)

        for threshold in THRESHOLDS:
            output = results / f"prefuzz_t{threshold}.csv"
            command = lookup_command(
                binary,
                inputs / "reference.csv",
                inputs / "queries_bench_1000.csv",
                scratch / f"prefuzz_t{threshold}.sqlite",
                output,
                threshold=threshold,
                repeat=REPEAT,
            )
            completed = log_command(logs / f"prefuzz_t{threshold}.log", command, repo)
            commands.append({"phase": f"benchmark_t{threshold}", "command": command})
            metadata[str(threshold)] = parse_prefuzz_metadata(completed.stdout)
            validate_lookup_output(output, BENCHMARK_QUERY_COUNT * REPEAT, threshold)

        for path in sorted(scratch.glob("prefuzz*.sqlite*")):
            database_files[path.name] = path.stat().st_size
        environment = collect_environment(repo)
        write_json(results / "environment.json", environment)
        (results / "README.md").write_text(
            "PreFuzzDup server lookup results. Keep this directory with the logs and manifests;\n"
            "the scratch SQLite files remain on the server and are not part of the handoff.\n",
            encoding="utf-8",
            newline="\n",
        )
    except Exception as error:
        failure = str(error)
        raise
    finally:
        result_manifest = {
            "schema_version": 1,
            "package_type": "prefuzzdup_lookup_handoff_result",
            "status": "failed" if failure else "passed",
            "failure": failure,
            "created_utc": utc_now(),
            "scale": manifest["scale"],
            "source_handoff_manifest_sha256": sha256_file(package / "handoff-manifest.json"),
            "server_git_commit": git_commit(repo),
            "thresholds": list(THRESHOLDS),
            "repeat": REPEAT,
            "fpp": FPP,
            "tag_bits": TAG_BITS,
            "prefuzz_metadata": metadata,
            "database_files": database_files,
            "commands": commands,
            "files": file_inventory(results),
            "notes": [
                "Offline batch handoff; no client-server network latency was measured.",
                "The OS page cache was not cleared.",
                "SQLite application cache is approximately 1 MiB.",
                "Thresholds ran in the fixed order 4, 5, 6.",
            ],
        }
        write_json(results / "server-result-manifest.json", result_manifest)


def load_result_rows(results: Path) -> dict[tuple[str, int, int], dict[str, str]]:
    rows: dict[tuple[str, int, int], dict[str, str]] = {}
    for threshold in THRESHOLDS:
        for row in read_csv(results / f"prefuzz_t{threshold}.csv"):
            key = (row["query_id"], threshold, int(row["repeat"]))
            if key in rows:
                fail(f"duplicate result key: {key}")
            rows[key] = row
    return rows


def nearest_percentile(values: Sequence[float], quantile: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * quantile) - 1))
    return ordered[index]


def numeric_summary(values: Sequence[float]) -> dict[str, float]:
    numeric = [float(value) for value in values]
    return {
        "mean": statistics.fmean(numeric),
        "p50": nearest_percentile(numeric, 0.50),
        "p95": nearest_percentile(numeric, 0.95),
        "p99": nearest_percentile(numeric, 0.99),
    }


def verify_analysis_inputs(package: Path, baseline: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    handoff = verify_package(package)
    result_path = package / "results" / "server-result-manifest.json"
    result_manifest = read_json(result_path)
    if result_manifest.get("status") != "passed":
        fail("server result manifest does not have status=passed")
    if not (baseline / "run_manifest.json").is_file():
        fail(f"missing baseline run manifest: {baseline / 'run_manifest.json'}")
    baseline_manifest = read_json(baseline / "run_manifest.json")

    for name in INPUT_FILES:
        baseline_path = baseline / "inputs" / name
        if not baseline_path.is_file():
            fail(f"missing baseline input: {baseline_path}")
        if sha256_file(baseline_path) != handoff["inputs"][name]["sha256"]:
            fail(f"baseline and handoff input differ: {name}")
    return handoff, result_manifest, baseline_manifest


def analyze_results(package: Path, baseline: Path, output: Path) -> bool:
    handoff, server_manifest, baseline_manifest = verify_analysis_inputs(package, baseline)
    require_empty_output(output, "analysis output")
    output.mkdir(parents=True)
    server_rows = load_result_rows(package / "results")
    baseline_rows = load_result_rows(baseline / "raw")
    expected = BENCHMARK_QUERY_COUNT * REPEAT * len(THRESHOLDS)
    if len(server_rows) != expected or set(server_rows) != set(baseline_rows):
        fail(
            "server and baseline result keys differ; "
            f"server={len(server_rows)}, baseline={len(baseline_rows)}, expected={expected}"
        )

    comparison_rows: list[dict[str, Any]] = []
    disagreements = 0
    for key in sorted(server_rows):
        server = server_rows[key]
        base = baseline_rows[key]
        candidate_match = int(server["candidate_count"]) == int(base["candidate_count"])
        workload_match = candidate_match and all(
            int(server[metric]) == int(base[metric]) for metric in WORKLOAD_METRICS[1:]
        )
        if not workload_match:
            disagreements += 1
        row: dict[str, Any] = {
            "threshold": key[1],
            "query_id": key[0],
            "repeat": key[2],
            "server_matched": int(int(server["candidate_count"]) > 0),
            "baseline_matched": int(int(base["candidate_count"]) > 0),
            "candidate_match": int(candidate_match),
            "workload_match": int(workload_match),
        }
        for metric in ("latency_us", *WORKLOAD_METRICS):
            row[f"server_{metric}"] = int(server[metric])
            row[f"baseline_{metric}"] = int(base[metric])
            if metric != "latency_us":
                row[f"{metric}_delta"] = int(server[metric]) - int(base[metric])
        comparison_rows.append(row)
    write_csv(
        output / "comparison.csv",
        [
            "threshold", "query_id", "repeat", "server_matched", "baseline_matched",
            "candidate_match", "workload_match", "server_latency_us", "baseline_latency_us",
            *[f"{metric}_{suffix}" for metric in WORKLOAD_METRICS for suffix in ("server", "baseline", "delta")],
        ],
        comparison_rows,
    )

    latency_rows: list[dict[str, Any]] = []
    workload_rows: list[dict[str, Any]] = []
    metadata_rows: list[dict[str, Any]] = []
    for threshold in THRESHOLDS:
        keys = [key for key in server_rows if key[1] == threshold]
        server_latency = numeric_summary([server_rows[key]["latency_us"] for key in keys])
        baseline_latency = numeric_summary([baseline_rows[key]["latency_us"] for key in keys])
        latency_rows.append(
            {
                "threshold": threshold,
                "samples": len(keys),
                **{f"server_{name}": value for name, value in server_latency.items()},
                **{f"baseline_{name}": value for name, value in baseline_latency.items()},
                "mean_delta_us": server_latency["mean"] - baseline_latency["mean"],
                "mean_ratio": server_latency["mean"] / baseline_latency["mean"],
            }
        )
        for metric in WORKLOAD_METRICS:
            server_values = [int(server_rows[key][metric]) for key in keys]
            baseline_values = [int(baseline_rows[key][metric]) for key in keys]
            workload_rows.append(
                {
                    "threshold": threshold,
                    "metric": metric,
                    "samples": len(keys),
                    "server_mean": statistics.fmean(server_values),
                    "baseline_mean": statistics.fmean(baseline_values),
                    "exact_match_rate": sum(a == b for a, b in zip(server_values, baseline_values)) / len(keys),
                }
            )
        server_meta = server_manifest["prefuzz_metadata"][str(threshold)]
        baseline_meta = baseline_manifest["prefuzz_metadata"][str(threshold)]
        for metric in METADATA_METRICS:
            metadata_rows.append(
                {
                    "threshold": threshold,
                    "metric": metric,
                    "server_value": server_meta.get(metric),
                    "baseline_value": baseline_meta.get(metric),
                }
            )
        database_metric = f"prefuzz_t{threshold}.sqlite_size_bytes"
        metadata_rows.append(
            {
                "threshold": threshold,
                "metric": database_metric,
                "server_value": server_manifest.get("database_files", {}).get(
                    f"prefuzz_t{threshold}.sqlite"
                ),
                "baseline_value": baseline_manifest.get("database_files", {}).get(
                    f"prefuzz_t{threshold}.sqlite"
                ),
            }
        )
    write_csv(
        output / "latency_summary.csv",
        [
            "threshold", "samples", "server_mean", "server_p50", "server_p95", "server_p99",
            "baseline_mean", "baseline_p50", "baseline_p95", "baseline_p99",
            "mean_delta_us", "mean_ratio",
        ],
        latency_rows,
    )
    write_csv(
        output / "workload_summary.csv",
        ["threshold", "metric", "samples", "server_mean", "baseline_mean", "exact_match_rate"],
        workload_rows,
    )
    write_csv(
        output / "metadata_comparison.csv",
        ["threshold", "metric", "server_value", "baseline_value"],
        metadata_rows,
    )

    passed = disagreements == 0
    lines = [
        "# PreFuzzDup handoff analysis",
        "",
        f"- Scale: `{handoff['scale']}`",
        f"- Result keys: `{len(server_rows)}`",
        f"- Workload disagreements: `{disagreements}`",
        f"- Verification: `{'passed' if passed else 'failed'}`",
        "",
        "Latency differences are descriptive. Workload counts must match exactly because the",
        "input tags, threshold, and lookup algorithm are fixed. Index preparation and disk",
        "reuse are compared in `metadata_comparison.csv`.",
        "",
    ]
    if not passed:
        lines.append("The returned server results must not be used as a baseline until mismatches are resolved.")
    (output / "analysis.md").write_text("\n".join(lines), encoding="utf-8", newline="\n")
    return passed


def parse_arguments() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    repo = script_dir.parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    client = subparsers.add_parser("client", help="create a lookup handoff package")
    client.add_argument("--scale", choices=sorted(SCALE_COUNTS), required=True)
    client.add_argument("--source", type=Path, required=True)
    client.add_argument("--dest", type=Path, required=True)
    client.add_argument("--repo", type=Path, default=repo)

    server = subparsers.add_parser("server", help="verify and execute a handoff package")
    server.add_argument("--package", type=Path, required=True)
    server.add_argument("--scratch", type=Path, required=True)
    server.add_argument("--repo", type=Path, default=repo)

    analyze = subparsers.add_parser("analyze", help="compare returned server results with local baseline")
    analyze.add_argument("--package", type=Path, required=True)
    analyze.add_argument("--baseline", type=Path, required=True)
    analyze.add_argument("--output", type=Path)
    analyze.add_argument("--repo", type=Path, default=repo)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        if arguments.command == "client":
            create_client_package(
                arguments.scale,
                arguments.source.resolve(),
                arguments.dest.resolve(),
                arguments.repo.resolve(),
            )
        elif arguments.command == "server":
            run_server(
                arguments.package.resolve(),
                arguments.scratch.resolve(),
                arguments.repo.resolve(),
            )
        else:
            output = arguments.output
            if output is None:
                handoff = read_json(arguments.package.resolve() / "handoff-manifest.json")
                output = (
                    arguments.repo
                    / "results-local"
                    / "prefuzzdup-handoff"
                    / f"enron-{handoff['scale']}"
                )
            passed = analyze_results(
                arguments.package.resolve(),
                arguments.baseline.resolve(),
                output.resolve(),
            )
            if not passed:
                fail("server and baseline workload results disagree")
        return 0
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
