#!/usr/bin/env python3
"""Run the 5wTest persistent lookup comparison and produce audited artifacts."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import random
import shutil
import statistics
import subprocess
import sys
import time
import unittest
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


THRESHOLDS = (4, 5, 6)
QUERY_POOL_SIZE = 10_348
BENCHMARK_QUERY_COUNT = 1_000
VERIFY_PER_GROUP = 50
SPLIT_SEED = 20_260_921
SAMPLE_SEED = 20_260_922
FPP = 0.01


def fail(message: str) -> None:
    raise RuntimeError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def prefuzz_threshold_argument(threshold: int) -> str:
    """The lookup CLI requires a default even when all records have type text."""
    return f"default={threshold}"


def largest_remainder_allocation(counts: dict[str, int], total: int) -> dict[str, int]:
    """Allocate exactly total seats proportionally, breaking ties by group name."""
    if total < 0:
        raise ValueError("total must be non-negative")
    if any(value < 0 for value in counts.values()):
        raise ValueError("counts must be non-negative")
    population = sum(counts.values())
    if population == 0:
        raise ValueError("cannot allocate an empty population")

    raw = {name: total * value / population for name, value in counts.items()}
    result = {name: int(value) for name, value in raw.items()}
    remaining = total - sum(result.values())
    order = sorted(counts, key=lambda name: (-(raw[name] - result[name]), name))
    for name in order[:remaining]:
        result[name] += 1
    return result


def select_stratified(
    records: list[dict[str, str]],
    reference_hashes: set[str],
    benchmark_count: int,
    seed: int,
    verify_per_group: int,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for record in records:
        group = "exact_ref" if record["body_sha256"] in reference_hashes else "no_exact_ref"
        grouped[group].append(record)

    allocation = largest_remainder_allocation(
        {name: len(values) for name, values in grouped.items()}, benchmark_count
    )
    rng = random.Random(seed)
    benchmark: list[dict[str, str]] = []
    verify: list[dict[str, str]] = []
    for group in sorted(grouped):
        members = sorted(grouped[group], key=lambda item: item["id"])
        if allocation[group] > len(members):
            raise ValueError(f"not enough {group} records for benchmark sample")
        benchmark.extend(rng.sample(members, allocation[group]))
        if verify_per_group > len(members):
            raise ValueError(f"not enough {group} records for verify sample")
        for record in rng.sample(members, verify_per_group):
            verify.append({**record, "group": group})

    benchmark.sort(key=lambda item: item["id"])
    verify.sort(key=lambda item: item["id"])
    return benchmark, verify


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as source:
        return list(csv.DictReader(source))


def load_prefuzz_rows(raw_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for threshold in THRESHOLDS:
        for row in read_csv(raw_dir / f"prefuzz_t{threshold}.csv"):
            row["threshold"] = threshold
            rows.append(row)
    return rows


def write_csv(path: Path, fieldnames: list[str], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as target:
        writer = csv.DictWriter(target, fieldnames=fieldnames, lineterminator="\n", extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def load_dataset(dataset_dir: Path) -> list[dict[str, str]]:
    manifest_path = dataset_dir / "manifest.csv"
    tags_path = dataset_dir / "tags.csv"
    manifest = read_csv(manifest_path)
    tags = read_csv(tags_path)
    if len(manifest) != 51_740 or len(tags) != 51_740:
        fail(f"expected 51740 rows, got manifest={len(manifest)}, tags={len(tags)}")

    manifest_by_id = {row["id"]: row for row in manifest}
    tags_by_id = {row["id"]: row for row in tags}
    if len(manifest_by_id) != len(manifest) or len(tags_by_id) != len(tags):
        fail("dataset contains duplicate IDs")
    if set(manifest_by_id) != set(tags_by_id):
        fail("manifest and tags IDs differ")

    records: list[dict[str, str]] = []
    for record_id in sorted(tags_by_id):
        tag_row = tags_by_id[record_id]
        manifest_row = manifest_by_id[record_id]
        tag = tag_row["tag_hex"]
        if tag_row["type"] != "text" or manifest_row["id"] != record_id:
            fail(f"invalid dataset row: {record_id}")
        if len(tag) != 64 or any(character not in "0123456789abcdef" for character in tag):
            fail(f"invalid 256-bit tag: {record_id}")
        records.append(
            {
                "id": record_id,
                "type": "text",
                "tag_hex": tag,
                "body_sha256": manifest_row["body_sha256"],
            }
        )
    return records


def prepare_inputs(dataset_dir: Path, output_dir: Path) -> dict[str, Any]:
    records = load_dataset(dataset_dir)
    query_ids = set(random.Random(SPLIT_SEED).sample(sorted(row["id"] for row in records), QUERY_POOL_SIZE))
    reference = [row for row in records if row["id"] not in query_ids]
    query_pool = [row for row in records if row["id"] in query_ids]
    reference.sort(key=lambda row: row["id"])
    query_pool.sort(key=lambda row: row["id"])
    if len(reference) != 41_392 or len(query_pool) != QUERY_POOL_SIZE:
        fail("unexpected split size")

    reference_hashes = {row["body_sha256"] for row in reference}
    benchmark, verify = select_stratified(
        query_pool, reference_hashes, BENCHMARK_QUERY_COUNT, SAMPLE_SEED, VERIFY_PER_GROUP
    )
    benchmark_ids = {row["id"] for row in benchmark}
    if len(benchmark_ids) != BENCHMARK_QUERY_COUNT:
        fail("benchmark query IDs are not unique")

    inputs_dir = output_dir / "inputs"
    inputs_dir.mkdir(parents=True, exist_ok=True)
    write_csv(inputs_dir / "reference.csv", ["id", "type", "tag_hex"], reference)
    write_csv(inputs_dir / "queries_bench_1000.csv", ["id", "type", "tag_hex"], benchmark)
    write_csv(
        inputs_dir / "query_labels_bench_1000.csv",
        ["query_id", "group", "body_sha256", "source_id"],
        [
            {
                "query_id": row["id"],
                "group": "exact_ref" if row["body_sha256"] in reference_hashes else "no_exact_ref",
                "body_sha256": row["body_sha256"],
                "source_id": row["id"],
            }
            for row in benchmark
        ],
    )
    write_csv(inputs_dir / "queries_verify_100.csv", ["id", "type", "tag_hex"], verify)

    def group_counts(rows: list[dict[str, str]], grouped: bool = False) -> dict[str, int]:
        if grouped:
            counts: dict[str, int] = defaultdict(int)
            for row in rows:
                counts[row["group"]] += 1
            return dict(sorted(counts.items()))
        exact = sum(row["body_sha256"] in reference_hashes for row in rows)
        return {"exact_ref": exact, "no_exact_ref": len(rows) - exact}

    files = {
        "reference.csv": inputs_dir / "reference.csv",
        "queries_bench_1000.csv": inputs_dir / "queries_bench_1000.csv",
        "query_labels_bench_1000.csv": inputs_dir / "query_labels_bench_1000.csv",
        "queries_verify_100.csv": inputs_dir / "queries_verify_100.csv",
    }
    summary = {
        "split_seed": SPLIT_SEED,
        "sample_seed": SAMPLE_SEED,
        "total_records": len(records),
        "reference_count": len(reference),
        "query_pool_count": len(query_pool),
        "benchmark_count": len(benchmark),
        "verify_count": len(verify),
        "query_pool_groups": group_counts(query_pool),
        "benchmark_groups": group_counts(benchmark),
        "verify_groups": group_counts(verify, grouped=True),
        "files": {name: {"sha256": sha256_file(path), "size_bytes": path.stat().st_size} for name, path in files.items()},
    }
    if summary["benchmark_count"] != 1_000 or summary["verify_count"] != 100:
        fail("unexpected benchmark or verify count")
    with (inputs_dir / "split_summary.json").open("w", encoding="utf-8", newline="\n") as target:
        json.dump(summary, target, indent=2, sort_keys=True)
        target.write("\n")
    return summary


def check_cross_scheme(
    prefuzz: list[dict[str, str]],
    simless: list[dict[str, str]],
    fuzzydedup: list[dict[str, str]],
) -> None:
    def matched_by_scheme(rows: list[dict[str, str]], candidate_mode: bool) -> dict[tuple[str, int, int], bool]:
        result: dict[tuple[str, int, int], bool] = {}
        for row in rows:
            key = (row["query_id"], int(row["threshold"]), int(row["repeat"]))
            if key in result:
                raise ValueError(f"duplicate result key: {key}")
            result[key] = int(row["candidate_count"]) > 0 if candidate_mode else int(row["matched"]) == 1
        return result

    prefuzz_matches = matched_by_scheme(prefuzz, True)
    simless_matches = matched_by_scheme(simless, False)
    fuzzy_matches = matched_by_scheme(fuzzydedup, False)
    keys = set(prefuzz_matches) | set(simless_matches) | set(fuzzy_matches)
    if len(prefuzz_matches) != len(keys) or len(simless_matches) != len(keys) or len(fuzzy_matches) != len(keys):
        raise ValueError("cross-scheme result key sets differ")
    for key in sorted(keys):
        if not prefuzz_matches[key] == simless_matches[key] == fuzzy_matches[key]:
            raise ValueError(f"cross-scheme matched disagreement: {key}")


def percentile_nearest(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(round(quantile * (len(ordered) - 1)))))
    return ordered[index]


def read_summary_source_rows(scheme: str, path: Path, threshold: int) -> list[dict[str, Any]]:
    if scheme == "PreFuzzDup":
        return [{**row, "threshold": threshold} for row in read_csv(path)]
    return [row for row in read_csv(path) if int(row["threshold"]) == threshold]


def parse_prefuzz_metadata(stdout: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in stdout.splitlines():
        if line.startswith("records="):
            for item in line.split():
                if "=" not in item:
                    continue
                key, value = item.split("=", 1)
                if key in {"records", "tag_bits", "index_prepare_us", "disk_index_reused", "filter_bytes_estimate"}:
                    values[key] = int(value.rstrip(","))
    required = {"records", "tag_bits", "index_prepare_us", "disk_index_reused", "filter_bytes_estimate"}
    if not required.issubset(values):
        fail(f"could not parse PreFuzzDup metadata: {stdout}")
    return values


def run_command(
    command: list[str],
    log_dir: Path,
    name: str,
    cwd: Path,
    record: list[dict[str, Any]],
) -> tuple[int, str, str, float]:
    started = time.perf_counter()
    process = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)
    elapsed = time.perf_counter() - started
    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / f"{name}.stdout.log").write_text(process.stdout, encoding="utf-8", newline="")
    (log_dir / f"{name}.stderr.log").write_text(process.stderr, encoding="utf-8", newline="")
    (log_dir / f"{name}.command.txt").write_text(" ".join(command) + "\n", encoding="utf-8", newline="")
    (log_dir / f"{name}.exit_code").write_text(f"{process.returncode}\n", encoding="utf-8", newline="")
    record.append(
        {
            "name": name,
            "command": command,
            "exit_code": process.returncode,
            "wall_seconds": elapsed,
        }
    )
    if process.returncode != 0:
        excerpt = (process.stdout + "\n" + process.stderr).strip()[-2000:]
        fail(f"command failed ({name}, exit {process.returncode}):\n{excerpt}")
    return process.returncode, process.stdout, process.stderr, elapsed


def summarize(
    raw_dir: Path,
    output_dir: Path,
    labels_path: Path,
) -> tuple[Path, list[dict[str, Any]]]:
    labels = {row["query_id"]: row["group"] for row in read_csv(labels_path)}
    rows: list[dict[str, Any]] = []
    for threshold in THRESHOLDS:
        sources = [
            ("PreFuzzDup", raw_dir / f"prefuzz_t{threshold}.csv"),
            ("SimLESS", raw_dir / "simless_lookup.csv"),
            ("FuzzyDedup", raw_dir / "fuzzydedup_lookup.csv"),
        ]
        for scheme, path in sources:
            source_rows = read_summary_source_rows(scheme, path, threshold)
            normalized: list[dict[str, Any]] = []
            for row in source_rows:
                normalized.append(
                    {
                        "scheme": scheme,
                        "threshold": threshold,
                        "group": labels[row["query_id"]],
                        "latency": float(row["latency_us"]),
                        "matched": int(row["candidate_count"]) > 0 if scheme == "PreFuzzDup" else int(row["matched"]),
                        "candidate_count": int(row.get("candidate_count", 0)) if scheme == "PreFuzzDup" else None,
                        "records_examined": int(row["records_examined"]) if "records_examined" in row else None,
                        "bits_compared": int(row["bits_compared"]) if "bits_compared" in row else None,
                        "best_distance": int(row["best_distance"]) if "best_distance" in row else None,
                        "filter_queries": int(row.get("filter_queries", 0)) if scheme == "PreFuzzDup" else None,
                        "inverted_lookups": int(row.get("inverted_lookups", 0)) if scheme == "PreFuzzDup" else None,
                        "posting_records_read": int(row.get("posting_records_read", 0)) if scheme == "PreFuzzDup" else None,
                        "full_tag_distance_computations": int(row.get("full_tag_distance_computations", 0))
                        if scheme == "PreFuzzDup"
                        else None,
                    }
                )
            for group in ["all", "exact_ref", "no_exact_ref"]:
                selected = normalized if group == "all" else [row for row in normalized if row["group"] == group]
                if not selected:
                    fail(f"empty summary group: {scheme} threshold={threshold} group={group}")

                def mean_field(name: str) -> float | None:
                    values = [row[name] for row in selected if row[name] is not None]
                    return statistics.fmean(values) if values else None

                query_ids = {
                    row["query_id"]
                    for row in source_rows
                    if group == "all" or labels[row["query_id"]] == group
                }
                rows.append(
                    {
                        "scheme": scheme,
                        "threshold": threshold,
                        "group": group,
                        "samples": len(selected),
                        "queries": len(query_ids),
                        "matched_rate": statistics.fmean([1 if row["matched"] else 0 for row in selected]),
                        "mean_latency_us": statistics.fmean([row["latency"] for row in selected]),
                        "median_latency_us": statistics.median([row["latency"] for row in selected]),
                        "p95_latency_us": percentile_nearest([row["latency"] for row in selected], 0.95),
                        "mean_candidates": mean_field("candidate_count"),
                        "mean_records_examined": mean_field("records_examined"),
                        "mean_bits_compared": mean_field("bits_compared"),
                        "mean_best_distance": mean_field("best_distance"),
                        "mean_filter_queries": mean_field("filter_queries"),
                        "mean_inverted_lookups": mean_field("inverted_lookups"),
                        "mean_posting_records_read": mean_field("posting_records_read"),
                        "mean_full_tag_distance_computations": mean_field("full_tag_distance_computations"),
                    }
                )

    summary_path = output_dir / "summary.csv"
    fieldnames = list(rows[0].keys())
    write_csv(summary_path, fieldnames, rows)
    return summary_path, rows


def write_report(
    output_dir: Path,
    split_summary: dict[str, Any],
    run_manifest: dict[str, Any],
    summary_rows: list[dict[str, Any]],
) -> Path:
    overall = [row for row in summary_rows if row["group"] == "all"]
    report = output_dir / "summary.md"
    lines = [
        "# 5wTest 三方案持久化检索实验结果",
        "",
        "## 实验口径",
        "",
        f"- 参考库 {split_summary['reference_count']} 条，查询池 {split_summary['query_pool_count']} 条，正式查询 {split_summary['benchmark_count']} 条，重复 3 次。",
        f"- 阈值 {', '.join(str(value) for value in THRESHOLDS)}；PreFuzzDup FPP={FPP}；标签均为 256 位。",
        "- 只测量标签检索，不包含文件加密、FuzzyPoW、OT、密文写入或网络开销。",
        "- PreFuzzDup 返回阈值内全部候选；SimLESS 全表扫描求最小距离；FuzzyDedup 找到首个匹配即返回。三者耗时不可解释为相同输出任务速度。",
        "- 运行顺序固定为 build、PreFuzzDup verify、PreFuzzDup t4/t5/t6、SimLESS、FuzzyDedup。OS 页缓存未清空；三个 SQLite 路径的应用层页缓存均约 1 MiB。",
        "",
        "## 总体汇总",
        "",
        "| 方案 | 阈值 | 样本 | 匹配率 | 平均时延 us | 中位 us | P95 us |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in overall:
        lines.append(
            f"| {row['scheme']} | {row['threshold']} | {row['samples']} | {row['matched_rate']:.6f} | "
            f"{row['mean_latency_us']:.3f} | {row['median_latency_us']:.3f} | {row['p95_latency_us']:.3f} |"
        )
    lines.extend(
        [
            "",
            "## 验证",
            "",
            "- 数据切分计数和 ID 唯一性检查通过。",
            "- PreFuzzDup 100 条抽查 `scan` / `exact` / `prefuzz` 等价性通过。",
            "- 1,000 条 × 3 次重复 × 3 阈值的三方案 matched 一致性检查通过。",
            "",
            "## 产物",
            "",
            "- 逐查询结果：`raw/`。",
            "- 命令、stdout/stderr 和耗时：`logs/`。",
            "- 切分证明：`inputs/split_summary.json`。",
            "- 数据库保留在 WSL 原生 scratch：`" + run_manifest["scratch_dir"] + "`。",
            "",
        ]
    )
    report.write_text("\n".join(lines), encoding="utf-8", newline="")
    return report


def ensure_empty_output(output_dir: Path) -> None:
    if output_dir.exists() and any(output_dir.iterdir()):
        fail(f"output directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)


def run_experiment(repo_dir: Path, dataset_dir: Path, output_dir: Path) -> None:
    ensure_empty_output(output_dir)
    started = time.perf_counter()
    split_summary = prepare_inputs(dataset_dir, output_dir)
    scratch_dir = Path.home() / "enron-5w-lookup-runs" / (
        datetime.now(timezone.utc).strftime("run-%Y%m%dT%H%M%SZ") + f"-{os.getpid()}"
    )
    (scratch_dir / "inputs").mkdir(parents=True)
    (scratch_dir / "db").mkdir()
    (scratch_dir / "raw").mkdir()
    for filename in [
        "reference.csv",
        "queries_bench_1000.csv",
        "query_labels_bench_1000.csv",
        "queries_verify_100.csv",
    ]:
        shutil.copy2(output_dir / "inputs" / filename, scratch_dir / "inputs" / filename)

    logs_dir = output_dir / "logs"
    commands: list[dict[str, Any]] = []
    prefuzz_metadata: dict[str, dict[str, int]] = {}
    try:
        for project in ["PreFuzzDup", "SimLESS", "FuzzyDedup"]:
            run_command(["cmake", "--build", f"{project}/build", "-j"], logs_dir / "build", project.lower(), repo_dir, commands)

        inputs = scratch_dir / "inputs"
        raw = scratch_dir / "raw"
        database = scratch_dir / "db"
        _, stdout, _, _ = run_command(
            [
                "./PreFuzzDup/build/prefuzzdup_persistent_lookup",
                "--records", str(inputs / "reference.csv"),
                "--queries", str(inputs / "queries_verify_100.csv"),
                "--db", str(database / "prefuzz_verify.sqlite"),
                "--tag-bits", "256",
                "--threshold", prefuzz_threshold_argument(6),
                "--fpp", str(FPP),
                "--strategies", "prefuzz",
                "--repeat", "1",
                "--verify-equivalence",
                "--out", str(raw / "prefuzz_verify.csv"),
            ],
            logs_dir / "verify",
            "prefuzz_verify",
            repo_dir,
            commands,
        )
        if "equivalence_check=passed" not in stdout:
            fail("PreFuzzDup equivalence check did not pass")

        for threshold in THRESHOLDS:
            _, stdout, _, _ = run_command(
                [
                    "./PreFuzzDup/build/prefuzzdup_persistent_lookup",
                    "--records", str(inputs / "reference.csv"),
                    "--queries", str(inputs / "queries_bench_1000.csv"),
                    "--db", str(database / f"prefuzz_t{threshold}.sqlite"),
                    "--tag-bits", "256",
                    "--threshold", prefuzz_threshold_argument(threshold),
                    "--fpp", str(FPP),
                    "--strategies", "prefuzz",
                    "--repeat", "3",
                    "--out", str(raw / f"prefuzz_t{threshold}.csv"),
                ],
                logs_dir / "prefuzz",
                f"prefuzz_t{threshold}",
                repo_dir,
                commands,
            )
            prefuzz_metadata[str(threshold)] = parse_prefuzz_metadata(stdout)

        common_arguments = [
            "--records", str(inputs / "reference.csv"),
            "--queries", str(inputs / "queries_bench_1000.csv"),
            "--labels", str(inputs / "query_labels_bench_1000.csv"),
            "--thresholds", "4,5,6",
            "--repeat", "3",
        ]
        run_command(
            ["./SimLESS/build/simless_lookup_benchmark", "--scheme", "simless", *common_arguments,
             "--db", str(database / "simless_labels.sqlite"), "--out", str(raw / "simless_lookup.csv")],
            logs_dir / "simless", "simless_lookup", repo_dir, commands,
        )
        run_command(
            ["./FuzzyDedup/build/fuzzydedup_lookup_benchmark", "--scheme", "fuzzydedup", *common_arguments,
             "--db", str(database / "fuzzydedup_labels.sqlite"), "--out", str(raw / "fuzzydedup_lookup.csv")],
            logs_dir / "fuzzydedup", "fuzzydedup_lookup", repo_dir, commands,
        )

        prefuzz_rows = load_prefuzz_rows(raw)
        check_cross_scheme(prefuzz_rows, read_csv(raw / "simless_lookup.csv"), read_csv(raw / "fuzzydedup_lookup.csv"))

        summary_path, summary_rows = summarize(raw, output_dir, inputs / "query_labels_bench_1000.csv")
        output_raw = output_dir / "raw"
        output_raw.mkdir()
        for path in sorted(raw.glob("*.csv")):
            shutil.copy2(path, output_raw / path.name)

        database_files = {path.name: path.stat().st_size for path in sorted(database.glob("*.sqlite"))}
        run_manifest = {
            "schema_version": 1,
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "scope": "persistent tag lookup only; no cryptographic microbenchmarks",
            "repo_dir": str(repo_dir),
            "dataset_dir": str(dataset_dir),
            "output_dir": str(output_dir),
            "scratch_dir": str(scratch_dir),
            "dataset_json_sha256": sha256_file(dataset_dir / "dataset.json"),
            "split": split_summary,
            "thresholds": list(THRESHOLDS),
            "prefuzz_fpp": FPP,
            "repeat": 3,
            "prefuzz_metadata": prefuzz_metadata,
            "database_files": database_files,
            "commands": commands,
            "environment": {
                "platform": platform.platform(),
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "python": sys.version,
                "uname": subprocess.run(["uname", "-a"], text=True, capture_output=True, check=True).stdout.strip(),
            },
            "notes": [
                "OS page cache was not cleared between commands.",
                "SQLite application page cache is approximately 1 MiB for all three lookup programs.",
                "Commands ran in the fixed order recorded in commands.",
                "Timing figures are not directly comparable across different output objectives.",
            ],
        }
        with (output_dir / "run_manifest.json").open("w", encoding="utf-8", newline="\n") as target:
            json.dump(run_manifest, target, indent=2, sort_keys=True)
            target.write("\n")
        write_report(output_dir, split_summary, run_manifest, summary_rows)
        print(f"experiment complete: {output_dir}")
        print(f"summary: {summary_path}")
        print(f"scratch databases: {scratch_dir}")
    except Exception:
        if (output_dir / "raw").exists():
            shutil.copytree(scratch_dir / "raw", output_dir / "raw-on-failure", dirs_exist_ok=True)
        raise
    finally:
        elapsed = time.perf_counter() - started
        print(f"total experiment seconds: {elapsed:.3f}")


def parse_arguments() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    repo_dir = script_dir.parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=repo_dir)
    parser.add_argument("--dataset", type=Path, default=repo_dir / "enron_mail_20150507" / "5wTest")
    parser.add_argument("--output", type=Path, default=repo_dir / "results-local/enron-5w/lookup-experiment")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        run_experiment(arguments.repo.resolve(), arguments.dataset.resolve(), arguments.output.resolve())
        return 0
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
