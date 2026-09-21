#!/usr/bin/env python3
"""Run the full-corpus Enron persistent lookup comparison."""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import statistics
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


FIVEW_TOOL_DIR = Path(__file__).resolve().parents[1] / "enron-5w"
sys.path.insert(0, str(FIVEW_TOOL_DIR))

import run_lookup_experiment as five_w  # noqa: E402


TOTAL_RECORDS = 517_401
REFERENCE_SIZE = 413_921
QUERY_POOL_SIZE = 103_480
BENCHMARK_QUERY_COUNT = 1_000
VERIFY_PER_GROUP = 50
SPLIT_SEED = 20_260_921
SAMPLE_SEED = 20_260_922
FPP = 0.01
THRESHOLDS = (4, 5, 6)


def duplicate_bucket(count: int) -> str:
    if count == 1:
        return "1"
    if count == 2:
        return "2"
    if count <= 10:
        return "3_10"
    if count <= 100:
        return "11_100"
    return "over_100"


def distribution_stats(values: list[int | float]) -> dict[str, int | float]:
    if not values:
        raise ValueError("cannot summarize an empty distribution")
    numeric = sorted(float(value) for value in values)
    import math

    def percentile(quantile: float) -> float:
        index = max(0, min(len(numeric) - 1, math.ceil(len(numeric) * quantile) - 1))
        return numeric[index]

    return {
        "samples": len(numeric),
        "mean": statistics.fmean(numeric),
        "p50": percentile(0.50),
        "p95": percentile(0.95),
        "p99": percentile(0.99),
        "max": max(numeric),
    }


def _summary_key(row: dict[str, Any]) -> tuple[str, str, str]:
    return str(row["scheme"]), str(row["threshold"]), str(row["group"])


def scale_comparison(
    full_rows: list[dict[str, Any]],
    five_w_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    old = {_summary_key(row): row for row in five_w_rows}
    result: list[dict[str, Any]] = []
    for row in full_rows:
        previous = old.get(_summary_key(row))
        if previous is None:
            continue
        old_latency = float(previous["mean_latency_us"])
        new_latency = float(row["mean_latency_us"])
        result.append(
            {
                "scheme": row["scheme"],
                "threshold": row["threshold"],
                "group": row["group"],
                "five_w_latency_us": old_latency,
                "full_latency_us": new_latency,
                "latency_ratio": new_latency / old_latency if old_latency else None,
                "five_w_matched_rate": float(previous["matched_rate"]),
                "full_matched_rate": float(row["matched_rate"]),
                "matched_rate_delta": float(row["matched_rate"]) - float(previous["matched_rate"]),
            }
        )
    return result


def read_csv(path: Path) -> list[dict[str, str]]:
    return five_w.read_csv(path)


def load_full_dataset(dataset_dir: Path) -> list[dict[str, str]]:
    manifest_hashes: dict[str, str] = {}
    manifest_count = 0
    with (dataset_dir / "manifest.csv").open(newline="", encoding="utf-8") as source:
        import csv

        reader = csv.DictReader(source)
        expected_header = [
            "id", "mailbox", "source_path", "body_sha256",
            "body_size_bytes", "normalized_word_count",
        ]
        if reader.fieldnames != expected_header:
            five_w.fail("full manifest header mismatch")
        for row in reader:
            manifest_count += 1
            if row["id"] in manifest_hashes:
                five_w.fail(f"duplicate full manifest ID: {row['id']}")
            manifest_hashes[row["id"]] = row["body_sha256"]

    records: list[dict[str, str]] = []
    tag_ids: set[str] = set()
    with (dataset_dir / "tags.csv").open(newline="", encoding="utf-8") as source:
        import csv

        reader = csv.DictReader(source)
        if reader.fieldnames != ["id", "type", "tag_hex"]:
            five_w.fail("full tags header mismatch")
        for row in reader:
            record_id = row["id"]
            if record_id in tag_ids:
                five_w.fail(f"duplicate full tag ID: {record_id}")
            if record_id not in manifest_hashes:
                five_w.fail(f"tag ID missing from full manifest: {record_id}")
            if row["type"] != "text":
                five_w.fail(f"non-text full tag: {record_id}")
            tag = row["tag_hex"]
            if len(tag) != 64 or any(character not in "0123456789abcdef" for character in tag):
                five_w.fail(f"invalid full tag: {record_id}")
            tag_ids.add(record_id)
            records.append(
                {
                    "id": record_id,
                    "type": "text",
                    "tag_hex": tag,
                    "body_sha256": manifest_hashes[record_id],
                }
            )
    if manifest_count != TOTAL_RECORDS or len(records) != TOTAL_RECORDS:
        five_w.fail(
            f"unexpected full dataset count: manifest={manifest_count}, tags={len(records)}"
        )
    if tag_ids != set(manifest_hashes):
        five_w.fail("full manifest and tags ID sets differ")
    records.sort(key=lambda row: row["id"])
    return records


def prepare_inputs(dataset_dir: Path, output_dir: Path) -> dict[str, Any]:
    records = load_full_dataset(dataset_dir)
    all_ids = [row["id"] for row in records]
    selected = set(
        __import__("random").Random(SPLIT_SEED).sample(sorted(all_ids), QUERY_POOL_SIZE)
    )
    reference = [row for row in records if row["id"] not in selected]
    query_pool = [row for row in records if row["id"] in selected]
    reference.sort(key=lambda row: row["id"])
    query_pool.sort(key=lambda row: row["id"])
    if len(reference) != REFERENCE_SIZE or len(query_pool) != QUERY_POOL_SIZE:
        five_w.fail("unexpected full split size")

    reference_hashes = {row["body_sha256"] for row in reference}
    benchmark, verify = five_w.select_stratified(
        query_pool,
        reference_hashes,
        BENCHMARK_QUERY_COUNT,
        SAMPLE_SEED,
        VERIFY_PER_GROUP,
    )
    benchmark_ids = {row["id"] for row in benchmark}
    if len(benchmark_ids) != BENCHMARK_QUERY_COUNT:
        five_w.fail("full benchmark IDs are not unique")

    inputs_dir = output_dir / "inputs"
    inputs_dir.mkdir(parents=True, exist_ok=True)
    five_w.write_csv(inputs_dir / "reference.csv", ["id", "type", "tag_hex"], reference)
    five_w.write_csv(
        inputs_dir / "queries_bench_1000.csv",
        ["id", "type", "tag_hex"],
        benchmark,
    )
    labels = []
    for row in benchmark:
        labels.append(
            {
                "query_id": row["id"],
                "group": "exact_ref" if row["body_sha256"] in reference_hashes else "no_exact_ref",
                "body_sha256": row["body_sha256"],
                "source_id": row["id"],
            }
        )
    five_w.write_csv(
        inputs_dir / "query_labels_bench_1000.csv",
        ["query_id", "group", "body_sha256", "source_id"],
        labels,
    )
    five_w.write_csv(
        inputs_dir / "queries_verify_100.csv",
        ["id", "type", "tag_hex"],
        verify,
    )

    corpus_counts = Counter(row["body_sha256"] for row in records)
    reference_counts = Counter(row["body_sha256"] for row in reference)
    benchmark_hashes = {row["body_sha256"] for row in benchmark}
    group_counts = Counter(row["group"] for row in labels)
    files = {
        "reference.csv": inputs_dir / "reference.csv",
        "queries_bench_1000.csv": inputs_dir / "queries_bench_1000.csv",
        "query_labels_bench_1000.csv": inputs_dir / "query_labels_bench_1000.csv",
        "queries_verify_100.csv": inputs_dir / "queries_verify_100.csv",
    }
    summary = {
        "dataset": "enron_full_body_tags_v1",
        "split_seed": SPLIT_SEED,
        "sample_seed": SAMPLE_SEED,
        "total_records": len(records),
        "reference_count": len(reference),
        "query_pool_count": len(query_pool),
        "benchmark_count": len(benchmark),
        "verify_count": len(verify),
        "query_pool_groups": dict(
            sorted(
                Counter(
                    "exact_ref" if row["body_sha256"] in reference_hashes else "no_exact_ref"
                    for row in query_pool
                ).items()
            )
        ),
        "benchmark_groups": dict(sorted(group_counts.items())),
        "verify_groups": dict(sorted(Counter(row["group"] for row in verify).items())),
        "corpus_duplicate_buckets": dict(
            sorted(Counter(duplicate_bucket(value) for value in corpus_counts.values()).items())
        ),
        "benchmark_corpus_duplicate_buckets": dict(
            sorted(
                Counter(
                    duplicate_bucket(corpus_counts[row["body_sha256"]])
                    for row in benchmark
                    if row["body_sha256"] in corpus_counts
                ).items()
            )
        ),
        "benchmark_reference_duplicate_buckets": dict(
            sorted(
                Counter(
                    duplicate_bucket(reference_counts[row["body_sha256"]])
                    for row in benchmark
                    if row["body_sha256"] in reference_counts
                ).items()
            )
        ),
        "benchmark_unique_body_hashes": len(benchmark_hashes),
        "files": {
            name: {
                "sha256": five_w.sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
            for name, path in files.items()
        },
    }
    with (inputs_dir / "split_summary.json").open(
        "w", encoding="utf-8", newline="\n"
    ) as target:
        json.dump(summary, target, indent=2, sort_keys=True)
        target.write("\n")
    return summary


def write_query_analysis(
    output_dir: Path,
    split_summary: dict[str, Any],
) -> Path:
    labels = read_csv(output_dir / "inputs" / "query_labels_bench_1000.csv")
    prefuzz_rows: list[dict[str, Any]] = []
    for threshold in THRESHOLDS:
        for row in read_csv(output_dir / "raw" / f"prefuzz_t{threshold}.csv"):
            row["threshold"] = threshold
            prefuzz_rows.append(row)
    candidates: dict[tuple[str, int], list[int]] = defaultdict(list)
    for row in prefuzz_rows:
        candidates[(row["query_id"], row["threshold"])].append(int(row["candidate_count"]))
    path = output_dir / "query_analysis.csv"
    rows = []
    for label in labels:
        for threshold in THRESHOLDS:
            values = candidates[(label["query_id"], threshold)]
            rows.append(
                {
                    "query_id": label["query_id"],
                    "group": label["group"],
                    "threshold": threshold,
                    "mean_candidates": statistics.fmean(values) if values else None,
                    "max_candidates": max(values) if values else None,
                }
            )
    five_w.write_csv(
        path,
        ["query_id", "group", "threshold", "mean_candidates", "max_candidates"],
        rows,
    )
    return path


def write_tail_summary(output_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    labels = {
        row["query_id"]: row["group"]
        for row in read_csv(output_dir / "inputs" / "query_labels_bench_1000.csv")
    }
    for threshold in THRESHOLDS:
        prefuzz = read_csv(output_dir / "raw" / f"prefuzz_t{threshold}.csv")
        rows.append(
            {
                "scheme": "PreFuzzDup",
                "metric": "candidate_count",
                "threshold": threshold,
                "group": "all",
                **distribution_stats([int(row["candidate_count"]) for row in prefuzz]),
            }
        )
        for group in ("exact_ref", "no_exact_ref"):
            selected = [row for row in prefuzz if labels[row["query_id"]] == group]
            rows.append(
                {
                    "scheme": "PreFuzzDup",
                    "metric": "candidate_count",
                    "threshold": threshold,
                    "group": group,
                    **distribution_stats([int(row["candidate_count"]) for row in selected]),
                }
            )
    for scheme, filename in (
        ("SimLESS", "simless_lookup.csv"),
        ("FuzzyDedup", "fuzzydedup_lookup.csv"),
    ):
        source_rows = read_csv(output_dir / "raw" / filename)
        for threshold in THRESHOLDS:
            selected = [row for row in source_rows if int(row["threshold"]) == threshold]
            metric = "best_distance" if scheme == "SimLESS" else "records_examined"
            rows.append(
                {
                    "scheme": scheme,
                    "metric": metric,
                    "threshold": threshold,
                    "group": "all",
                    **distribution_stats([int(row[metric]) for row in selected]),
                }
            )
    five_w.write_csv(
        output_dir / "tail_summary.csv",
        ["scheme", "metric", "threshold", "group", "samples", "mean", "p50", "p95", "p99", "max"],
        rows,
    )
    return rows


def write_scale_summary(output_dir: Path) -> list[dict[str, Any]]:
    full_rows = read_csv(output_dir / "summary.csv")
    old_path = Path(__file__).resolve().parents[2] / "results-local/enron-5w/lookup-experiment/summary.csv"
    if not old_path.is_file():
        five_w.fail(f"5w baseline summary is missing: {old_path}")
    old_rows = read_csv(old_path)
    rows = scale_comparison(full_rows, old_rows)
    if not rows:
        five_w.fail("no comparable full/5w summary rows")
    five_w.write_csv(
        output_dir / "scale_vs_5w.csv",
        [
            "scheme", "threshold", "group", "five_w_latency_us", "full_latency_us",
            "latency_ratio", "five_w_matched_rate", "full_matched_rate", "matched_rate_delta",
        ],
        rows,
    )
    return rows


def write_report(
    output_dir: Path,
    split_summary: dict[str, Any],
    run_manifest: dict[str, Any],
) -> Path:
    summary_rows = read_csv(output_dir / "summary.csv")
    tail_rows = read_csv(output_dir / "tail_summary.csv")
    scale_rows = read_csv(output_dir / "scale_vs_5w.csv")
    lines = [
        "# Enron 全量三方案持久化检索实验结果",
        "",
        "## 口径",
        "",
        f"- 全量 {split_summary['total_records']:,} 条；参考库 {split_summary['reference_count']:,} 条；查询池 {split_summary['query_pool_count']:,} 条。",
        f"- 正式查询 {split_summary['benchmark_count']:,} 条，重复 3 次；阈值 {', '.join(map(str, THRESHOLDS))}。",
        "- 只测标签检索，不包含加密、FuzzyPoW、OT、密文写入或网络。",
        "- PreFuzzDup 返回全部候选；SimLESS 求全库最小距离；FuzzyDedup 首个匹配即返回。",
        "- OS 页缓存未清空，SQLite 应用页缓存约 1 MiB，命令按 manifest 记录的固定顺序执行。",
        "",
        "## 总体结果",
        "",
        "| 方案 | 阈值 | 匹配率 | 平均 us | 中位 us | P95 us |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in summary_rows:
        if row["group"] != "all":
            continue
        lines.append(
            f"| {row['scheme']} | {row['threshold']} | {float(row['matched_rate']):.6f} | "
            f"{float(row['mean_latency_us']):.3f} | {float(row['median_latency_us']):.3f} | "
            f"{float(row['p95_latency_us']):.3f} |"
        )
    lines.extend(["", "## 尾部指标", ""])
    lines.extend(
        [
            "| 方案 | 指标 | 阈值 | 组 | 样本 | 平均 | P95 | P99 | Max |",
            "| --- | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in tail_rows:
        lines.append(
            f"| {row['scheme']} | {row['metric']} | {row['threshold']} | {row['group']} | {row['samples']} | "
            f"{float(row['mean']):.3f} | {row['p95']} | {row['p99']} | {row['max']} |"
        )
    lines.extend(["", "## 相对 5wTest", ""])
    lines.extend(
        [
            "| 方案 | 阈值 | 组 | 5w 平均 us | 全量平均 us | 放大倍数 | 匹配率变化 |",
            "| --- | --- | --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in scale_rows:
        if row["group"] != "all":
            continue
        ratio = float(row["latency_ratio"]) if row["latency_ratio"] else 0.0
        lines.append(
            f"| {row['scheme']} | {row['threshold']} | {row['group']} | "
            f"{float(row['five_w_latency_us']):.3f} | {float(row['full_latency_us']):.3f} | "
            f"{ratio:.3f}x | {float(row['matched_rate_delta']):+.6f} |"
        )
    lines.extend(
        [
            "",
            "## 验证",
            "",
            "- 全量数据集 C++ 校验 517,401/517,401，mismatch=0。",
            "- 切分计数、ID 唯一性和无交集检查通过。",
            "- PreFuzzDup 100 条 `scan/exact/prefuzz` 等价抽查通过。",
            "- 三方案 27,000 个 matched 判定完全一致。",
            "",
            f"- WSL scratch 数据库：`{run_manifest['scratch_dir']}`。",
            "- 原始逐查询结果：`raw/`；命令与日志：`logs/`。",
        ]
    )
    report = output_dir / "summary.md"
    report.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="")
    return report


def run_experiment(repo_dir: Path, dataset_dir: Path, output_dir: Path) -> None:
    five_w.ensure_empty_output(output_dir)
    started = time.perf_counter()
    split_summary = prepare_inputs(dataset_dir, output_dir)
    scratch_dir = Path.home() / "enron-full-lookup-runs" / (
        datetime.now(timezone.utc).strftime("run-%Y%m%dT%H%M%SZ")
        + f"-{__import__('os').getpid()}"
    )
    (scratch_dir / "inputs").mkdir(parents=True)
    (scratch_dir / "db").mkdir()
    (scratch_dir / "raw").mkdir()
    for filename in (
        "reference.csv",
        "queries_bench_1000.csv",
        "query_labels_bench_1000.csv",
        "queries_verify_100.csv",
    ):
        shutil.copy2(output_dir / "inputs" / filename, scratch_dir / "inputs" / filename)

    logs_dir = output_dir / "logs"
    commands: list[dict[str, Any]] = []
    prefuzz_metadata: dict[str, dict[str, int]] = {}
    inputs = scratch_dir / "inputs"
    raw = scratch_dir / "raw"
    database = scratch_dir / "db"
    try:
        for project in ("PreFuzzDup", "SimLESS", "FuzzyDedup"):
            five_w.run_command(
                ["cmake", "--build", f"{project}/build", "-j"],
                logs_dir / "build",
                project.lower(),
                repo_dir,
                commands,
            )
            binary = {
                "PreFuzzDup": "./PreFuzzDup/build/prefuzzdup",
                "SimLESS": "./SimLESS/build/simless",
                "FuzzyDedup": "./FuzzyDedup/build/fuzzydedup",
            }[project]
            five_w.run_command(
                [binary, "self-test"],
                logs_dir / "self-test",
                project.lower(),
                repo_dir,
                commands,
            )

        _, stdout, _, _ = five_w.run_command(
            [
                "./PreFuzzDup/build/prefuzzdup_persistent_lookup",
                "--records", str(inputs / "reference.csv"),
                "--queries", str(inputs / "queries_verify_100.csv"),
                "--db", str(database / "prefuzz_verify.sqlite"),
                "--tag-bits", "256",
                "--threshold", five_w.prefuzz_threshold_argument(6),
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
            five_w.fail("PreFuzzDup full verify did not pass")

        for threshold in THRESHOLDS:
            _, stdout, _, _ = five_w.run_command(
                [
                    "./PreFuzzDup/build/prefuzzdup_persistent_lookup",
                    "--records", str(inputs / "reference.csv"),
                    "--queries", str(inputs / "queries_bench_1000.csv"),
                    "--db", str(database / f"prefuzz_t{threshold}.sqlite"),
                    "--tag-bits", "256",
                    "--threshold", five_w.prefuzz_threshold_argument(threshold),
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
            prefuzz_metadata[str(threshold)] = five_w.parse_prefuzz_metadata(stdout)

        common_arguments = [
            "--records", str(inputs / "reference.csv"),
            "--queries", str(inputs / "queries_bench_1000.csv"),
            "--labels", str(inputs / "query_labels_bench_1000.csv"),
            "--thresholds", "4,5,6",
            "--repeat", "3",
        ]
        five_w.run_command(
            [
                "./SimLESS/build/simless_lookup_benchmark",
                "--scheme", "simless",
                *common_arguments,
                "--db", str(database / "simless_labels.sqlite"),
                "--out", str(raw / "simless_lookup.csv"),
            ],
            logs_dir / "simless",
            "simless_lookup",
            repo_dir,
            commands,
        )
        five_w.run_command(
            [
                "./FuzzyDedup/build/fuzzydedup_lookup_benchmark",
                "--scheme", "fuzzydedup",
                *common_arguments,
                "--db", str(database / "fuzzydedup_labels.sqlite"),
                "--out", str(raw / "fuzzydedup_lookup.csv"),
            ],
            logs_dir / "fuzzydedup",
            "fuzzydedup_lookup",
            repo_dir,
            commands,
        )

        prefuzz_rows = five_w.load_prefuzz_rows(raw)
        five_w.check_cross_scheme(
            prefuzz_rows,
            read_csv(raw / "simless_lookup.csv"),
            read_csv(raw / "fuzzydedup_lookup.csv"),
        )
        output_raw = output_dir / "raw"
        output_raw.mkdir()
        for path in sorted(raw.glob("*.csv")):
            shutil.copy2(path, output_raw / path.name)

        five_w.summarize(raw, output_dir, inputs / "query_labels_bench_1000.csv")
        write_query_analysis(output_dir, split_summary)
        write_tail_summary(output_dir)
        write_scale_summary(output_dir)
        database_files = {
            path.name: path.stat().st_size for path in sorted(database.glob("*.sqlite"))
        }
        run_manifest = {
            "schema_version": 1,
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "scope": "full-corpus persistent tag lookup only",
            "repo_dir": str(repo_dir),
            "dataset_dir": str(dataset_dir),
            "output_dir": str(output_dir),
            "scratch_dir": str(scratch_dir),
            "dataset_json_sha256": five_w.sha256_file(dataset_dir / "dataset.json"),
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
                "uname": subprocess.run(
                    ["uname", "-a"], text=True, capture_output=True, check=True
                ).stdout.strip(),
            },
            "notes": [
                "Full dataset was independently verified by C++ before benchmarking.",
                "OS page cache was not cleared between commands.",
                "SQLite application page cache is approximately 1 MiB.",
                "Output objectives differ across schemes; timing is not a same-output speed ranking.",
            ],
        }
        with (output_dir / "run_manifest.json").open(
            "w", encoding="utf-8", newline="\n"
        ) as target:
            json.dump(run_manifest, target, indent=2, sort_keys=True)
            target.write("\n")
        write_report(output_dir, split_summary, run_manifest)
        print(f"full experiment complete: {output_dir}")
        print(f"scratch databases: {scratch_dir}")
    except Exception:
        if (scratch_dir / "raw").exists():
            shutil.copytree(
                scratch_dir / "raw",
                output_dir / "raw-on-failure",
                dirs_exist_ok=True,
            )
        raise
    finally:
        print(f"total full experiment seconds: {time.perf_counter() - started:.3f}")


def parse_arguments() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    repo_dir = script_dir.parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=repo_dir)
    parser.add_argument(
        "--dataset",
        type=Path,
        default=repo_dir / "enron_mail_20150507" / "full50wTest",
    )
    parser.add_argument("--output", type=Path, default=repo_dir / "results-local/enron-full/lookup-experiment")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        run_experiment(
            arguments.repo.resolve(),
            arguments.dataset.resolve(),
            arguments.output.resolve(),
        )
        return 0
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
