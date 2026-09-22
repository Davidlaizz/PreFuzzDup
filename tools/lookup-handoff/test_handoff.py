import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from typing import Any

import handoff


def tag(value: str) -> str:
    return value * 64


def write_tag_csv(path: Path, rows: list[tuple[str, str]]) -> None:
    handoff.write_csv(
        path,
        ["id", "type", "tag_hex"],
        [{"id": record_id, "type": "text", "tag_hex": tag(value)} for record_id, value in rows],
    )


def prepare_source(root: Path) -> Path:
    source = root / "source"
    source.mkdir()
    write_tag_csv(source / "reference.csv", [("r1", "0")])
    write_tag_csv(source / "queries_bench_1000.csv", [("q1", "1")])
    write_tag_csv(source / "queries_verify_100.csv", [("v1", "2")])
    handoff.write_csv(
        source / "query_labels_bench_1000.csv",
        ["query_id", "group", "body_sha256", "source_id"],
        [{"query_id": "q1", "group": "exact_ref", "body_sha256": "", "source_id": "q1"}],
    )
    handoff.write_json(
        source / "split_summary.json",
        {
            "total_records": 3,
            "reference_count": 1,
            "benchmark_count": 1,
            "verify_count": 1,
            "files": {
                "reference.csv": {"sha256": handoff.sha256_file(source / "reference.csv")},
                "queries_bench_1000.csv": {"sha256": handoff.sha256_file(source / "queries_bench_1000.csv")},
                "queries_verify_100.csv": {"sha256": handoff.sha256_file(source / "queries_verify_100.csv")},
            },
        },
    )
    return source


def prepare_baseline(root: Path) -> Path:
    baseline = root / "baseline"
    (baseline / "raw").mkdir(parents=True)
    handoff.write_json(baseline / "run_manifest.json", {"repeat": handoff.REPEAT})
    for threshold in handoff.THRESHOLDS:
        handoff.write_csv(
            baseline / "raw" / f"prefuzz_t{threshold}.csv",
            handoff.PREFUZZ_HEADER,
            [prefuzz_row("q1", threshold, candidate_count=0)],
        )
    for scheme in ("simless", "fuzzydedup"):
        handoff.write_csv(
            baseline / "raw" / f"{scheme}_lookup.csv",
            handoff.COMPARATIVE_HEADER,
            [comparative_row(scheme, "q1", "exact_ref", matched=0)],
        )
    return baseline


def prefuzz_row(query_id: str, threshold: int, candidate_count: int) -> dict[str, Any]:
    return {
        "strategy": "prefuzz",
        "query_id": query_id,
        "type": "text",
        "repeat": 0,
        "latency_us": 10,
        "candidate_count": candidate_count,
        "filter_queries": threshold + 1,
        "inverted_lookups": 0,
        "posting_records_read": 0,
        "full_tag_distance_computations": candidate_count,
    }


def comparative_row(scheme: str, query_id: str, group: str, matched: int) -> dict[str, Any]:
    return {
        "scheme": scheme,
        "threshold": 4,
        "repeat": 0,
        "query_id": query_id,
        "group": group,
        "latency_us": 10,
        "matched": matched,
        "best_distance": 0 if matched else 99,
        "records_examined": 1,
        "bits_compared": 256,
    }


def make_package(root: Path) -> Path:
    source = prepare_source(root)
    baseline = prepare_baseline(root)
    package = root / "package"
    with mock.patch.dict(handoff.EXPECTED_COUNTS, {"total_records": 3, "reference_count": 1, "benchmark_count": 1, "verify_count": 1}), \
         mock.patch.object(handoff, "BENCHMARK_QUERY_COUNT", 1), \
         mock.patch.object(handoff, "VERIFY_QUERY_COUNT", 1), \
         mock.patch.object(handoff, "git_commit", lambda repo: "testcommit"):
        handoff.create_client_package(source, package, baseline, root)
    return package


class ClientPackageTests(unittest.TestCase):
    def test_client_package_sanitizes_groups_and_records_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = make_package(Path(directory))
            manifest = handoff.read_json(package / "handoff-manifest.json")
            self.assertEqual(set(handoff.INPUT_FILES), set(manifest["inputs"]))
            bench = handoff.read_csv(package / "inputs" / "query_groups_bench_1000.csv")
            verify = handoff.read_csv(package / "inputs" / "query_groups_verify_100.csv")
            self.assertEqual(bench[0]["group"], "exact_ref")
            self.assertEqual(verify[0]["group"], "verify")
            self.assertFalse(bench[0]["payload_digest"])
            self.assertFalse(bench[0]["source_ref"])

    def test_client_rejects_conflicting_overlapping_ids(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = prepare_source(root)
            baseline = prepare_baseline(root)
            write_tag_csv(source / "queries_bench_1000.csv", [("v1", "1")])
            handoff.write_csv(
                source / "query_labels_bench_1000.csv",
                ["query_id", "group", "body_sha256", "source_id"],
                [{"query_id": "v1", "group": "exact_ref", "body_sha256": "", "source_id": "v1"}],
            )
            package = root / "package"
            with mock.patch.dict(handoff.EXPECTED_COUNTS, {"total_records": 3, "reference_count": 1, "benchmark_count": 1, "verify_count": 1}), \
                 mock.patch.object(handoff, "BENCHMARK_QUERY_COUNT", 1), \
                 mock.patch.object(handoff, "VERIFY_QUERY_COUNT", 1):
                with self.assertRaisesRegex(RuntimeError, "different tags"):
                    handoff.create_client_package(source, package, baseline, root)

    def test_client_accepts_identical_overlapping_ids(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = prepare_source(root)
            baseline = prepare_baseline(root)
            write_tag_csv(source / "queries_bench_1000.csv", [("v1", "2")])
            handoff.write_csv(
                source / "query_labels_bench_1000.csv",
                ["query_id", "group", "body_sha256", "source_id"],
                [{"query_id": "v1", "group": "exact_ref", "body_sha256": "", "source_id": "v1"}],
            )
            package = root / "package"
            with mock.patch.dict(handoff.EXPECTED_COUNTS, {"total_records": 3, "reference_count": 1, "benchmark_count": 1, "verify_count": 1}), \
                 mock.patch.object(handoff, "BENCHMARK_QUERY_COUNT", 1), \
                 mock.patch.object(handoff, "VERIFY_QUERY_COUNT", 1), \
                 mock.patch.object(handoff, "git_commit", lambda repo: "testcommit"):
                handoff.create_client_package(source, package, baseline, root)
            bench = handoff.read_csv(package / "inputs" / "query_groups_bench_1000.csv")
            verify = handoff.read_csv(package / "inputs" / "query_groups_verify_100.csv")
            self.assertEqual(bench[0]["query_id"], "v1")
            self.assertEqual(verify[0]["query_id"], "v1")

    def test_client_rejects_reference_overlap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = prepare_source(root)
            baseline = prepare_baseline(root)
            write_tag_csv(source / "queries_bench_1000.csv", [("r1", "1")])
            handoff.write_csv(
                source / "query_labels_bench_1000.csv",
                ["query_id", "group", "body_sha256", "source_id"],
                [{"query_id": "r1", "group": "exact_ref", "body_sha256": "", "source_id": "r1"}],
            )
            package = root / "package"
            with mock.patch.dict(handoff.EXPECTED_COUNTS, {"total_records": 3, "reference_count": 1, "benchmark_count": 1, "verify_count": 1}), \
                 mock.patch.object(handoff, "BENCHMARK_QUERY_COUNT", 1), \
                 mock.patch.object(handoff, "VERIFY_QUERY_COUNT", 1), \
                 mock.patch.object(handoff, "git_commit", lambda repo: "testcommit"):
                with self.assertRaisesRegex(RuntimeError, "reference and query IDs overlap"):
                    handoff.create_client_package(source, package, baseline, root)


class OutputTests(unittest.TestCase):
    def test_prefuzz_rejects_bad_filter_workload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "prefuzz.csv"
            handoff.write_csv(path, handoff.PREFUZZ_HEADER, [prefuzz_row("q", 4, candidate_count=0)])
            rows = handoff.read_csv(path)
            rows[0]["filter_queries"] = "3"
            handoff.write_csv(path, handoff.PREFUZZ_HEADER, rows)
            with self.assertRaisesRegex(RuntimeError, "filter query count"):
                handoff.validate_prefuzz_csv(path, 1, 4, {"q"})

    def test_comparative_rejects_scheme_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.csv"
            handoff.write_csv(path, handoff.COMPARATIVE_HEADER, [comparative_row("wrong", "q", "verify", matched=0)])
            with self.assertRaisesRegex(RuntimeError, "unexpected scheme"):
                handoff.validate_comparative_csv(path, "simless", 1, 1, {"q"}, {"verify"}, 1)


class AnalysisTests(unittest.TestCase):
    def test_analysis_detects_workload_disagreement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = make_package(root)
            baseline = root / "baseline"
            results = package / "results"
            results.mkdir()

            metadata = {
                str(threshold): {
                    "index_prepare_us": 1,
                    "disk_index_reused": 0,
                    "filter_bytes_estimate": 1,
                    "sqlite_cache_kib": 1024,
                }
                for threshold in handoff.THRESHOLDS
            }
            for threshold in handoff.THRESHOLDS:
                handoff.write_csv(
                    results / f"prefuzzdup_t{threshold}.csv",
                    handoff.PREFUZZ_HEADER,
                    [prefuzz_row("q1", threshold, candidate_count=1 if threshold == 4 else 0)],
                )
            for scheme in ("simless", "fuzzydedup"):
                handoff.write_csv(
                    results / f"{scheme}_bench.csv",
                    handoff.COMPARATIVE_HEADER,
                    [comparative_row(scheme, "q1", "exact_ref", matched=0)],
                )
                handoff.write_csv(
                    results / f"{scheme}_verify.csv",
                    handoff.COMPARATIVE_HEADER,
                    [comparative_row(scheme, "v1", "verify", matched=0)],
                )
            handoff.write_csv(
                results / "prefuzzdup_verify.csv",
                handoff.PREFUZZ_HEADER,
                [prefuzz_row("v1", 6, candidate_count=0)],
            )
            handoff.write_json(results / "environment.json", {})
            server_manifest = {
                "status": "passed",
                "prefuzz_metadata": metadata,
                "database_files": {},
            }
            server_manifest["result_files"] = handoff.file_inventory(
                results, results / "server-result-manifest.json"
            )
            handoff.write_json(
                results / "server-result-manifest.json",
                server_manifest,
            )
            with mock.patch.dict(
                handoff.EXPECTED_COUNTS,
                {"total_records": 3, "reference_count": 1, "benchmark_count": 1, "verify_count": 1},
            ), \
                 mock.patch.object(handoff, "BENCHMARK_QUERY_COUNT", 1), \
                 mock.patch.object(handoff, "VERIFY_QUERY_COUNT", 1):
                passed = handoff.analyze_results(package, baseline, root / "analysis")
            self.assertFalse(passed)
            report = (root / "analysis" / "analysis.md").read_text(encoding="utf-8")
            self.assertIn("Workload disagreements: `2`", report)


if __name__ == "__main__":
    unittest.main()
