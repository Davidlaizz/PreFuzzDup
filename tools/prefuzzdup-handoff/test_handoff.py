import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import handoff


class MetadataTests(unittest.TestCase):
    def test_parses_prefuzz_metadata(self):
        metadata = handoff.parse_prefuzz_metadata(
            "records=41392, tag_bits=256, index_prepare_us=123, "
            "disk_index_reused=1, filter_bytes_estimate=456, sqlite_cache_kib=1024\n"
        )
        self.assertEqual(metadata["records"], 41392)
        self.assertEqual(metadata["index_prepare_us"], 123)
        self.assertEqual(metadata["disk_index_reused"], 1)

    def test_rejects_missing_metadata(self):
        with self.assertRaisesRegex(RuntimeError, "incomplete"):
            handoff.parse_prefuzz_metadata("records=1, tag_bits=256\n")


class CommandTests(unittest.TestCase):
    def test_lookup_command_uses_default_threshold_and_fixed_parameters(self):
        command = handoff.lookup_command(
            binary=Path("/repo/PreFuzzDup/build/prefuzzdup_persistent_lookup"),
            records=Path("/package/inputs/reference.csv"),
            queries=Path("/package/inputs/queries_bench_1000.csv"),
            database=Path("/scratch/prefuzz_t4.sqlite"),
            output=Path("/package/results/prefuzz_t4.csv"),
            threshold=4,
            repeat=3,
        )
        self.assertIn("--threshold", command)
        self.assertEqual(command[command.index("--threshold") + 1], "default=4")
        self.assertEqual(command[command.index("--fpp") + 1], "0.01")
        self.assertEqual(command[command.index("--strategies") + 1], "prefuzz")
        self.assertEqual(command[command.index("--repeat") + 1], "3")
        self.assertNotIn("--verify-equivalence", command)


class PackageTests(unittest.TestCase):
    def test_client_package_records_hashes_and_validates_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            destination = root / "package"
            source.mkdir()
            handoff.write_csv(
                source / "reference.csv",
                ["id", "type", "tag_hex"],
                [{"id": "r", "type": "text", "tag_hex": "0" * 64}],
            )
            handoff.write_csv(
                source / "queries_bench_1000.csv",
                ["id", "type", "tag_hex"],
                [{"id": "q", "type": "text", "tag_hex": "1" * 64}],
            )
            handoff.write_csv(
                source / "queries_verify_100.csv",
                ["id", "type", "tag_hex"],
                [{"id": "v", "type": "text", "tag_hex": "2" * 64}],
            )
            handoff.write_json(
                source / "split_summary.json",
                {
                    "total_records": 51_740,
                    "reference_count": 1,
                    "benchmark_count": 1,
                    "verify_count": 1,
                },
            )

            with mock.patch.object(handoff, "BENCHMARK_QUERY_COUNT", 1), \
                 mock.patch.object(handoff, "VERIFY_QUERY_COUNT", 1), \
                 mock.patch.dict(handoff.SCALE_COUNTS["5w"], reference_count=1), \
                 mock.patch.object(handoff, "git_commit", lambda repo: "testcommit"):
                handoff.create_client_package("5w", source, destination, root)

            manifest = json.loads(
                (destination / "handoff-manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["scale"], "5w")
            self.assertEqual(manifest["thresholds"], [4, 5, 6])
            self.assertEqual(manifest["repeat"], 3)
            self.assertEqual(manifest["fpp"], "0.01")
            self.assertEqual(set(manifest["inputs"]), set(handoff.INPUT_FILES))
            self.assertTrue((destination / "README.md").is_file())


class OutputValidationTests(unittest.TestCase):
    def test_lookup_output_rejects_wrong_filter_workload(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.csv"
            handoff.write_csv(
                path,
                handoff.LOOKUP_HEADER,
                [{
                    "strategy": "prefuzz", "query_id": "q", "type": "text", "repeat": 0,
                    "latency_us": 1, "candidate_count": 0, "filter_queries": 4,
                    "inverted_lookups": 0, "posting_records_read": 0,
                    "full_tag_distance_computations": 0,
                }],
            )
            with self.assertRaisesRegex(RuntimeError, "filter query count"):
                handoff.validate_lookup_output(path, expected_rows=1, threshold=4)


class AnalysisTests(unittest.TestCase):
    def test_analyze_fails_on_candidate_disagreement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            package = root / "package"
            baseline = root / "baseline"
            output = root / "analysis"
            source.mkdir()
            handoff.write_csv(
                source / "reference.csv",
                ["id", "type", "tag_hex"],
                [{"id": "r", "type": "text", "tag_hex": "0" * 64}],
            )
            handoff.write_csv(
                source / "queries_bench_1000.csv",
                ["id", "type", "tag_hex"],
                [{"id": "q", "type": "text", "tag_hex": "1" * 64}],
            )
            handoff.write_csv(
                source / "queries_verify_100.csv",
                ["id", "type", "tag_hex"],
                [{"id": "v", "type": "text", "tag_hex": "2" * 64}],
            )
            handoff.write_json(
                source / "split_summary.json",
                {
                    "total_records": 51_740,
                    "reference_count": 1,
                    "benchmark_count": 1,
                    "verify_count": 1,
                },
            )
            with mock.patch.object(handoff, "BENCHMARK_QUERY_COUNT", 1), \
                 mock.patch.object(handoff, "VERIFY_QUERY_COUNT", 1), \
                 mock.patch.object(handoff, "REPEAT", 1), \
                 mock.patch.dict(handoff.SCALE_COUNTS["5w"], reference_count=1), \
                 mock.patch.object(handoff, "git_commit", lambda repo: "testcommit"):
                handoff.create_client_package("5w", source, package, root)

            baseline_inputs = baseline / "inputs"
            baseline_raw = baseline / "raw"
            baseline_inputs.mkdir(parents=True)
            baseline_raw.mkdir(parents=True)
            for name in handoff.INPUT_FILES:
                (baseline_inputs / name).write_bytes(
                    (package / "inputs" / name).read_bytes()
                )

            metadata = {
                str(threshold): {
                    "index_prepare_us": 1,
                    "disk_index_reused": 0,
                    "filter_bytes_estimate": 1,
                    "sqlite_cache_kib": 1024,
                }
                for threshold in handoff.THRESHOLDS
            }

            def result_row(candidate_count: int, threshold: int) -> dict[str, str | int]:
                return {
                    "strategy": "prefuzz",
                    "query_id": "q",
                    "type": "text",
                    "repeat": 0,
                    "latency_us": 10 + threshold,
                    "candidate_count": candidate_count,
                    "filter_queries": threshold + 1,
                    "inverted_lookups": 1,
                    "posting_records_read": 1,
                    "full_tag_distance_computations": 1,
                }

            server_results = package / "results"
            server_results.mkdir()
            for threshold in handoff.THRESHOLDS:
                handoff.write_csv(
                    server_results / f"prefuzz_t{threshold}.csv",
                    handoff.LOOKUP_HEADER,
                    [result_row(1 if threshold == 4 else 0, threshold)],
                )
                handoff.write_csv(
                    baseline_raw / f"prefuzz_t{threshold}.csv",
                    handoff.LOOKUP_HEADER,
                    [result_row(0, threshold)],
                )
            handoff.write_json(
                server_results / "server-result-manifest.json",
                {
                    "status": "passed",
                    "prefuzz_metadata": metadata,
                    "database_files": {
                        f"prefuzz_t{threshold}.sqlite": 1 for threshold in handoff.THRESHOLDS
                    },
                },
            )
            handoff.write_json(
                baseline / "run_manifest.json",
                {
                    "prefuzz_metadata": metadata,
                    "database_files": {
                        f"prefuzz_t{threshold}.sqlite": 1 for threshold in handoff.THRESHOLDS
                    },
                },
            )

            with mock.patch.object(handoff, "BENCHMARK_QUERY_COUNT", 1), \
                 mock.patch.object(handoff, "VERIFY_QUERY_COUNT", 1), \
                 mock.patch.object(handoff, "REPEAT", 1), \
                 mock.patch.dict(handoff.SCALE_COUNTS["5w"], reference_count=1):
                passed = handoff.analyze_results(package, baseline, output)
            self.assertFalse(passed)
            self.assertIn("Workload disagreements: `1`", (output / "analysis.md").read_text())


if __name__ == "__main__":
    unittest.main()
