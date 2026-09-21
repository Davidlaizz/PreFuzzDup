import tempfile
import unittest
from pathlib import Path

import run_lookup_experiment
from run_lookup_experiment import (
    check_cross_scheme,
    load_prefuzz_rows,
    largest_remainder_allocation,
    prefuzz_threshold_argument,
    parse_prefuzz_metadata,
    read_summary_source_rows,
    select_stratified,
    summarize,
)


class AllocationTests(unittest.TestCase):
    def test_largest_remainder_uses_total_and_lexicographic_tie(self):
        self.assertEqual(
            largest_remainder_allocation({"a": 65, "b": 35}, 10),
            {"a": 7, "b": 3},
        )


class ArgumentTests(unittest.TestCase):
    def test_prefuzz_threshold_uses_parser_required_default_form(self):
        self.assertEqual(prefuzz_threshold_argument(6), "default=6")


class MetadataTests(unittest.TestCase):
    def test_parses_prefuzz_build_line_with_comma_separated_fields(self):
        metadata = parse_prefuzz_metadata(
            "records=41392, tag_bits=256, index_prepare_us=1000, "
            "disk_index_reused=0, filter_bytes_estimate=12345, sqlite_cache_kib=1024\n"
        )
        self.assertEqual(metadata["records"], 41392)
        self.assertEqual(metadata["index_prepare_us"], 1000)


class PrefuzzLoaderTests(unittest.TestCase):
    def test_adds_threshold_from_separate_per_threshold_files(self):
        with tempfile.TemporaryDirectory() as directory:
            raw_dir = Path(directory)
            header = ["strategy", "query_id", "type", "repeat", "latency_us", "candidate_count"]
            for threshold in (4, 5, 6):
                run_lookup_experiment.write_csv(
                    raw_dir / f"prefuzz_t{threshold}.csv",
                    header,
                    [{"strategy": "prefuzz", "query_id": "q", "type": "text", "repeat": 0,
                      "latency_us": 1, "candidate_count": threshold}],
                )
            rows = load_prefuzz_rows(raw_dir)
            self.assertEqual([row["threshold"] for row in rows], [4, 5, 6])


class SummarySourceTests(unittest.TestCase):
    def test_prefuzz_source_rows_receive_file_threshold(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "prefuzz_t4.csv"
            run_lookup_experiment.write_csv(
                path,
                ["strategy", "query_id", "type", "repeat", "latency_us", "candidate_count"],
                [{"strategy": "prefuzz", "query_id": "q", "type": "text", "repeat": 0,
                  "latency_us": 1, "candidate_count": 0}],
            )
            rows = read_summary_source_rows("PreFuzzDup", path, 4)
            self.assertEqual(rows[0]["threshold"], 4)


class SummaryTests(unittest.TestCase):
    def test_reports_distinct_query_counts_per_group_and_threshold(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "raw"
            raw.mkdir()
            prefuzz_header = ["strategy", "query_id", "type", "repeat", "latency_us", "candidate_count"]
            for threshold in (4, 5, 6):
                run_lookup_experiment.write_csv(raw / f"prefuzz_t{threshold}.csv", prefuzz_header, [
                    {"strategy": "prefuzz", "query_id": "q1", "type": "text", "repeat": 0,
                     "latency_us": 1, "candidate_count": 0},
                    {"strategy": "prefuzz", "query_id": "q2", "type": "text", "repeat": 0,
                     "latency_us": 1, "candidate_count": 0},
                ])
            comparison_header = ["scheme", "threshold", "repeat", "query_id", "group", "latency_us",
                                 "matched", "best_distance", "records_examined", "bits_compared"]
            comparison_rows = []
            for threshold in (4, 5, 6):
                for query_id in ("q1", "q2"):
                    comparison_rows.append({"scheme": "{scheme}", "threshold": threshold, "repeat": 0,
                                            "query_id": query_id, "group": "unused", "latency_us": 1,
                                            "matched": 0, "best_distance": 128,
                                            "records_examined": 2, "bits_compared": 512})
            run_lookup_experiment.write_csv(raw / "simless_lookup.csv", comparison_header, comparison_rows)
            run_lookup_experiment.write_csv(raw / "fuzzydedup_lookup.csv", comparison_header, comparison_rows)
            run_lookup_experiment.write_csv(root / "labels.csv", ["query_id", "group", "body_sha256", "source_id"], [
                {"query_id": "q1", "group": "exact_ref", "body_sha256": "a", "source_id": "q1"},
                {"query_id": "q2", "group": "no_exact_ref", "body_sha256": "b", "source_id": "q2"},
            ])
            _, rows = summarize(raw, root, root / "labels.csv")
            self.assertTrue(all(row["queries"] == 2 for row in rows if row["group"] == "all"))
            self.assertTrue(all(row["queries"] == 1 for row in rows if row["group"] != "all"))


class StratifiedSelectionTests(unittest.TestCase):
    def test_selects_proportional_benchmark_and_balanced_verify_sets(self):
        records = [
            {"id": f"q{i:03d}", "type": "text", "tag_hex": f"{i:064x}", "body_sha256": f"h{i:02d}"}
            for i in range(10)
        ]
        reference_hashes = {record["body_sha256"] for record in records[:4]}

        benchmark, verify = select_stratified(
            records=records,
            reference_hashes=reference_hashes,
            benchmark_count=5,
            seed=20260922,
            verify_per_group=1,
        )

        groups = ["exact_ref" if record["body_sha256"] in reference_hashes else "no_exact_ref" for record in benchmark]
        self.assertEqual(groups.count("exact_ref"), 2)
        self.assertEqual(groups.count("no_exact_ref"), 3)
        self.assertEqual(len(verify), 2)
        self.assertEqual({record["group"] for record in verify}, {"exact_ref", "no_exact_ref"})


class CsvTests(unittest.TestCase):
    def test_write_csv_ignores_fields_outside_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "output.csv"
            run_lookup_experiment.write_csv(path, ["id", "type", "tag_hex"], [{"id": "q", "type": "text", "tag_hex": "00", "body_sha256": "h"}])
            self.assertEqual(path.read_text(encoding="utf-8"), "id,type,tag_hex\nq,text,00\n")


class CrossSchemeTests(unittest.TestCase):
    def test_rejects_any_matched_disagreement(self):
        prefuzz = [
            {"query_id": "q1", "threshold": 4, "repeat": 0, "candidate_count": 1},
            {"query_id": "q2", "threshold": 4, "repeat": 0, "candidate_count": 0},
        ]
        simless = [
            {"query_id": "q1", "threshold": 4, "repeat": 0, "matched": 1},
            {"query_id": "q2", "threshold": 4, "repeat": 0, "matched": 0},
        ]
        fuzzy = [
            {"query_id": "q1", "threshold": 4, "repeat": 0, "matched": 1},
            {"query_id": "q2", "threshold": 4, "repeat": 0, "matched": 1},
        ]

        with self.assertRaisesRegex(ValueError, "q2"):
            check_cross_scheme(prefuzz, simless, fuzzy)


if __name__ == "__main__":
    unittest.main()
