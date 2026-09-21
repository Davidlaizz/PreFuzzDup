import unittest

from run_full_lookup_experiment import (
    duplicate_bucket,
    distribution_stats,
    scale_comparison,
)


class DistributionTests(unittest.TestCase):
    def test_duplicate_bucket_uses_right_open_ranges(self):
        self.assertEqual(duplicate_bucket(1), "1")
        self.assertEqual(duplicate_bucket(2), "2")
        self.assertEqual(duplicate_bucket(10), "3_10")
        self.assertEqual(duplicate_bucket(11), "11_100")
        self.assertEqual(duplicate_bucket(101), "over_100")

    def test_distribution_reports_tail_statistics(self):
        stats = distribution_stats(list(range(1, 101)))
        self.assertEqual(stats["samples"], 100)
        self.assertEqual(stats["mean"], 50.5)
        self.assertEqual(stats["p50"], 50)
        self.assertEqual(stats["p95"], 95)
        self.assertEqual(stats["p99"], 99)
        self.assertEqual(stats["max"], 100)

    def test_distribution_sorts_unsorted_input_before_quantiles(self):
        values = [100, 1, 50, 95, 99]
        stats = distribution_stats(values)
        self.assertEqual(stats["p50"], 95)
        self.assertEqual(stats["p95"], 100)
        self.assertEqual(stats["p99"], 100)


class ScaleTests(unittest.TestCase):
    def test_compare_to_5w_matches_scheme_threshold_and_group(self):
        old = [{"scheme": "PreFuzzDup", "threshold": 4, "group": "all", "mean_latency_us": 5.0, "matched_rate": 0.1}]
        new = [{"scheme": "PreFuzzDup", "threshold": 4, "group": "all", "mean_latency_us": 10.0, "matched_rate": 0.2}]
        result = scale_comparison(new, old)
        self.assertEqual(result[0]["scheme"], "PreFuzzDup")
        self.assertEqual(result[0]["latency_ratio"], 2.0)
        self.assertEqual(result[0]["matched_rate_delta"], 0.1)


if __name__ == "__main__":
    unittest.main()
