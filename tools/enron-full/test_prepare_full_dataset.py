import csv
import unittest
from pathlib import Path

from prepare_full_dataset import (
    ONE_WORD_TEXT,
    QUERY_POOL_SIZE,
    REFERENCE_SIZE,
    extract_body,
    split_full_ids,
    words_of,
    simhash_tag,
)


class BodyTests(unittest.TestCase):
    def test_extracts_body_after_first_blank_line_and_normalizes_crlf(self):
        raw = b"Subject: test\r\n\r\n\r\n Alpha\tBeta\r\n\r\nquoted\r\n"
        self.assertEqual(extract_body(raw, "x"), b"Alpha\tBeta\n\nquoted")

    def test_rejects_missing_header_body_separator(self):
        with self.assertRaisesRegex(RuntimeError, "header/body separator"):
            extract_body(b"Subject: test", "x")

    def test_words_match_prefuzzdup_ascii_normalization(self):
        self.assertEqual(words_of(b" HeLLo, WORLD!!! caf\xc3\xa9 42 "), [b"hello", b"world", b"caf", b"42"])


class TagTests(unittest.TestCase):
    def test_short_text_matches_verified_5w_edge_case(self):
        edge_path = Path(__file__).resolve().parents[1] / "fixtures" / "enron-tag-edge-cases.csv"
        with edge_path.open(newline="", encoding="utf-8") as source:
            expected = {row["name"]: row["expected_hex"] for row in csv.DictReader(source)}
        self.assertEqual(expected["one_word"], ONE_WORD_TEXT.hex())

    def test_all_portable_edge_cases_match_cpp_verified_tags(self):
        fixture = Path(__file__).resolve().parents[1] / "fixtures/enron-tag-edge-cases.csv"
        with fixture.open(newline="", encoding="utf-8") as source:
            rows = list(csv.DictReader(source))
        self.assertEqual(len(rows), 9)
        for row in rows:
            with self.subTest(case=row["name"]):
                self.assertEqual(simhash_tag(words_of(bytes.fromhex(row["input_hex"]))).hex(), row["expected_hex"])


class SplitTests(unittest.TestCase):
    def test_full_split_sizes_are_exact_and_disjoint(self):
        ids = [f"enron_full_{index:06d}" for index in range(1, 517_402)]
        reference, query_pool = split_full_ids(ids, seed=20260921)
        self.assertEqual(len(reference), REFERENCE_SIZE)
        self.assertEqual(len(query_pool), QUERY_POOL_SIZE)
        self.assertEqual(REFERENCE_SIZE, 413_921)
        self.assertEqual(QUERY_POOL_SIZE, 103_480)
        self.assertFalse(set(reference) & set(query_pool))


if __name__ == "__main__":
    unittest.main()
