import random
import tempfile
import unittest
from pathlib import Path

try:
    import prepare_queries as prep
except ModuleNotFoundError:
    prep = None


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(prep, "Reproducible body-preserving preparation is required")

    def test_sampling_does_not_depend_on_population_order(self):
        population = ["q3", "q1", "q2", "q4"]
        self.assertEqual(prep.sample_ids(population, 3, 42),
                         prep.sample_ids(reversed(population), 3, 42))

    def test_edit_preserves_signature_layout_and_case(self):
        body = b"Hello, TEAM!\n\nRegards,\nAlice"
        self.assertEqual(prep.edit_word(body, 1, b"group"),
                         b"Hello, group!\n\nRegards,\nAlice")

    def test_distance_scan_matches_independent_integer_popcount(self):
        rng = random.Random(19)
        tags = [rng.randbytes(32) for _ in range(25)] + [bytes(32)]
        index = prep.DistanceIndex(tags)
        for tag in tags[:4] + [bytes([255]) * 32]:
            expected = [(int.from_bytes(tag, "little") ^
                         int.from_bytes(ref, "little")).bit_count() for ref in tags]
            self.assertEqual(index.distances(tag).tolist(), expected)

    def test_saved_body_is_available_for_encryption_and_has_correct_digest(self):
        body = b"Alpha beta gamma.\nSigned Alice."
        with tempfile.TemporaryDirectory() as folder:
            metadata = prep.store_body(Path(folder), "q1", body, prep.tag_of(body))
            saved = Path(folder) / metadata["body_path"]
            self.assertEqual(saved.read_bytes(), body)
            self.assertEqual(metadata["body_sha256"], prep.digest(body))

    def test_incorrect_tag_cannot_be_published_with_a_body(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError, "tag mismatch"):
                prep.store_body(Path(folder), "q1", b"alpha beta gamma", bytes(32))


if __name__ == "__main__":
    unittest.main()
