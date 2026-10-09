import unittest
try:
    import prefuzz_artifacts as artifacts
except ModuleNotFoundError:
    artifacts = None


class PrefuzzArtifactTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(artifacts, 'PreFuzzDup artifact planner is required')

    def test_only_protocol_eligible_candidates_get_reference_cipher_inputs(self):
        queries = [
            {'query_id': 'q1', 'protocol_eligible': True, 'candidates': [['r1', 0]]},
            {'query_id': 'synthetic', 'protocol_eligible': False, 'candidates': [['r2', 1]]},
            {'query_id': 'q2', 'protocol_eligible': True, 'candidates': [['r1', 2], ['r3', 4]]},
        ]
        self.assertEqual(artifacts.protocol_union(queries), {'r1': 0, 'r3': 4})

    def test_missing_query_body_is_not_marked_protocol_ready(self):
        with self.assertRaisesRegex(ValueError, 'body'):
            artifacts.require_protocol_body({'query_id': 'synthetic', 'protocol_eligible': False}, {})
        self.assertEqual(artifacts.require_protocol_body(
            {'query_id': 'q1', 'protocol_eligible': True}, {'q1': {'source_path': 'mail'}}), 'mail')


if __name__ == '__main__':
    unittest.main()
