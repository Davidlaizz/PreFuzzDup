import unittest
from client_round_audit import check_lookup


class LookupAuditTests(unittest.TestCase):
    def setUp(self):
        self.row = dict(query_id='q', repeat='0', mode='all', strategy='prefuzz',
                        candidate_count='2', candidates_json='[["a",0],["b",2]]')

    def test_exact_candidate_truth_and_complete_keys_required(self):
        truth = {'q': [['a', 0], ['b', 2]]}
        rows = [{**self.row, 'repeat': str(i)} for i in range(3)]
        self.assertEqual(check_lookup(rows, truth, 'all', 4), 3)
        for bad in [rows[:-1], rows + [rows[0]],
                    [{**r, 'candidates_json': '[["a",0]]', 'candidate_count': '1'} for r in rows]]:
            with self.assertRaises(ValueError):
                check_lookup(bad, truth, 'all', 4)

    def test_nearest_requires_true_first_not_merely_a_close_candidate(self):
        rows = [{**self.row, 'repeat': str(i), 'mode': 'nearest', 'candidate_count': '1',
                 'candidates_json': '[["b",2]]'} for i in range(3)]
        with self.assertRaises(ValueError):
            check_lookup(rows, {'q': [['a', 0], ['b', 2]]}, 'nearest', 4)


if __name__ == '__main__':
    unittest.main()
