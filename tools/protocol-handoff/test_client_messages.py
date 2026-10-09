import unittest
from client_messages import validate_tasks, key


class MessageTests(unittest.TestCase):
    def setUp(self):
        self.row = dict(run='run1', uid='enron-client', query_id='q1', mode='all', record_id='r1',
                        threshold='4', repeat='0', query_tag='00' * 32, token='11' * 32, candidate_rank='0')
        self.queries = {'q1': dict(tag_hex='00' * 32, protocol_eligible=True)}
        self.candidates = {'q1': [['r1', 1], ['r2', 2]]}

    def call(self, rows=None, history=None):
        validate_tasks(rows or [self.row], 'run1', self.queries, self.candidates, history or {})

    def test_first_candidate_and_no_duplicates(self):
        self.call()
        with self.assertRaises(ValueError):
            self.call([self.row, self.row])

    def test_synthetic_run_tag_and_nearest_gate(self):
        for field, value in [('run', 'other'), ('query_tag', 'ff' * 32), ('uid', 'bob')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.call([{**self.row, field: value}])
        self.queries['q1']['protocol_eligible'] = False
        with self.assertRaises(ValueError):
            self.call()

    def test_all_requires_failed_prefix_and_stops_after_acceptance(self):
        second = {**self.row, 'record_id': 'r2', 'candidate_rank': '1', 'token': '22' * 32}
        with self.assertRaises(ValueError):
            self.call([second])
        history = {key(self.row): [{'token': self.row['token'], 'status': 'recovery_failed'}]}
        self.call([second], history)
        with self.assertRaises(ValueError):
            self.call([{**second, 'mode': 'nearest'}], history)
        history[key(self.row)][0]['status'] = 'accepted'
        with self.assertRaises(ValueError):
            self.call([second], history)


if __name__ == '__main__':
    unittest.main()
