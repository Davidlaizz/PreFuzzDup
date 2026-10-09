import unittest
from client_fallback import exhausted
from client_messages import key


class FallbackTests(unittest.TestCase):
    def test_no_candidate_is_ready_but_pending_candidate_is_not(self):
        self.assertTrue(exhausted('q', [], {}, 'run'))
        self.assertFalse(exhausted('q', [['r', 1]], {}, 'run'))

    def test_failed_nearest_requires_upload_even_if_all_can_continue(self):
        k = key(dict(run='run', uid='enron-client', query_id='q', mode='nearest', threshold='4', repeat='0'))
        self.assertTrue(exhausted('q', [['r', 1], ['r2', 2]], {k: [{'status': 'recovery_failed'}]}, 'run'))
        self.assertFalse(exhausted('q', [['r', 1]], {k: [{'status': 'accepted'}]}, 'run'))


if __name__ == '__main__':
    unittest.main()
