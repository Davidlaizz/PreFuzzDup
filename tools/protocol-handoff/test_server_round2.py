"""Round-2 planning uses only public evidence; never consumes server tokens."""
import unittest
import csv
import json
import os
import sqlite3
import tempfile
from pathlib import Path
from collections import Counter
from unittest.mock import patch

try:
    import server_round2 as worker
except ImportError:
    worker = None

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / 'handoff/20261008-prefuzzdup-cipher-import'
REQUEST = ROOT / 'handoff/20261009-prefuzz-client-run/client-request.json'
RUN = ROOT / 'handoff-results/prefuzz-full-20261009'


class Round2Tests(unittest.TestCase):
    def test_sixth_candidate_plan(self):
        tasks, evidence = worker.plan(PACKAGE, REQUEST, RUN, 5)
        self.assertEqual(len(tasks), 135)
        self.assertEqual(Counter(r['threshold'] for r in tasks), {'4': 33, '5': 48, '6': 54})
        self.assertTrue(all(r['candidate_rank'] == '5' and r['mode'] == 'all' for r in tasks))
        self.assertEqual(len(evidence['prior_tokens']), 8271)
        self.assertEqual(evidence['prior_rounds_checked'], 5)

    def test_fifth_candidate_plan(self):
        tasks, evidence = worker.plan(PACKAGE, REQUEST, RUN, 4)
        self.assertEqual(len(tasks), 150)
        self.assertEqual(Counter(r['threshold'] for r in tasks), {'4': 36, '5': 54, '6': 60})
        self.assertTrue(all(r['candidate_rank'] == '4' and r['mode'] == 'all' for r in tasks))
        self.assertEqual(len(evidence['prior_tokens']), 8121)
        self.assertEqual(evidence['prior_rounds_checked'], 4)

    def test_fourth_candidate_plan(self):
        tasks, evidence = worker.plan(PACKAGE, REQUEST, RUN, 3)
        self.assertEqual(len(tasks), 171)
        self.assertEqual(Counter(r['threshold'] for r in tasks), {'4': 45, '5': 60, '6': 66})
        self.assertTrue(all(r['candidate_rank'] == '3' and r['mode'] == 'all' for r in tasks))
        self.assertEqual(len(evidence['prior_tokens']), 7950)

    def test_issue_packaging_and_repeat_guard(self, rank=2, count=186):
        self.assertIsNotNone(worker)
        _, evidence = worker.plan(PACKAGE, REQUEST, RUN, rank)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = root / 'store'
            store.mkdir()
            (store / 'protocol.sqlite').touch()
            binary = root / 'binary'
            binary.touch()
            session = root / 'session.sqlite'
            with sqlite3.connect(session) as db:
                db.execute('CREATE TABLE protocol_challenges(token BLOB PRIMARY KEY,binding BLOB NOT NULL,message BLOB NOT NULL,vk BLOB NOT NULL,expires INTEGER NOT NULL,used INTEGER NOT NULL DEFAULT 0)')
                db.executemany('INSERT INTO protocol_challenges VALUES(?,X\'\',X\'\',X\'\',0,1)',
                               [(bytes.fromhex(t),) for t in evidence['prior_tokens']])
            db.close()
            argv = ['server_round2.py', 'issue', '--candidate-round', str(rank), '--package', str(PACKAGE), '--request', str(REQUEST),
                    '--root', str(RUN), '--store', os.environ.get('ROUND2_TEST_STORE', str(store)),
                    '--session-db', str(session), '--session-binary', os.environ.get('ROUND2_TEST_BINARY', str(binary)),
                    '--work', str(root / 'work'), '--output', str(root / 'out')]
            real_run = worker.subprocess.run

            def issue(command, **kwargs):
                if command[0] == 'git' or os.environ.get('ROUND2_TEST_BINARY'):
                    return real_run(command, **kwargs)
                with Path(command[-2]).open() as f:
                    tasks = list(csv.DictReader(f, fieldnames=worker.TASK, delimiter='\t'))
                rows = [{**t, 'token': format(i + 1, '064x'), 'status': 'issued', 'challenge_us': '1'}
                        for i, t in enumerate(tasks)]
                worker.write_csv(Path(command[-1]), worker.TASK + ['status', 'challenge_us'], rows)
                with sqlite3.connect(session) as db:
                    db.executemany('INSERT INTO protocol_challenges VALUES(?,X\'\',X\'\',X\'\',0,0)',
                                   [(bytes.fromhex(r['token']),) for r in rows])
                db.close()

            with patch('sys.argv', argv), patch.object(worker.subprocess, 'run', side_effect=issue):
                worker.main()
            m = worker.checked_manifest(root / 'out', 'next-round-manifest.json')
            self.assertEqual((m['candidate_round'], m['next_challenges']), (rank, count))
            self.assertEqual(m['prior_rounds_checked'], rank)
            _, rows = worker.read_bundle(root / 'out/challenges', 'prefuzzdup-challenges-v1',
                                         m['run_id'], m['package_manifest_sha256'], 'challenges.csv')
            self.assertEqual({r['candidate_rank'] for r in rows}, {str(rank)})
            argv[-3], argv[-1] = str(root / 'work2'), str(root / 'out2')
            with patch('sys.argv', argv), patch.object(worker.subprocess, 'run') as call:
                with self.assertRaisesRegex(ValueError, 'session already advanced'):
                    worker.main()
                call.assert_not_called()

    def test_fifth_issue_packaging_and_repeat_guard(self):
        self.test_issue_packaging_and_repeat_guard(4, 150)

    def test_sixth_issue_packaging_and_repeat_guard(self):
        self.test_issue_packaging_and_repeat_guard(5, 135)

    def test_frozen_plan_and_failed_prefix(self):
        self.assertIsNotNone(worker, 'validated third-candidate handoff is required')
        tasks, evidence = worker.plan(PACKAGE, REQUEST, RUN)
        self.assertEqual(len(tasks), 186)
        self.assertEqual(Counter(r['threshold'] for r in tasks), {'4': 54, '5': 60, '6': 72})
        self.assertTrue(all(r['mode'] == 'all' and r['candidate_rank'] == '2' for r in tasks))
        self.assertEqual(len({worker.key(r) for r in tasks}), 186)
        self.assertEqual(evidence['prior_rounds_checked'], 2)

    def test_duplicate_or_false_success_is_rejected(self):
        self.assertIsNotNone(worker, 'validated third-candidate handoff is required')
        original = worker.read_bundle
        for corruption in ['duplicate', 'false_success']:
            with self.subTest(corruption=corruption):
                def corrupt(root, *args):
                    manifest, rows = original(root, *args)
                    if root == RUN / 'client-confirmation-round001/public':
                        if corruption == 'duplicate':
                            rows[1] = dict(rows[0])
                        else:
                            next(r for r in rows if r['status'] == 'recovery_failed')['status'] = 'accepted'
                    return manifest, rows
                with patch.object(worker, 'read_bundle', side_effect=corrupt):
                    with self.assertRaises(ValueError):
                        worker.plan(PACKAGE, REQUEST, RUN)


if __name__ == '__main__':
    unittest.main()
