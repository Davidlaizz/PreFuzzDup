"""Replay public receipts to test packaging without consuming real tokens."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import server_verify_proofs as worker
from import_prefuzz_artifacts import sha

ROOT = Path(__file__).resolve().parents[2]
RUN = ROOT / 'handoff-results/prefuzz-full-20261009'


class MetadataTests(unittest.TestCase):
    def test_both_rounds_finish_and_bind_the_correct_manifest(self):
        for round_id, challenge, proof, receipt, manifest in [
            (0, 'server-round-000-r1', 'client-proof-round000-r1',
             'server-receipts-round000-r1', 'server-round-manifest.json'),
            (1, 'server-next-round-001', 'client-proof-round001',
             'server-receipts-round001', 'next-round-manifest.json'),
            (2, 'server-next-round-002', 'client-proof-round002',
             None, 'next-round-manifest.json'),
        ]:
            with self.subTest(round=round_id), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                store = root / 'store'
                store.mkdir()
                binary = root / 'binary'
                session = root / 'session.sqlite'
                binary.touch()
                session.touch()
                output = root / 'output'
                arguments = dict(package=ROOT / 'handoff/20261008-prefuzzdup-cipher-import',
                    request=ROOT / 'handoff/20261009-prefuzz-client-run/client-request.json',
                    server_round=RUN / challenge, client_proofs=RUN / proof / 'public',
                    store=store, session_db=session, session_binary=binary,
                    work=root / 'work', output=output, candidate_round=round_id,
                    confirmations=RUN / ('client-confirmation-round001/public' if round_id == 2
                                         else 'client-confirmation-round000-r1/public'))
                argv = ['server_verify_proofs.py']
                for name, value in arguments.items():
                    argv += ['--' + name.replace('_', '-'), str(value)]
                original_read = Path.read_text

                def read_text(path, *args, **kwargs):
                    if path.as_posix() == '/proc/cpuinfo':
                        return 'test cpu'
                    return original_read(path, *args, **kwargs)

                def replay(command, **kwargs):
                    if receipt:
                        shutil.copyfile(RUN / receipt / 'receipts/receipts.csv', command[-1])
                    else:
                        _, proofs = worker.read_csv(RUN / proof / 'public/proofs.csv')
                        worker.write_csv(Path(command[-1]), worker.TASK + ['status'],
                            [{**r, 'status': 'verified' if r['status'] == 'signed' else 'client_failed'}
                             for r in proofs])

                with patch('sys.argv', argv), patch.object(Path, 'read_text', read_text), \
                        patch.object(worker.subprocess, 'run', side_effect=replay) as call, \
                        patch.object(worker.subprocess, 'check_output', return_value='test'):
                    try:
                        worker.main()
                    except FileNotFoundError as exc:
                        self.fail('packaging failed after token-consuming step: ' + str(exc))
                call.assert_called_once()
                expected = sha(RUN / challenge / manifest)
                for name in ['server-verify-manifest.json', 'receipts/message-manifest.json']:
                    self.assertEqual(json.loads((output / name).read_text())[
                        'server_round_manifest_sha256'], expected)
                if receipt:
                    self.assertEqual(sha(output / 'receipts/receipts.csv'),
                                     sha(RUN / receipt / 'receipts/receipts.csv'))
                else:
                    result = json.loads((output / 'server-verify-manifest.json').read_text())
                    self.assertEqual((result['candidate_round'], result['receipts']), (2, 186))


if __name__ == '__main__':
    unittest.main()
