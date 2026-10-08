import json
import tempfile
import unittest
from pathlib import Path
import cipher_handoff as handoff


class ManifestTests(unittest.TestCase):
    def test_integrity_and_whitelist_are_both_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'inputs/reference.csv'
            path.parent.mkdir()
            path.write_text('id,type,tag_hex\n')
            manifest = {'files': {'inputs/reference.csv': handoff.fingerprint(path)}}
            (root / 'handoff-manifest.json').write_text(json.dumps(manifest))
            handoff.verify(root)
            path.write_text('changed')
            with self.assertRaises(ValueError):
                handoff.verify(root)
            manifest['files'] = {'../private-bodies.tsv': {}}
            (root / 'handoff-manifest.json').write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                handoff.verify(root)

    def test_unlisted_private_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'handoff-manifest.json').write_text('{"files": {}}')
            (root / 'private-bodies.tsv').write_text('plaintext')
            with self.assertRaises(ValueError):
                handoff.verify(root)


if __name__ == '__main__':
    unittest.main()
