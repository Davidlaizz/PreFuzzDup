import hashlib
import tempfile
import unittest
from pathlib import Path
from client_prepare import extract_checked_body


class BodyTests(unittest.TestCase):
    def test_original_body_rules_and_integrity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'mail').write_bytes(b'Subject: sample\r\n\r\n alpha\r\nbeta \r\n')
            body = b'alpha\nbeta'
            row = dict(source_path='mail', body_sha256=hashlib.sha256(body).hexdigest(),
                       body_size_bytes=str(len(body)), protocol_eligible='true')
            self.assertEqual(extract_checked_body(root, row), body)
            row['body_sha256'] = '0' * 64
            with self.assertRaises(ValueError):
                extract_checked_body(root, row)

    def test_synthetic_and_escaping_paths_never_read_as_bodies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for row in [dict(protocol_eligible='false'),
                        dict(protocol_eligible='true', source_path='../private')]:
                with self.assertRaises(ValueError):
                    extract_checked_body(root, row)


if __name__ == '__main__':
    unittest.main()
