import csv
import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path
try:
    import import_prefuzz_artifacts as importer
except ModuleNotFoundError:
    importer = None


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importer, 'Validated protocol-only import is required')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.package = self.root / 'package'
        (self.package / 'blobs').mkdir(parents=True)
        self.rid = 'ab' * 16
        self.blob = self.package / 'blobs' / (self.rid + '.bin')
        self.blob.write_bytes(b'ciphertext')
        self.row = dict(record_id='r1', protocol_rid=self.rid, type='text',
                        cipher_path='blobs/' + self.rid + '.bin', cipher_bytes='10',
                        cipher_sha256=hashlib.sha256(b'ciphertext').hexdigest(), prepare_total_us='1')
        for field, size in importer.HEX_SIZES.items():
            self.row[field + '_hex'] = '00' * size
        self.refs = {'r1': self.row['tag_hex'], 'r2': 'ff' * 32}

    def run_import(self, rows=None, digest=None):
        path = self.package / 'records.csv'
        with path.open('w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=importer.FIELDS)
            writer.writeheader()
            writer.writerows(rows if rows is not None else [self.row])
        return importer.import_package(self.package, self.root / 'server', self.refs,
                                       {'r1'}, digest or importer.sha(path))

    def test_roundtrip_keeps_full_reference_separate(self):
        report = self.run_import()
        self.assertEqual(report['records'], 1)
        with sqlite3.connect(self.root / 'server/protocol.sqlite') as db:
            self.assertEqual(db.execute('select record_id,rid,tag from protocol_records').fetchone(),
                             ('r1', self.rid, bytes(32)))
            self.assertEqual(db.execute("select count(*) from sqlite_master where name='postings'").fetchone()[0], 0)
        self.assertEqual((self.root / 'server/blobs' / self.blob.name).read_bytes(), b'ciphertext')
        with self.assertRaises(FileExistsError):
            self.run_import()

    def test_rejects_tampered_ciphertext(self):
        self.blob.write_bytes(b'Ciphertext')
        with self.assertRaisesRegex(ValueError, 'cipher'):
            self.run_import()
        self.assertFalse((self.root / 'server/import-report.json').exists())

    def test_rejects_duplicate_mapping_and_bad_tag(self):
        with self.assertRaises(ValueError):
            self.run_import([self.row, self.row])
        self.row['tag_hex'] = 'ff' * 32
        with self.assertRaises(ValueError):
            self.run_import()

    def test_rejects_path_escape_and_wrong_manifest_digest(self):
        with self.assertRaisesRegex(ValueError, 'digest'):
            self.run_import(digest='0' * 64)
        self.row['cipher_path'] = '../private-bodies.tsv'
        with self.assertRaisesRegex(ValueError, 'path'):
            self.run_import()


if __name__ == '__main__':
    unittest.main()
