#!/usr/bin/env python3
"""Import public PreFuzzDup artifacts into a separate, non-search protocol store."""
import argparse
import csv
import hashlib
import json
import re
import shutil
import sqlite3
from pathlib import Path

HEX_SIZES = dict(tag=32, helper=96, vk=32, nfile=12, nwrap=12, ctag=16, wrap=32, wtag=16)
FIELDS = ['record_id', 'protocol_rid', 'type'] + [k + '_hex' for k in HEX_SIZES] + [
    'cipher_path', 'cipher_bytes', 'cipher_sha256', 'prepare_total_us']


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def read_csv(path):
    with path.open(newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        return reader.fieldnames, list(reader)


def import_package(package, output, references, expected_ids, records_digest):
    if output.exists():
        raise FileExistsError(output)
    metadata = package / 'records.csv'
    if sha(metadata) != records_digest:
        raise ValueError('records digest mismatch')
    fields, rows = read_csv(metadata)
    if fields != FIELDS or not rows:
        raise ValueError('unexpected public record schema')
    ids, rids, validated = set(), set(), []
    for row in rows:
        rid, record_id = row['protocol_rid'], row['record_id']
        if (None in row or not re.fullmatch('[0-9a-f]{32}', rid) or
                not re.fullmatch('[A-Za-z0-9_-]+', record_id) or record_id in ids or rid in rids):
            raise ValueError('invalid or duplicate record mapping')
        if row['type'] != 'text' or references.get(record_id) != row['tag_hex']:
            raise ValueError('reference tag mismatch')
        values = []
        for key, size in HEX_SIZES.items():
            text = row[key + '_hex']
            if not re.fullmatch('[0-9a-f]{' + str(2 * size) + '}', text):
                raise ValueError('malformed public field: ' + key)
            values.append(bytes.fromhex(text))
        relative = 'blobs/' + rid + '.bin'
        source = package / relative
        if row['cipher_path'] != relative or not source.resolve().is_relative_to(package.resolve()):
            raise ValueError('cipher path outside package or noncanonical path')
        if source.stat().st_size != int(row['cipher_bytes']) or sha(source) != row['cipher_sha256']:
            raise ValueError('cipher size/hash mismatch')
        ids.add(record_id)
        rids.add(rid)
        validated.append((row, values, source))
    if ids != set(expected_ids):
        raise ValueError('protocol candidate coverage mismatch')
    if sha(metadata) != records_digest:
        raise ValueError('records digest changed')
    output.mkdir(parents=True, exist_ok=False)
    (output / 'blobs').mkdir()
    # No postings table: this store must never replace the full lookup index.
    db = sqlite3.connect(output / 'protocol.sqlite')
    try:
        db.execute('CREATE TABLE protocol_records(record_id TEXT PRIMARY KEY, rid TEXT UNIQUE NOT NULL, '
                   'type TEXT NOT NULL, tag BLOB NOT NULL, helper BLOB NOT NULL, vk BLOB NOT NULL, '
                   'nfile BLOB NOT NULL, nwrap BLOB NOT NULL, ctag BLOB NOT NULL, wrap BLOB NOT NULL, '
                   'wtag BLOB NOT NULL, cipher_path TEXT NOT NULL, cipher_bytes INTEGER NOT NULL, cipher_sha256 TEXT NOT NULL)')
        with db:
            for row, values, source in validated:
                target = output / row['cipher_path']
                shutil.copyfile(source, target)
                if sha(target) != row['cipher_sha256'] or target.stat().st_size != int(row['cipher_bytes']):
                    raise ValueError('copied cipher mismatch')
                db.execute('INSERT INTO protocol_records VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                           [row['record_id'], row['protocol_rid'], 'text', *values,
                            row['cipher_path'], int(row['cipher_bytes']), row['cipher_sha256']])
        if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('SQLite integrity check failed')
        actual = db.execute('SELECT record_id,rid,tag FROM protocol_records').fetchall()
        if set(actual) != {(r['record_id'], r['protocol_rid'], values[0]) for r, values, _ in validated}:
            raise ValueError('stored mapping mismatch')
    finally:
        db.close()
    report = dict(status='passed', records=len(rows), full_reference_count=len(references),
                  cipher_bytes=sum(int(r['cipher_bytes']) for r in rows),
                  db_bytes=(output / 'protocol.sqlite').stat().st_size,
                  db_sha256=sha(output / 'protocol.sqlite'), records_sha256=records_digest,
                  code_sha256=sha(Path(__file__)), protocol_store_only=True,
                  search_index_created=False, crypto_verified_by_server=False, handoff_ready=False)
    (output / 'import-report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--records-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    split_path = args.inputs / 'split_summary.json'
    split = json.loads(split_path.read_text())
    inventory = json.loads((args.inventory / 'inventory_summary.json').read_text())
    if inventory['input_summary_sha256'] != sha(split_path) or inventory['status'] != 'passed':
        raise ValueError('inventory/input mismatch')
    ref_path = args.inputs / 'reference.csv'
    union_path = args.inventory / 'protocol_union_t6.csv'
    if sha(ref_path) != split['output_sha256']['reference.csv'] or sha(union_path) != inventory['output_sha256']['protocol_union_t6.csv']:
        raise ValueError('reference/union digest mismatch')
    _, refs = read_csv(ref_path)
    _, union = read_csv(union_path)
    references = {r['id']: r['tag_hex'] for r in refs}
    expected = {r['record_id'] for r in union}
    if len(refs) != 413921 or len(references) != 413921 or len(union) != 2259 or len(expected) != 2259:
        raise ValueError('unexpected dataset size')
    print(json.dumps(import_package(args.package, args.output, references, expected,
                                   args.records_sha256), indent=2))


if __name__ == '__main__':
    main()
