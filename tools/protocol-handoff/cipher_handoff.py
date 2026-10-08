"""Whitelist-only ciphertext handoff; import stage, not a complete protocol runner."""
import argparse
import json
import re
import shutil
import tempfile
from pathlib import Path
from import_prefuzz_artifacts import FIELDS, import_package, read_csv, sha

INPUTS = {
    'reference.csv': (413921, ['id', 'type', 'tag_hex']),
    'queries_bench_5000.csv': (5000, ['id', 'type', 'tag_hex']),
    'queries_verify_100.csv': (100, ['id', 'type', 'tag_hex']),
    'query_groups_bench_5000.csv': (5000, ['query_id', 'group', 'dmin', 'base_id', 'protocol_eligible']),
    'query_groups_verify_100.csv': (100, ['query_id', 'group', 'dmin', 'base_id', 'protocol_eligible']),
}


def fingerprint(path):
    return {'sha256': sha(path), 'bytes': path.stat().st_size}


def allowed(name):
    return (name in {'inputs/' + n for n in INPUTS} or
            name in {'artifacts/records.csv', 'inputs/protocol_union_t6.csv', 'README.md'} or
            re.fullmatch(r'artifacts/blobs/[0-9a-f]{32}\.bin', name) is not None)


def verify(root):
    manifest = json.loads((root / 'handoff-manifest.json').read_text(encoding='utf-8'))
    for name, expected in manifest['files'].items():
        path = root / name
        if not allowed(name) or path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError('non-whitelisted path: ' + name)
        if fingerprint(path) != expected:
            raise ValueError('digest/size mismatch: ' + name)
    actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
    if actual != set(manifest['files']) | {'handoff-manifest.json'}:
        raise ValueError('unlisted files in package')
    return manifest


def validate_inputs(root):
    tables = {}
    for name, (count, fields) in INPUTS.items():
        header, rows = read_csv(root / 'inputs' / name)
        if header != fields or len(rows) != count or len({r[fields[0]] for r in rows}) != count:
            raise ValueError('input schema/count/ID mismatch: ' + name)
        if any(None in r or any(v is None for v in r.values()) for r in rows):
            raise ValueError('malformed CSV: ' + name)
        tables[name] = {r[fields[0]]: r for r in rows}
    refs = tables['reference.csv']
    bench, check = tables['queries_bench_5000.csv'], tables['queries_verify_100.csv']
    if set(refs) & (set(bench) | set(check)) or set(bench) & set(check):
        raise ValueError('overlapping query/reference IDs')
    for suffix, queries in [('bench_5000', bench), ('verify_100', check)]:
        groups = tables['query_groups_' + suffix + '.csv']
        if groups.keys() != queries.keys():
            raise ValueError('query group IDs mismatch')
    for rows in [refs, bench, check]:
        if any(r['type'] != 'text' or not re.fullmatch('[0-9a-f]{64}', r['tag_hex']) for r in rows.values()):
            raise ValueError('invalid text tag')
    fields, union = read_csv(root / 'inputs/protocol_union_t6.csv')
    expected = {r['record_id'] for r in union}
    if fields != ['record_id', 'min_distance'] or len(union) != 2259 or len(expected) != 2259:
        raise ValueError('unexpected protocol union')
    return {key: row['tag_hex'] for key, row in refs.items()}, expected


def server(package, output):
    manifest = verify(package)
    refs, expected = validate_inputs(package)
    report = import_package(package / 'artifacts', output, refs, expected,
                            manifest['files']['artifacts/records.csv']['sha256'])
    report['handoff_manifest_sha256'] = sha(package / 'handoff-manifest.json')
    (output / 'import-report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    return report


def client(inputs, artifacts, union, dest):
    if dest.exists():
        raise FileExistsError(dest)
    # Stage outside Git; publish only after full structural and import validation.
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=dest.parent) as tmp:
        root = Path(tmp) / 'package'
        (root / 'inputs').mkdir(parents=True)
        (root / 'artifacts/blobs').mkdir(parents=True)
        for name in INPUTS:
            shutil.copyfile(inputs / name, root / 'inputs' / name)
        shutil.copyfile(union, root / 'inputs/protocol_union_t6.csv')
        header, rows = read_csv(artifacts / 'records.csv')
        if header != FIELDS:
            raise ValueError('unexpected public metadata schema')
        shutil.copyfile(artifacts / 'records.csv', root / 'artifacts/records.csv')
        for row in rows:
            relative = 'blobs/' + row['protocol_rid'] + '.bin'
            if not allowed('artifacts/' + relative) or row['cipher_path'] != relative:
                raise ValueError('invalid ciphertext path')
            shutil.copyfile(artifacts / relative, root / 'artifacts' / relative)
        (root / 'README.md').write_text(
            '# PreFuzzDup import-stage package\n\n'
            'See docs/prefuzzdup-cipher-import-handoff.md in this repository.\n'
            'This package does not yet execute the full protocol.\n', encoding='utf-8')
        manifest = dict(stage='protocol_store_import_only', full_protocol_ready=False,
                        challenge_ttl_seconds=1728000, thresholds=[4, 5, 6],
                        modes=['nearest', 'all'], repeat=3,
                        communication_model=dict(rtt_ms=1, bandwidth_bps=1000000000),
                        git_wait_timed=False, files={})
        manifest['files'] = {p.relative_to(root).as_posix(): fingerprint(p)
                             for p in sorted(root.rglob('*')) if p.is_file()}
        (root / 'handoff-manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
        server(root, Path(tmp) / 'validation-store')
        shutil.move(str(root), str(dest))
    return {'status': 'passed', 'package': str(dest), 'files': len(manifest['files'])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    c = sub.add_parser('client')
    for name in ['inputs', 'artifacts', 'union', 'dest']:
        c.add_argument('--' + name, type=Path, required=True)
    s = sub.add_parser('server')
    s.add_argument('--package', type=Path, required=True)
    s.add_argument('--output', type=Path, required=True)
    args = vars(parser.parse_args())
    command = args.pop('command')
    print(json.dumps((client if command == 'client' else server)(**args), indent=2))


if __name__ == '__main__':
    main()
