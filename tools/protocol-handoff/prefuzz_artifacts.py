#!/usr/bin/env python3
"""Build PreFuzzDup-only protocol input manifests; never creates ciphertext."""
import argparse
import csv
import hashlib
import json
from pathlib import Path


def protocol_union(rows):
    result = {}
    for row in rows:
        if row['protocol_eligible']:
            for rid, distance in row['candidates']:
                result[rid] = min(result.get(rid, distance), distance)
    return result


def require_protocol_body(row, manifest):
    if not row['protocol_eligible']:
        raise ValueError(f"query {row['query_id']} has no protocol body")
    try:
        return manifest[row['query_id']]['source_path']
    except KeyError as exc:
        raise ValueError(f"query {row['query_id']} body is missing") from exc


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def rows(path):
    with path.open(newline='', encoding='utf-8') as handle:
        return list(csv.DictReader(handle))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    inventory = json.loads((args.inventory / 'inventory_summary.json').read_text())
    split = json.loads((args.inputs / 'split_summary.json').read_text())
    if sha(args.inputs / 'split_summary.json') != inventory['input_summary_sha256']:
        raise ValueError('inventory/input summary mismatch')
    if sha(args.manifest) != split['input_sha256']['manifest.csv']:
        raise ValueError('corpus manifest mismatch')
    for root, checks in ((args.inputs, split['output_sha256']),
                         (args.inventory, inventory['output_sha256'])):
        for name, digest in checks.items():
            if Path(name).name != name or sha(root / name) != digest:
                raise ValueError(f'input hash mismatch: {name}')
    if inventory['status'] != 'passed' or inventory['protocol_union_count'] != 2259:
        raise ValueError('candidate inventory is not the verified PreFuzzDup input')
    with (args.inventory / 'query_candidates_t6.jsonl').open(encoding='utf-8') as handle:
        candidates = [json.loads(line) for line in handle]
    union = protocol_union(candidates)
    if len(union) != inventory['protocol_union_count']:
        raise ValueError('protocol union count mismatch')
    tags = {row['id']: row['tag_hex'] for row in rows(args.inputs / 'reference.csv')}
    manifest = {row['id']: row for row in rows(args.manifest)}
    references = []
    for rid, distance in sorted(union.items(), key=lambda item: (item[1], item[0])):
        if rid not in manifest:
            raise ValueError(f'missing reference manifest row: {rid}')
        row = manifest[rid]
        references.append({'record_id': rid, 'type': 'text', 'tag_hex': tags[rid],
                           'source_path': row['source_path'], 'body_sha256': row['body_sha256'],
                           'body_size_bytes': row['body_size_bytes'], 'min_distance': distance})
    query_rows = []
    for dataset in ('bench_5000', 'verify_100'):
        qpath = args.inputs / f'queries_{dataset}.csv'
        gpath = args.inputs / f'query_groups_{dataset}.csv'
        q = {r['id']: r for r in rows(qpath)}
        groups = {r['query_id']: r for r in rows(gpath)}
        for qid, row in q.items():
            group = groups[qid]
            eligible = group['protocol_eligible'] == 'True'
            source_path = ''
            if eligible:
                source_path = require_protocol_body({'query_id': qid, 'protocol_eligible': True}, manifest)
            query_rows.append({'query_id': qid, 'dataset': dataset, 'group': group['group'],
                               'protocol_eligible': str(eligible).lower(), 'tag_hex': row['tag_hex'],
                               'source_path': source_path, 'body_sha256': manifest[qid]['body_sha256'] if eligible and qid in manifest else '',
                               'body_size_bytes': manifest[qid]['body_size_bytes'] if eligible and qid in manifest else ''})
    def write(path, fields, data):
        with path.open('x', newline='', encoding='utf-8') as handle:
            writer = csv.DictWriter(handle, fieldnames=fields, lineterminator='\n')
            writer.writeheader(); writer.writerows(data)
    write(args.output / 'reference_cipher_inputs.csv', list(references[0]), references)
    write(args.output / 'query_protocol_inputs.csv', list(query_rows[0]), query_rows)
    report = {'scheme': 'PreFuzzDup', 'threshold': 6, 'reference_tag_count': 413921,
              'benchmark_query_count': 5000, 'verify_query_count': 100,
              'protocol_eligible_query_count': sum(r['protocol_eligible'] == 'true' for r in query_rows),
              'reference_cipher_input_count': len(references),
              'synthetic_query_count': sum(r['protocol_eligible'] == 'false' for r in query_rows),
              'ciphertext_generated': False, 'keys_generated': False, 'handoff_ready': False,
              'inventory_sha256': sha(args.inventory / 'inventory_summary.json'),
              'input_summary_sha256': sha(args.inputs / 'split_summary.json'),
              'code_sha256': sha(Path(__file__))}
    report['output_sha256'] = {p.name: sha(p) for p in sorted(args.output.iterdir())}
    with (args.output / 'prefuzz_artifact_plan.json').open('x', encoding='utf-8') as handle:
        json.dump(report, handle, indent=2)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
