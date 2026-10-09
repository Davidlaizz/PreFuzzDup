"""Validated client proof/recovery batches. Private input and history stay local."""
import argparse
import csv
import json
import re
from pathlib import Path
from cipher_handoff import verify, fingerprint
from client_prepare import invoke
from import_prefuzz_artifacts import read_csv, sha

TASK = ['run', 'uid', 'query_id', 'mode', 'record_id', 'threshold', 'repeat', 'query_tag', 'token']
CHALLENGE = TASK + ['candidate_rank']
FAILURES = {'recovery_failed', 'verification_key_mismatch', 'decrypt_failed', 'integrity_failed',
            'similarity_rejected', 'server_rejected'}


def key(row):
    return '/'.join(row[n] for n in ['run', 'uid', 'query_id', 'mode', 'threshold', 'repeat'])


def validate_tasks(rows, run, queries, candidates, history):
    seen, tokens = set(), {r['token'] for attempts in history.values() for r in attempts}
    for row in rows:
        if set(row) != set(CHALLENGE) or any(v is None for v in row.values()):
            raise ValueError('invalid challenge schema')
        query = queries.get(row['query_id'])
        if (row['run'] != run or row['uid'] != 'enron-client' or not query or not query['protocol_eligible'] or
                row['query_tag'] != query['tag_hex'] or row['mode'] not in ('nearest', 'all') or
                row['threshold'] not in ('4', '5', '6') or row['repeat'] not in ('0', '1', '2') or
                not re.fullmatch('[0-9a-f]{64}', row['token']) or row['token'] in tokens):
            raise ValueError('unbound/synthetic/replayed challenge')
        attempt = key(row)
        prior = history.get(attempt, [])
        valid = [rid for rid, d in candidates[row['query_id']] if d <= int(row['threshold'])]
        if row['mode'] == 'nearest':
            valid = valid[:1]
        rank = int(row['candidate_rank'])
        if (attempt in seen or rank != len(prior) or rank >= len(valid) or rank < 0 or
                valid[rank] != row['record_id'] or any(r['status'] not in FAILURES for r in prior)):
            raise ValueError('candidate order or failed-prefix violation')
        seen.add(attempt)
        tokens.add(row['token'])


def write_csv(path, fields, rows, delimiter=',', header=True):
    with path.open('x', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fields, delimiter=delimiter, lineterminator='\n', extrasaction='ignore')
        if header:
            writer.writeheader()
        writer.writerows(rows)


def bundle(root, schema, run, package_digest, name, extra=None):
    manifest = dict(schema=schema, run_id=run, package_manifest_sha256=package_digest,
                    files={name: fingerprint(root / name)}, **(extra or {}))
    (root / 'message-manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')


def read_bundle(root, schema, run, digest, name):
    m = json.loads((root / 'message-manifest.json').read_text())
    if (m['schema'] != schema or m['run_id'] != run or m['package_manifest_sha256'] != digest or
            set(m['files']) != {name} or fingerprint(root / name) != m['files'][name]):
        raise ValueError('message manifest mismatch')
    if {p.name for p in root.iterdir()} != {name, 'message-manifest.json'}:
        raise ValueError('unexpected files in message bundle')
    return m, read_csv(root / name)[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=['sign', 'recover'])
    for name in ['state', 'package', 'binary', 'input', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--plan', type=Path)
    parser.add_argument('--inventory', type=Path)
    parser.add_argument('--proofs', type=Path)
    args = parser.parse_args()
    verify(args.package)
    state = json.loads((args.state / 'client-state.json').read_text())
    digest = sha(args.package / 'handoff-manifest.json')
    if (state['package_manifest_sha256'] != digest or state['binary_sha256'] != sha(args.binary) or
            state['private_bodies_sha256'] != sha(args.state / 'private-bodies.tsv')):
        raise ValueError('client state/input/binary mismatch')
    history_path = args.state / 'attempt-history.json'
    history = json.loads(history_path.read_text()) if history_path.exists() else {}
    run = state['run_id']
    if args.output.exists():
        raise FileExistsError(args.output)
    if args.stage == 'sign':
        if not args.plan or not args.inventory:
            raise ValueError('sign requires private plan and independent candidate inventory')
        if sha(args.plan / 'prefuzz_artifact_plan.json') != state['private_plan_sha256']:
            raise ValueError('private plan mismatch')
        plan = json.loads((args.plan / 'prefuzz_artifact_plan.json').read_text())
        if sha(args.inventory / 'inventory_summary.json') != plan['inventory_sha256']:
            raise ValueError('inventory summary mismatch')
        inv = json.loads((args.inventory / 'inventory_summary.json').read_text())
        if sha(args.inventory / 'query_candidates_t6.jsonl') != inv['output_sha256']['query_candidates_t6.jsonl']:
            raise ValueError('candidate truth mismatch')
        candidates = {}
        with (args.inventory / 'query_candidates_t6.jsonl').open() as f:
            for line in f:
                item = json.loads(line)
                candidates[item['query_id']] = item['candidates']
        queries = {}
        for dataset in ['bench_5000', 'verify_100']:
            _, qrows = read_csv(args.package / 'inputs' / ('queries_' + dataset + '.csv'))
            _, groups = read_csv(args.package / 'inputs' / ('query_groups_' + dataset + '.csv'))
            flags = {r['query_id']: r['protocol_eligible'] == 'True' for r in groups}
            queries.update({r['id']: {**r, 'protocol_eligible': flags[r['id']]} for r in qrows})
        incoming, tasks = read_bundle(args.input, 'prefuzzdup-challenges-v1', run, digest, 'challenges.csv')
        validate_tasks(tasks, run, queries, candidates, history)
    else:
        if not args.proofs:
            raise ValueError('recover requires the original client proofs bundle')
        _, proofs = read_bundle(args.proofs, 'prefuzzdup-proofs-v1', run, digest, 'proofs.csv')
        incoming, receipts = read_bundle(args.input, 'prefuzzdup-receipts-v1', run, digest, 'receipts.csv')
        if incoming.get('proofs_sha256') != sha(args.proofs / 'proofs.csv'):
            raise ValueError('receipt belongs to another proof batch')
        by_token = {r['token']: r for r in proofs}
        if len(by_token) != len(proofs) or len(receipts) != len(proofs) or {r['token'] for r in receipts} != by_token.keys():
            raise ValueError('receipt/proof coverage mismatch')
        tasks = []
        for row in receipts:
            proof = by_token[row['token']]
            prior = history.get(key(proof), [])
            if (any(row[n] != proof[n] for n in TASK) or not prior or
                    prior[-1]['token'] != row['token'] or prior[-1]['status'] != 'pending'):
                raise ValueError('receipt binding/history mismatch')
            if proof['status'] == 'signed':
                if row['status'] == 'verified':
                    tasks.append({n: row[n] for n in TASK})
                elif row['status'] != 'rejected':
                    raise ValueError('invalid server verdict')
            elif row['status'] != 'client_failed':
                raise ValueError('server verified an unsigned proof')
    args.output.mkdir(parents=True)
    work = args.output / 'local-work'
    work.mkdir()
    fields, refs = read_csv(args.package / 'artifacts/records.csv')
    write_csv(work / 'records.tsv', fields, refs, '\t', False)
    write_csv(work / 'tasks.tsv', TASK, tasks, '\t', False)
    result_path = work / 'computed.csv'
    command = [args.stage, args.state / 'private-bodies.tsv', work / 'records.tsv', work / 'tasks.tsv']
    if args.stage == 'recover':
        command.append(args.package / 'artifacts')
    invoke(args.binary, command + [result_path], work)
    fields, computed = read_csv(result_path)
    if len(computed) != len(tasks) or any(any(r[n] != t[n] for n in TASK) for r, t in zip(computed, tasks)):
        raise ValueError('worker output binding mismatch')
    public = args.output / 'public'
    public.mkdir()
    if args.stage == 'sign':
        for row in computed:
            if row['status'] not in {'signed', 'recovery_failed', 'verification_key_mismatch'}:
                raise ValueError('client signing failed validation')
            history.setdefault(key(row), []).append(dict(token=row['token'], status='pending'))
        write_csv(public / 'proofs.csv', fields, computed)
        bundle(public, 'prefuzzdup-proofs-v1', run, digest, 'proofs.csv',
               {'challenges_sha256': sha(args.input / 'challenges.csv')})
    else:
        recovered = {r['token']: r for r in computed}
        terminal = []
        for row in receipts:
            proof = by_token[row['token']]
            result = recovered.get(row['token'])
            status = result['status'] if result else ('server_rejected' if proof['status'] == 'signed' else proof['status'])
            if status != 'accepted' and status not in FAILURES:
                raise ValueError('invalid terminal status')
            history[key(proof)][-1]['status'] = status
            terminal.append({**{n: proof[n] for n in TASK}, 'status': status, 'jaccard': result['jaccard'] if result else ''})
        write_csv(public / 'confirmations.csv', TASK + ['status', 'jaccard'], terminal)
        bundle(public, 'prefuzzdup-confirmations-v1', run, digest, 'confirmations.csv',
               {'receipts_sha256': sha(args.input / 'receipts.csv')})
    temporary = history_path.with_suffix('.tmp')
    temporary.write_text(json.dumps(history, indent=2), encoding='utf-8')
    temporary.replace(history_path)
    print(json.dumps({'status': 'passed', 'stage': args.stage, 'messages': len(tasks), 'public_bundle': str(public)}))


if __name__ == '__main__':
    main()
