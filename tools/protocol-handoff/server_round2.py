"""Frozen third-candidate handoff. Check mode is read-only; issue runs once."""
import argparse
import json
import platform
import re
import sqlite3
import subprocess
from collections import Counter
from contextlib import closing
from pathlib import Path

from cipher_handoff import verify, fingerprint
from client_messages import TASK, CHALLENGE, FAILURES, key, read_bundle, bundle, write_csv, validate_tasks
from import_prefuzz_artifacts import read_csv, sha


def checked_manifest(root, name):
    m = json.loads((root / name).read_text())
    for relative, expected in m['files'].items():
        path = root / relative
        if not path.resolve().is_relative_to(root.resolve()):
            raise ValueError('manifest path escape')
        actual = fingerprint(path) if isinstance(expected, dict) else sha(path)
        if actual != expected:
            raise ValueError('manifest file digest mismatch: ' + relative)
    return m


def plan(package, request_path, root, target_rank=2):
    verify(package)
    request = json.loads(request_path.read_text())
    run, digest = request['run_id'], sha(package / 'handoff-manifest.json')
    if request['package_manifest_sha256'] != digest:
        raise ValueError('request/package mismatch')
    first = root / 'server-round-000-r1'
    lookup_manifest = checked_manifest(first, 'server-round-manifest.json')
    if lookup_manifest['client_request_sha256'] != sha(request_path):
        raise ValueError('lookup/request mismatch')
    queries, truth = {}, {}
    for dataset in ['verify_100', 'bench_5000']:
        flags = {r['query_id']: r['protocol_eligible'] == 'True' for r in
                 read_csv(package / 'inputs' / f'query_groups_{dataset}.csv')[1]}
        queries.update({r['id']: {**r, 'protocol_eligible': flags[r['id']]} for r in
                        read_csv(package / 'inputs' / f'queries_{dataset}.csv')[1]})
        for row in read_csv(first / 'lookup' / f'{dataset}_all_t6.csv')[1]:
            choices = json.loads(row['candidates_json'])
            if row['query_id'] in truth and truth[row['query_id']] != choices:
                raise ValueError('repeated lookup differs')
            truth[row['query_id']] = choices
    if target_rank not in (2, 3):
        raise ValueError('only round 2 and round 3 are frozen')
    history, evidence, last = {}, {}, []
    rounds = [(0, 'round000-r1', first),
              (1, 'round001', root / 'server-next-round-001'),
              (2, 'round002', root / 'server-next-round-002')]
    for rank, suffix, challenge_dir in rounds[:target_rank]:
        name = 'server-round-manifest.json' if rank == 0 else 'next-round-manifest.json'
        cm = checked_manifest(challenge_dir, name)
        challenge_manifest, challenges = read_bundle(challenge_dir / 'challenges',
            'prefuzzdup-challenges-v1', run, digest, 'challenges.csv')
        if cm['status'] != 'awaiting_client_proofs' or cm['run_id'] != run or cm['package_manifest_sha256'] != digest:
            raise ValueError('challenge manifest binding')
        if rank and challenge_manifest['confirmations_sha256'] != sha(
                root / f'client-confirmation-{rounds[rank - 1][1]}/public/confirmations.csv'):
            raise ValueError('failed-prefix manifest mismatch')
        validate_tasks(challenges, run, queries, truth, history)
        proof_root = root / f'client-proof-{suffix}/public'
        receipt_root = root / f'server-receipts-{suffix}'
        confirmation_root = root / f'client-confirmation-{suffix}/public'
        pm, proofs = read_bundle(proof_root, 'prefuzzdup-proofs-v1', run, digest, 'proofs.csv')
        rm, receipts = read_bundle(receipt_root / 'receipts', 'prefuzzdup-receipts-v1', run, digest, 'receipts.csv')
        fm, confirmations = read_bundle(confirmation_root, 'prefuzzdup-confirmations-v1', run, digest, 'confirmations.csv')
        vm = checked_manifest(receipt_root, 'server-verify-manifest.json')
        if (pm['challenges_sha256'] != sha(challenge_dir / 'challenges/challenges.csv') or
                rm['proofs_sha256'] != sha(proof_root / 'proofs.csv') or
                fm['receipts_sha256'] != sha(receipt_root / 'receipts/receipts.csv') or
                vm['server_round_manifest_sha256'] != sha(challenge_dir / name) or
                vm['client_proofs_manifest_sha256'] != sha(proof_root / 'message-manifest.json') or
                vm['status'] != 'awaiting_client_recovery'):
            raise ValueError('round chain mismatch')
        tokens = {r['token'] for r in challenges}
        maps = []
        for rows in [proofs, receipts, confirmations]:
            by_token = {r['token']: r for r in rows}
            if len(rows) != len(tokens) or set(by_token) != tokens:
                raise ValueError('message coverage mismatch')
            maps.append(by_token)
        for challenge in challenges:
            p, r, f = [m[challenge['token']] for m in maps]
            if any(any(row[n] != challenge[n] for n in TASK) for row in [p, r, f]):
                raise ValueError('task binding mismatch')
            allowed = ({'accepted', 'similarity_rejected', 'decrypt_failed', 'integrity_failed',
                        'recovery_failed', 'verification_key_mismatch'} if r['status'] == 'verified'
                       else {'server_rejected'} if r['status'] == 'rejected' else {p['status']})
            if (p['status'] not in {'signed', 'recovery_failed', 'verification_key_mismatch'} or
                    r['status'] not in ({'verified', 'rejected'} if p['status'] == 'signed' else {'client_failed'}) or
                    f['status'] not in allowed or int(challenge['candidate_rank']) != rank):
                raise ValueError('confirmation status mismatch')
            history.setdefault(key(challenge), []).append({'token': challenge['token'], 'status': f['status']})
        evidence[f'confirmations_rank{rank}_sha256'] = sha(confirmation_root / 'confirmations.csv')
        last = confirmations
    tasks = []
    for row in last:
        choices = [c for c in truth[row['query_id']] if c[1] <= int(row['threshold'])]
        if row['mode'] == 'all' and row['status'] in FAILURES and len(choices) > target_rank:
            tasks.append({**{n: row[n] for n in TASK}, 'record_id': choices[target_rank][0],
                          'token': '', 'candidate_rank': str(target_rank)})
    expected = ({2: (186, {'4': 54, '5': 60, '6': 72}),
                 3: (171, {'4': 45, '5': 60, '6': 66})})[target_rank]
    if len(tasks) != expected[0] or Counter(r['threshold'] for r in tasks) != expected[1]:
        raise ValueError('frozen candidate coverage differs')
    evidence.update(prior_rounds_checked=2, run_id=run, package_manifest_sha256=digest,
                    prior_tokens=[h['token'] for hs in history.values() for h in hs])
    return tasks, evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=['check', 'issue'])
    parser.add_argument('--candidate-round', type=int, choices=[2, 3], default=2)
    for n in ['package', 'request', 'root']:
        parser.add_argument('--' + n, type=Path, required=True)
    for n in ['store', 'session-db', 'session-binary', 'work', 'output']:
        parser.add_argument('--' + n, type=Path)
    args = parser.parse_args()
    tasks, evidence = plan(args.package, args.request, args.root, args.candidate_round)
    if args.stage == 'check':
        print(json.dumps({'status': 'passed', 'tasks': len(tasks), 'candidate_rank': args.candidate_round}))
        return
    if any(v is None for v in [args.store, args.session_db, args.session_binary, args.work, args.output]):
        raise ValueError('issue requires store/session/binary/work/output')
    if args.work.exists() or args.output.exists():
        raise FileExistsError('keep existing evidence; do not retry issue')
    if not (args.store / 'protocol.sqlite').is_file() or not args.session_db.is_file() or not args.session_binary.is_file():
        raise ValueError('existing store/session/binary required')
    # One receipt per prior token must already have consumed its challenge.
    with closing(sqlite3.connect(args.session_db.resolve().as_uri() + '?mode=ro', uri=True)) as db:
        if db.execute('SELECT count(*) FROM protocol_challenges').fetchone()[0] != len(evidence['prior_tokens']):
            raise ValueError('session already advanced or belongs to another run')
        for token in evidence['prior_tokens']:
            if db.execute('SELECT used FROM protocol_challenges WHERE token=?', (bytes.fromhex(token),)).fetchone() != (1,):
                raise ValueError('prior token not consumed in this session')
    args.work.mkdir(parents=True)
    args.output.mkdir(parents=True)
    fields, records = read_csv(args.package / 'artifacts/records.csv')
    write_csv(args.work / 'records.tsv', fields, records, '\t', False)
    write_csv(args.work / 'tasks.tsv', TASK, tasks, '\t', False)
    environment = {'platform': platform.platform(), 'code_commit': subprocess.check_output(
        ['git', 'rev-parse', 'HEAD'], text=True).strip(), 'script_sha256': sha(Path(__file__)),
        'session_binary_sha256': sha(args.session_binary), 'git_transfer_measured': False}
    (args.output / 'environment.json').write_text(json.dumps(environment, indent=2))
    command = [str(args.session_binary.resolve()), 'issue', str(args.store.resolve()),
               str(args.session_db.resolve()), str((args.work / 'records.tsv').resolve()),
               str((args.work / 'tasks.tsv').resolve()), str((args.output / 'challenge-metrics.csv').resolve())]
    with (args.output / 'issue.stdout').open('wb') as out, (args.output / 'issue.stderr').open('wb') as err:
        subprocess.run(command, stdout=out, stderr=err, check=True)
    rows = read_csv(args.output / 'challenge-metrics.csv')[1]
    if len(rows) != len(tasks) or any(any(r[n] != t[n] for n in TASK[:-1]) or r['status'] != 'issued'
                                    for r, t in zip(rows, tasks)):
        raise ValueError('issued rows mismatch; preserve session and evidence')
    tokens = {r['token'] for r in rows}
    if len(tokens) != len(rows) or tokens.intersection(evidence['prior_tokens']) or any(
            not re.fullmatch('[0-9a-f]{64}', t) for t in tokens):
        raise ValueError('invalid issued tokens')
    public = args.output / 'challenges'
    public.mkdir()
    write_csv(public / 'challenges.csv', CHALLENGE,
              [{**r, 'candidate_rank': str(args.candidate_round)} for r in rows])
    evidence.pop('prior_tokens')
    bundle(public, 'prefuzzdup-challenges-v1', evidence['run_id'], evidence['package_manifest_sha256'],
           'challenges.csv', {'confirmations_sha256': evidence[f'confirmations_rank{args.candidate_round - 1}_sha256'],
                              'candidate_round': args.candidate_round})
    manifest = dict(evidence, status='awaiting_client_proofs', candidate_round=args.candidate_round,
                    next_challenges=len(rows), command=command,
                    files={p.relative_to(args.output).as_posix(): sha(p) for p in args.output.rglob('*') if p.is_file()})
    (args.output / 'next-round-manifest.json').write_text(json.dumps(manifest, indent=2))
    print(f'awaiting_client_proofs: {len(rows)} challenges, rank={args.candidate_round}')


if __name__ == '__main__':
    main()
