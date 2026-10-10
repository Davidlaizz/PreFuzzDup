"""4110: issue next all-mode candidates after a failed prior confirmation."""
import argparse
import json
import platform
import sqlite3
import subprocess
from collections import Counter
from pathlib import Path

from client_messages import CHALLENGE, FAILURES, TASK, bundle, read_bundle, write_csv
from import_prefuzz_artifacts import read_csv, sha


def attempt_key(row):
    return tuple(row[name] for name in TASK)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['package', 'request', 'server-round', 'client-proofs', 'receipts',
                 'confirmations', 'store', 'session-db', 'session-binary', 'work', 'output']:
        p.add_argument('--' + name, type=Path, required=True)
    args = p.parse_args()
    if args.output.exists() or args.work.exists():
        raise FileExistsError('output and work must be new directories')
    if not args.store.is_dir() or not args.session_db.is_file() or not args.session_binary.is_file():
        raise FileNotFoundError('store, session database, or session binary is missing')

    from cipher_handoff import verify
    verify(args.package)
    digest = sha(args.package / 'handoff-manifest.json')
    request = json.loads(args.request.read_text())
    run = request['run_id']
    _, proofs = read_bundle(args.client_proofs, 'prefuzzdup-proofs-v1', run, digest, 'proofs.csv')
    _, receipts = read_bundle(args.receipts, 'prefuzzdup-receipts-v1', run, digest, 'receipts.csv')
    confirm_manifest, confirmations = read_bundle(args.confirmations, 'prefuzzdup-confirmations-v1',
                                                  run, digest, 'confirmations.csv')
    round_manifest = json.loads((args.server_round / 'server-round-manifest.json').read_text())
    if (round_manifest.get('status') != 'awaiting_client_recovery' or
            round_manifest.get('run_id') != run or
            round_manifest.get('client_request_sha256') != sha(args.request) or
            confirm_manifest.get('receipts_sha256') != sha(args.receipts / 'receipts.csv')):
        raise ValueError('confirmation/receipt/round binding mismatch')

    proof_by_token = {r['token']: r for r in proofs}
    receipt_by_token = {r['token']: r for r in receipts}
    if len(proof_by_token) != len(proofs) or len(receipt_by_token) != len(receipts):
        raise ValueError('duplicate proof/receipt token')
    if (len(confirmations) != len(receipts) or
            any(r['token'] not in proof_by_token or r['token'] not in receipt_by_token for r in confirmations)):
        raise ValueError('confirmation coverage mismatch')
    statuses = Counter(r['status'] for r in confirmations)
    if statuses != Counter({'accepted': 6408, 'recovery_failed': 882, 'similarity_rejected': 180}):
        raise ValueError(f'unexpected confirmation statuses: {dict(statuses)}')
    for row in confirmations:
        proof = proof_by_token[row['token']]
        receipt = receipt_by_token[row['token']]
        if (any(row[n] != proof[n] for n in TASK) or any(row[n] != receipt[n] for n in TASK) or
                (row['status'] == 'accepted') != (receipt['status'] == 'verified') or
                (row['status'] in FAILURES and receipt['status'] != 'client_failed')):
            raise ValueError('confirmation binding/status mismatch')

    _, challenges = read_csv(args.server_round / 'challenges/challenges.csv')
    rank_by_token = {r['token']: int(r['candidate_rank']) for r in challenges}
    history = {}
    for row in confirmations:
        key = attempt_key(row)
        history.setdefault(key, []).append((rank_by_token[row['token']], row['status']))
    if any([rank for rank, _ in values] != list(range(len(values))) for values in history.values()):
        raise ValueError('non-contiguous failed candidate history')

    datasets = {}
    for dataset in ['verify_100', 'bench_5000']:
        _, rows = read_csv(args.package / 'inputs' / ('queries_' + dataset + '.csv'))
        datasets.update({r['id']: (dataset, r['tag_hex']) for r in rows})
    candidates = {}
    for path in sorted((args.server_round / 'lookup').glob('*.csv')):
        parts = path.stem.rsplit('_t', 1)
        if parts[0].endswith('_nearest'):
            mode = 'nearest'
        elif parts[0].endswith('_all'):
            mode = 'all'
        else:
            raise ValueError(f'unexpected lookup filename: {path.name}')
        threshold = parts[1]
        for row in read_csv(path)[1]:
            key = (row['query_id'], row['mode'], row['threshold'], row['repeat'])
            candidates[key] = json.loads(row['candidates_json'])

    next_tasks = []
    next_summary = Counter()
    exhausted = Counter()
    for key, attempts in history.items():
        query_id, mode, threshold, repeat = key
        last_status = attempts[-1][1]
        next_rank = len(attempts)
        if last_status not in FAILURES:
            continue
        choices = candidates.get(key, [])
        if next_rank >= len(choices):
            exhausted[(mode, last_status)] += 1
            continue
        if mode != 'all':
            exhausted[(mode, last_status)] += 1
            continue
        dataset, query_tag = datasets[query_id]
        next_tasks.append(dict(run=run, uid='enron-client', query_id=query_id, mode=mode,
                               record_id=choices[next_rank][0], threshold=threshold, repeat=repeat,
                               query_tag=query_tag, token=''))
        next_summary[(last_status, int(threshold))] += 1

    args.work.mkdir(parents=True)
    _, records = read_csv(args.package / 'artifacts/records.csv')
    records_tsv = args.work / 'records.tsv'
    tasks_tsv = args.work / 'next-tasks.tsv'
    write_csv(records_tsv, read_csv(args.package / 'artifacts/records.csv')[0], records, '\t', False)
    write_csv(tasks_tsv, TASK, next_tasks, '\t', False)

    args.output.mkdir(parents=True)
    issued_csv = args.output / 'next-challenge-metrics.csv'
    command = [str(args.session_binary.resolve()), 'issue', str(args.store.resolve()),
               str(args.session_db.resolve()), str(records_tsv), str(tasks_tsv), str(issued_csv)]
    with (args.output / 'issue.stdout').open('wb') as out, (args.output / 'issue.stderr').open('wb') as err:
        subprocess.run(command, stdout=out, stderr=err, check=True)
    fields, issued = read_csv(issued_csv)
    if (len(issued) != len(next_tasks) or
            any(any(r[n] != t[n] for n in TASK[:-1]) or r['status'] != 'issued'
                for r, t in zip(issued, next_tasks))):
        raise ValueError('issued next-candidate coverage mismatch')

    challenge_root = args.output / 'challenges'
    challenge_root.mkdir()
    challenge_rows = []
    for rank, task in enumerate(next_tasks):
        issued_row = issued[rank]
        challenge_rows.append({**task, 'token': issued_row['token'], 'candidate_rank': str(next_rank)})
    write_csv(challenge_root / 'challenges.csv', CHALLENGE, challenge_rows)
    bundle(challenge_root, 'prefuzzdup-challenges-v1', run, digest, 'challenges.csv',
           {'confirmations_sha256': sha(args.confirmations / 'confirmations.csv'),
            'candidate_round': 1})

    environment = dict(platform=platform.platform(), cpu_info=Path('/proc/cpuinfo').read_text(),
                       code_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
                       compiler=subprocess.check_output(['g++', '--version'], text=True),
                       openssl=subprocess.check_output(['openssl', 'version'], text=True),
                       sqlite_python_version=sqlite3.sqlite_version,
                       session_binary_sha256=sha(args.session_binary), git_transfer_measured=False)
    (args.output / 'environment.json').write_text(json.dumps(environment, indent=2))
    manifest = dict(status='awaiting_client_proofs', run_id=run, candidate_round=1,
                    package_manifest_sha256=digest, confirmations=len(confirmations),
                    next_challenges=len(challenge_rows), next_summary={f'{k[0]}_t{k[1]}': v for k, v in sorted(next_summary.items())},
                    exhausted={f'{k[0]}_{k[1]}': v for k, v in sorted(exhausted.items())},
                    confirmations_sha256=sha(args.confirmations / 'confirmations.csv'),
                    receipts_manifest_sha256=sha(args.receipts / 'message-manifest.json'),
                    command=command, files={p.relative_to(args.output).as_posix(): sha(p)
                                            for p in sorted(args.output.rglob('*')) if p.is_file()})
    (args.output / 'next-round-manifest.json').write_text(json.dumps(manifest, indent=2))
    print(json.dumps({k: manifest[k] for k in ['status', 'candidate_round', 'next_challenges',
                                               'next_summary', 'exhausted']}, indent=2))


if __name__ == '__main__':
    main()
