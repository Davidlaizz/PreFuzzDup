"""4110: verify a client proof bundle and return one-time-use receipts."""
import argparse
import json
import platform
import sqlite3
import subprocess
from collections import Counter
from pathlib import Path

from client_messages import TASK, bundle, read_bundle, write_csv
from import_prefuzz_artifacts import read_csv, sha


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['package', 'request', 'server-round', 'client-proofs', 'store', 'session-db',
                 'session-binary', 'work', 'output']:
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--candidate-round', type=int, choices=[0, 1], required=True)
    p.add_argument('--confirmations', type=Path)
    args = p.parse_args()
    if args.output.exists() or args.work.exists():
        raise FileExistsError('output and work must be new directories')
    if not args.store.is_dir() or not args.session_db.is_file() or not args.session_binary.is_file():
        raise FileNotFoundError('store, session database, or session binary is missing')
    if args.candidate_round == 1 and not args.confirmations:
        raise ValueError('candidate round 1 requires --confirmations')

    from cipher_handoff import verify
    verify(args.package)
    digest = sha(args.package / 'handoff-manifest.json')
    request = json.loads(args.request.read_text())
    run = request['run_id']
    proof_manifest, proofs = read_bundle(args.client_proofs, 'prefuzzdup-proofs-v1', run, digest, 'proofs.csv')
    if proof_manifest.get('challenges_sha256') != sha(args.server_round / 'challenges/challenges.csv'):
        raise ValueError('proofs belong to another challenge bundle')
    _, challenges = read_csv(args.server_round / 'challenges/challenges.csv')
    manifest_name = ('server-round-manifest.json' if args.candidate_round == 0
                     else 'next-round-manifest.json')
    round_manifest = json.loads((args.server_round / manifest_name).read_text())
    if (round_manifest.get('status') != 'awaiting_client_proofs' or
            round_manifest.get('run_id') != run or
            round_manifest.get('package_manifest_sha256') != digest or
            round_manifest.get('candidate_round', 0) != args.candidate_round):
        raise ValueError('server round/request binding mismatch')
    if args.candidate_round == 1:
        if (round_manifest.get('confirmations_sha256') !=
                sha(args.confirmations / 'confirmations.csv') or
                any(r['mode'] != 'all' or r['candidate_rank'] != '1' for r in challenges)):
            raise ValueError('candidate round binding mismatch')
    challenge_keys = {tuple(r[name] for name in TASK): r['token'] for r in challenges}
    expected_proofs = (Counter({'signed': 6588, 'recovery_failed': 882}) if args.candidate_round == 0
                       else Counter({'signed': 111, 'recovery_failed': 183}))
    if ((7470 if args.candidate_round == 0 else 294) != len(proofs) or
            len(challenge_keys) != len(challenges)):
        raise ValueError('proof/challenge coverage mismatch')
    proof_statuses = Counter(r['status'] for r in proofs)
    if (proof_statuses != expected_proofs or
            any(challenge_keys.get(tuple(r[name] for name in TASK)) != r['token'] for r in proofs)):
        raise ValueError('proof binding or client status mismatch')

    args.work.mkdir(parents=True)
    _, records = read_csv(args.package / 'artifacts/records.csv')
    records_tsv = args.work / 'records.tsv'
    proofs_tsv = args.work / 'proofs.tsv'
    write_csv(records_tsv, read_csv(args.package / 'artifacts/records.csv')[0], records, '\t', False)
    proof_fields = read_csv(args.client_proofs / 'proofs.csv')[0]
    write_csv(proofs_tsv, proof_fields, proofs, '\t', False)

    args.output.mkdir(parents=True)
    receipts_root = args.output / 'receipts'
    receipts_root.mkdir()
    receipts_csv = receipts_root / 'receipts.csv'
    command = [str(args.session_binary.resolve()), 'verify', str(args.store.resolve()),
               str(args.session_db.resolve()), str(records_tsv), str(proofs_tsv), str(receipts_csv)]
    with (args.output / 'verify.stdout').open('wb') as out, (args.output / 'verify.stderr').open('wb') as err:
        subprocess.run(command, stdout=out, stderr=err, check=True)

    receipt_fields, receipts = read_csv(receipts_csv)
    if len(receipts) != len(proofs) or any(any(r[n] != p[n] for n in TASK) for r, p in zip(receipts, proofs)):
        raise ValueError('receipt binding mismatch')
    receipt_statuses = Counter(r['status'] for r in receipts)
    expected = (Counter({'verified': 6588, 'client_failed': 882}) if args.candidate_round == 0
                else Counter({'verified': 111, 'client_failed': 183}))
    if receipt_statuses != expected:
        raise ValueError(f'unexpected receipt statuses: {dict(receipt_statuses)}')
    bundle(receipts_root, 'prefuzzdup-receipts-v1', run, digest, 'receipts.csv',
           {'proofs_sha256': sha(args.client_proofs / 'proofs.csv'),
            'server_round_manifest_sha256': sha(args.server_round / 'server-round-manifest.json')})

    environment = dict(platform=platform.platform(), cpu_info=Path('/proc/cpuinfo').read_text(),
                       code_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
                       compiler=subprocess.check_output(['g++', '--version'], text=True),
                       openssl=subprocess.check_output(['openssl', 'version'], text=True),
                       sqlite_python_version=sqlite3.sqlite_version,
                       session_binary_sha256=sha(args.session_binary),
                       git_transfer_measured=False)
    (args.output / 'environment.json').write_text(json.dumps(environment, indent=2))
    manifest = dict(status='awaiting_client_recovery', run_id=run, candidate_round=args.candidate_round,
                    package_manifest_sha256=digest, proofs=len(proofs), receipts=len(receipts),
                    proof_statuses=dict(proof_statuses), receipt_statuses=dict(receipt_statuses),
                    client_proofs_manifest_sha256=sha(args.client_proofs / 'message-manifest.json'),
                    server_round_manifest_sha256=sha(args.server_round / 'server-round-manifest.json'),
                    command=command, files={p.relative_to(args.output).as_posix(): sha(p)
                                            for p in sorted(args.output.rglob('*')) if p.is_file()})
    (args.output / 'server-verify-manifest.json').write_text(json.dumps(manifest, indent=2))
    print(json.dumps({k: manifest[k] for k in ['status', 'proofs', 'receipts',
                                               'proof_statuses', 'receipt_statuses']}, indent=2))


if __name__ == '__main__':
    main()
