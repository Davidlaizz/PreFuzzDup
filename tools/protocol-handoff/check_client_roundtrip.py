"""Local role-separated integration check using real artifacts; never a formal server run."""
import argparse
import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from client_messages import TASK, CHALLENGE, bundle, write_csv
from import_prefuzz_artifacts import read_csv, sha


def run_worker(binary, arguments):
    command = [binary.as_posix(), *[str(a).replace('\\', '/') for a in arguments]]
    subprocess.run((['wsl', '-e'] if os.name == 'nt' else []) + command, check=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['state', 'package', 'plan', 'inventory', 'binary', 'server-binary', 'output']:
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--server-store', required=True)
    p.add_argument('--session-root', required=True)
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    state = json.loads((args.state / 'client-state.json').read_text())
    state['run_id'] = 'local-smoke-' + uuid.uuid4().hex
    local = args.output / 'client-state'
    local.mkdir()
    shutil.copyfile(args.state / 'private-bodies.tsv', local / 'private-bodies.tsv')
    (local / 'client-state.json').write_text(json.dumps(state, indent=2))
    _, refs = read_csv(args.plan / 'reference_cipher_inputs.csv')
    ref_sha = {r['record_id']: r['body_sha256'] for r in refs}
    candidates = {}
    with (args.inventory / 'query_candidates_t6.jsonl').open() as f:
        for line in f:
            item = json.loads(line); candidates[item['query_id']] = item['candidates']
    _, queries = read_csv(args.plan / 'query_protocol_inputs.csv')
    chosen = next(q for q in queries if q['group'] == 'exact_ref' and candidates[q['query_id']] and
                  ref_sha.get(candidates[q['query_id']][0][0]) == q['body_sha256'])
    rows = [dict(run=state['run_id'], uid='enron-client', query_id=chosen['query_id'], mode=mode,
                 record_id=candidates[chosen['query_id']][0][0], threshold=str(t), repeat=str(rep),
                 query_tag=chosen['tag_hex'], token='')
            for mode in ['nearest', 'all'] for t in [4, 5, 6] for rep in range(3)]
    fields, records = read_csv(args.package / 'artifacts/records.csv')
    records_path = args.output / 'records.tsv'
    write_csv(records_path, fields, records, '\t', False)
    issue = args.output / 'issue.tsv'
    write_csv(issue, TASK, rows, '\t', False)
    session = args.session_root + '/' + state['run_id'] + '.sqlite'
    subprocess.run((['wsl', '-e'] if os.name == 'nt' else []) + ['mkdir', '-p', args.session_root], check=True)
    issued = args.output / 'issued.csv'
    run_worker(args.server_binary, ['issue', args.server_store, session, records_path, issue, issued])
    _, rows = read_csv(issued)
    challenge = args.output / 'challenges'
    challenge.mkdir()
    write_csv(challenge / 'challenges.csv', CHALLENGE, [{**r, 'candidate_rank': '0'} for r in rows])
    bundle(challenge, 'prefuzzdup-challenges-v1', state['run_id'], state['package_manifest_sha256'], 'challenges.csv')
    common = ['--state', str(local), '--package', str(args.package), '--binary', str(args.binary)]
    cli = [sys.executable, str(Path(__file__).with_name('client_messages.py'))]
    proofdir = args.output / 'proof'
    subprocess.run(cli + ['sign', *common, '--plan', str(args.plan), '--inventory', str(args.inventory),
                         '--input', str(challenge), '--output', str(proofdir)], check=True)
    fields, proofs = read_csv(proofdir / 'public/proofs.csv')
    if len(proofs) != 18 or any(r['status'] != 'signed' for r in proofs):
        raise ValueError('exact-query signing failed')
    proof_tsv = args.output / 'proofs.tsv'
    write_csv(proof_tsv, fields, proofs, '\t', False)
    receipt = args.output / 'receipts'
    receipt.mkdir()
    run_worker(args.server_binary, ['verify', args.server_store, session, records_path, proof_tsv, receipt / 'receipts.csv'])
    _, receipts = read_csv(receipt / 'receipts.csv')
    if len(receipts) != 18 or any(r['status'] != 'verified' for r in receipts):
        raise ValueError('server verification failed')
    bundle(receipt, 'prefuzzdup-receipts-v1', state['run_id'], state['package_manifest_sha256'], 'receipts.csv',
           {'proofs_sha256': sha(proofdir / 'public/proofs.csv')})
    recoverdir = args.output / 'recover'
    subprocess.run(cli + ['recover', *common, '--proofs', str(proofdir / 'public'), '--input', str(receipt),
                         '--output', str(recoverdir)], check=True)
    _, results = read_csv(recoverdir / 'public/confirmations.csv')
    if len(results) != 18 or any(r['status'] != 'accepted' or float(r['jaccard']) != 1 for r in results):
        raise ValueError('client recovery/confirmation failed')
    timings = ['tag_check_us', 'key_recovery_us', 'decrypt_us', 'integrity_us', 'confirm_us']
    if any(not r[name] or float(r[name]) <= 0 for r in results for name in timings):
        raise ValueError('client recovery timing missing')
    replay = args.output / 'replay.csv'
    run_worker(args.server_binary, ['verify', args.server_store, session, records_path, proof_tsv, replay])
    if any(r['status'] != 'rejected' for r in read_csv(replay)[1]):
        raise ValueError('cross-process replay accepted')
    report = dict(status='passed', scope='local_integration_not_4110_benchmark', attempts=18,
                  signed=18, verified=18, decrypted_and_confirmed=18, replay_rejected=18,
                  run_id=state['run_id'], query_id=chosen['query_id'],
                  input_package_sha256=state['package_manifest_sha256'],
                  confirmations_sha256=sha(recoverdir / 'public/confirmations.csv'))
    (args.output / 'integration-report.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
