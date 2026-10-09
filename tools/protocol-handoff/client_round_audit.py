"""Audit a returned server lookup batch before any client proof is generated."""
import argparse
import json
import re
from pathlib import Path
from client_messages import bundle, write_csv
from import_prefuzz_artifacts import read_csv, sha


def check_lookup(rows, truth, mode, threshold):
    if not rows or any(r.get('strategy') != 'prefuzz' or r.get('mode') != mode for r in rows):
        raise ValueError('wrong lookup strategy or mode')
    expected_keys = {(qid, rep) for qid in truth for rep in range(3)}
    actual_keys = {(r['query_id'], int(r['repeat'])) for r in rows}
    if actual_keys != expected_keys or len(rows) != len(expected_keys):
        raise ValueError('lookup key coverage mismatch')
    for row in rows:
        candidate = json.loads(row['candidates_json'])
        expected = [pair for pair in truth[row['query_id']] if pair[1] <= threshold]
        if mode == 'nearest':
            expected = expected[:1]
        if int(row['candidate_count']) != len(candidate) or candidate != expected:
            raise ValueError('lookup candidate mismatch')
    return len(rows)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--package', type=Path, required=True)
    p.add_argument('--request', type=Path, required=True)
    p.add_argument('--server-round', type=Path, required=True)
    p.add_argument('--inventory', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    request = json.loads(args.request.read_text())
    manifest = json.loads((args.server_round / 'server-round-manifest.json').read_text())
    package_digest = sha(args.package / 'handoff-manifest.json')
    if (manifest.get('status') != 'awaiting_client_proofs' or manifest.get('run_id') != request['run_id'] or
            manifest.get('package_manifest_sha256') != package_digest):
        raise ValueError('server round binding/status mismatch')
    summary = json.loads((args.inventory / 'inventory_summary.json').read_text())
    if sha(args.inventory / 'query_candidates_t6.jsonl') != summary['output_sha256']['query_candidates_t6.jsonl']:
        raise ValueError('candidate truth digest mismatch')
    truth = {}
    with (args.inventory / 'query_candidates_t6.jsonl').open() as f:
        for line in f:
            item = json.loads(line); truth[item['query_id']] = item['candidates']
    checked = 0
    for path in sorted((args.server_round / 'lookup').glob('*.csv')):
        match = re.fullmatch(r'(verify_100|bench_5000)_(nearest|all)_t([456])', path.stem)
        if not match: raise ValueError('unexpected lookup output')
        rows = read_csv(path)[1]
        checked += check_lookup(rows, truth, match[2], int(match[3]))
    if checked != 91800:
        raise ValueError('expected 91800 lookup rows')
    challenges = read_csv(args.server_round / 'challenges/challenges.csv')[1]
    if len(challenges) != 7470 or any(r['run'] != request['run_id'] or r['uid'] != 'enron-client' or
                                      r['token'] == '' or r['candidate_rank'] != '0' for r in challenges):
        raise ValueError('challenge coverage/binding mismatch')
    # The first round contains only the first candidate; no synthetic query may enter it.
    challenge_keys = {(r['query_id'], r['mode'], r['threshold'], r['repeat'], r['record_id']) for r in challenges}
    if len(challenge_keys) != len(challenges):
        raise ValueError('duplicate challenge key')
    args.output.mkdir(parents=True)
    selected = args.output / 'challenges.csv'
    fields, rows = read_csv(args.server_round / 'challenges/challenges.csv')
    write_csv(selected, fields, rows)
    bundle(args.output, 'prefuzzdup-challenges-v1', request['run_id'], package_digest, 'challenges.csv',
           {'server_round_manifest_sha256': sha(args.server_round / 'server-round-manifest.json'),
            'lookup_rows_checked': checked, 'challenge_count': len(challenges)})
    report = dict(status='passed', run_id=request['run_id'], lookup_rows_checked=checked,
                  challenges=len(challenges), server_round_manifest_sha256=sha(args.server_round / 'server-round-manifest.json'),
                  candidate_truth_sha256=sha(args.inventory / 'query_candidates_t6.jsonl'),
                  proof_gate='passed', signed=False)
    (args.output / 'audit-report.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
