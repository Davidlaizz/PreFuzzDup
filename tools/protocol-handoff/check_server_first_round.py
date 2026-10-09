"""Full-data local integration validation; results are never labelled as 4110 performance."""
import argparse
import json
import subprocess
import sys
from pathlib import Path
from cipher_handoff import server
from import_prefuzz_artifacts import read_csv, sha


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['package', 'request', 'inventory', 'native-root', 'output', 'lookup-binary', 'session-binary']:
        p.add_argument('--' + name, type=Path, required=True)
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    args.native_root.mkdir(parents=True, exist_ok=False)
    server(args.package, args.native_root / 'store')
    request = json.loads(args.request.read_text())
    request['run_id'] = 'local-full-integration-20261009'
    local_request = args.output / 'client-request.json'
    local_request.write_text(json.dumps(request, indent=2))
    out = args.output / 'server'
    command = [sys.executable, str(Path(__file__).with_name('server_first_round.py')),
               '--package', str(args.package), '--request', str(local_request),
               '--store', str(args.native_root / 'store'), '--scratch', str(args.native_root / 'lookup'),
               '--output', str(out), '--lookup-binary', str(args.lookup_binary),
               '--session-binary', str(args.session_binary)]
    subprocess.run(command, check=True)
    summary = json.loads((args.inventory / 'inventory_summary.json').read_text())
    if sha(args.inventory / 'query_candidates_t6.jsonl') != summary['output_sha256']['query_candidates_t6.jsonl']:
        raise ValueError('truth hash mismatch')
    with (args.inventory / 'query_candidates_t6.jsonl').open() as f:
        truth = {r['query_id']: r['candidates'] for r in map(json.loads, f)}
    checked = 0
    for path in sorted((out / 'lookup').glob('*.csv')):
        threshold = int(path.stem[-1])
        for row in read_csv(path)[1]:
            expected = [pair for pair in truth[row['query_id']] if pair[1] <= threshold]
            if row['mode'] == 'nearest':
                expected = expected[:1]
            if json.loads(row['candidates_json']) != expected:
                raise ValueError('independent candidate truth mismatch')
            checked += 1
    m = json.loads((out / 'server-round-manifest.json').read_text())
    if checked != 91800 or m['challenges'] != 7470 or m['synthetic_rows'] != 15390 or m['no_candidate_rows'] != 68940:
        raise ValueError('full workload counts mismatch')
    report = dict(status='passed', scope='local_full_integration_not_4110_benchmark',
                  lookup_rows_checked_against_independent_truth=checked, challenges=7470,
                  synthetic_rows=15390, no_candidate_rows=68940,
                  server_manifest_sha256=sha(out / 'server-round-manifest.json'))
    (args.output / 'integration-report.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
