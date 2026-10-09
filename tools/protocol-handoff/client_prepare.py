"""Prepare private query bodies and measured client tags; publish only a request manifest."""
import argparse
import collections
import csv
import hashlib
import json
import os
import platform
import subprocess
from pathlib import Path
from cipher_handoff import validate_inputs, verify
from import_prefuzz_artifacts import read_csv, sha


def extract_checked_body(maildir, row):
    if row['protocol_eligible'] != 'true':
        raise ValueError('synthetic query has no protocol body')
    path = (maildir / row['source_path']).resolve()
    if not path.is_relative_to(maildir.resolve()):
        raise ValueError('source outside maildir')
    raw = path.read_bytes().replace(b'\r\n', b'\n')
    _, separator, body = raw.partition(b'\n\n')
    body = body.strip()
    if (not separator or len(body) != int(row['body_size_bytes']) or
            hashlib.sha256(body).hexdigest() != row['body_sha256']):
        raise ValueError('body size/SHA mismatch: ' + row['source_path'])
    return body


def invoke(binary, arguments, logdir):
    command = [binary.as_posix(), *[str(p).replace('\\', '/') for p in arguments]]
    if os.name == 'nt':
        command = ['wsl', '-e', *command]
    with (logdir / 'stdout.log').open('wb') as out, (logdir / 'stderr.log').open('wb') as err:
        subprocess.run(command, stdout=out, stderr=err, check=True)
    return command


def prepare(args):
    verify(args.package)
    validate_inputs(args.package)
    plan_path = args.plan / 'prefuzz_artifact_plan.json'
    plan = json.loads(plan_path.read_text())
    for name, digest in plan['output_sha256'].items():
        if Path(name).name != name or sha(args.plan / name) != digest:
            raise ValueError('private plan digest mismatch')
    _, rows = read_csv(args.plan / 'query_protocol_inputs.csv')
    local = {row['query_id']: row for row in rows}
    if len(local) != 5100 or len(rows) != 5100:
        raise ValueError('unexpected client plan ID coverage')
    groups = {}
    for dataset in ['bench_5000', 'verify_100']:
        _, queries = read_csv(args.package / 'inputs' / ('queries_' + dataset + '.csv'))
        _, labels = read_csv(args.package / 'inputs' / ('query_groups_' + dataset + '.csv'))
        labels = {r['query_id']: r for r in labels}
        groups[dataset] = dict(collections.Counter(r['group'] for r in labels.values()))
        for query in queries:
            row = local[query['id']]
            label = labels[query['id']]
            if (row['dataset'] != dataset or row['tag_hex'] != query['tag_hex'] or
                    row['group'] != label['group'] or
                    row['protocol_eligible'] != label['protocol_eligible'].lower()):
                raise ValueError('public/private query mismatch')
    if groups['bench_5000'] != dict(exact_ref=200, near_ref=185, near_ref_synthetic=815, no_match_ref=3800):
        raise ValueError('query quotas differ from plan')
    eligible = [r for r in rows if r['protocol_eligible'] == 'true']
    if len(eligible) != 4245:
        raise ValueError('unexpected eligible query count')
    args.output.mkdir(parents=True, exist_ok=False)
    private = args.output / 'private-bodies.tsv'
    with private.open('x', encoding='utf-8', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        for row in eligible:
            body = extract_checked_body(args.maildir, row)
            writer.writerow([row['query_id'], row['body_sha256'], row['tag_hex'], body.hex()])
    if os.name != 'nt':
        private.chmod(0o600)
    metrics = args.output / 'tag-metrics.csv'
    command = invoke(args.binary, ['tag', private, metrics], args.output)
    _, timing = read_csv(metrics)
    keys = {(r['query_id'], int(r['repeat'])) for r in timing}
    expected = {(r['query_id'], rep) for r in eligible for rep in range(3)}
    if len(timing) != len(expected) or keys != expected:
        raise ValueError('tag timing coverage mismatch')
    for row in timing:
        if row['tag_hex'] != local[row['query_id']]['tag_hex'] or float(row['tag_us']) < 0:
            raise ValueError('C++ tag validation failed')
    report = dict(status='passed', run_id=args.run_id, package_manifest_sha256=sha(args.package / 'handoff-manifest.json'),
                  private_plan_sha256=sha(plan_path), private_bodies_sha256=sha(private),
                  binary_sha256=sha(args.binary), tag_metrics_sha256=sha(metrics),
                  real_queries=4245, synthetic_queries=855, tag_timing_rows=len(timing),
                  groups=groups, command=command, platform=platform.platform(),
                  proof_status='waiting_for_server_challenges', recovery_status='waiting_for_server_verified_ciphertexts')
    (args.output / 'client-state.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    public = dict(schema='prefuzzdup-client-request-v1', run_id=args.run_id,
                  package_manifest_sha256=report['package_manifest_sha256'], reference_count=413921,
                  benchmark_queries=5000, verify_queries=100, groups=groups,
                  client_tag_validation='passed', real_queries=4245, synthetic_queries=855,
                  thresholds=[4, 5, 6], modes=['nearest', 'all'], repeat=3, repeat_base=0,
                  challenge_ttl_seconds=1728000, jaccard_threshold=0.5,
                  communication_model={'rtt_ms': 1, 'bandwidth_bps': 1000000000},
                  git_transfer_measured=False, computation_timing='measured', full_protocol_completed=False)
    (args.output / 'client-request.json').write_text(json.dumps(public, indent=2), encoding='utf-8')
    print(json.dumps({k: report[k] for k in ['status', 'real_queries', 'synthetic_queries', 'tag_timing_rows']}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['package', 'plan', 'maildir', 'binary', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--run-id', required=True)
    args = parser.parse_args()
    if not args.run_id or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in args.run_id):
        raise ValueError('invalid run ID')
    prepare(args)


if __name__ == '__main__':
    main()
