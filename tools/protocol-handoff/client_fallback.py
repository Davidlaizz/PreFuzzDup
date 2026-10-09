"""Stage real new-upload ciphertext for exhausted queries; do not mutate the reference corpus."""
import argparse
import json
import math
from pathlib import Path
from client_messages import key, FAILURES, write_csv
from client_prepare import invoke
from import_prefuzz_artifacts import read_csv, sha


def exhausted(query, candidates, history, run):
    for mode in ['nearest', 'all']:
        for threshold in [4, 5, 6]:
            selected = [rid for rid, d in candidates if d <= threshold]
            if mode == 'nearest':
                selected = selected[:1]
            for repeat in range(3):
                attempt = dict(run=run, uid='enron-client', query_id=query, mode=mode,
                               threshold=str(threshold), repeat=str(repeat))
                prior = history.get(key(attempt), [])
                if not selected or (len(prior) == len(selected) and all(r['status'] in FAILURES for r in prior)):
                    return True
    return False


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['state', 'plan', 'inventory', 'binary', 'output']:
        p.add_argument('--' + name, type=Path, required=True)
    args = p.parse_args()
    state = json.loads((args.state / 'client-state.json').read_text())
    plan = json.loads((args.plan / 'prefuzz_artifact_plan.json').read_text())
    if (sha(args.plan / 'prefuzz_artifact_plan.json') != state['private_plan_sha256'] or
            sha(args.state / 'private-bodies.tsv') != state['private_bodies_sha256'] or
            sha(args.plan / 'query_protocol_inputs.csv') != plan['output_sha256']['query_protocol_inputs.csv'] or
            sha(args.inventory / 'inventory_summary.json') != plan['inventory_sha256']):
        raise ValueError('private input/inventory mismatch')
    inventory = json.loads((args.inventory / 'inventory_summary.json').read_text())
    if sha(args.inventory / 'query_candidates_t6.jsonl') != inventory['output_sha256']['query_candidates_t6.jsonl']:
        raise ValueError('independent candidate truth mismatch')
    with (args.inventory / 'query_candidates_t6.jsonl').open() as f:
        candidates = {r['query_id']: r['candidates'] for r in map(json.loads, f)}
    history_path = args.state / 'attempt-history.json'
    history = json.loads(history_path.read_text()) if history_path.exists() else {}
    eligible = {r['query_id']: r for r in read_csv(args.plan / 'query_protocol_inputs.csv')[1] if r['protocol_eligible'] == 'true'}
    selected = sorted(q for q in eligible if exhausted(q, candidates[q], history, state['run_id']))
    args.output.mkdir(parents=True, exist_ok=False)
    write_csv(args.output / 'selected.tsv', ['query_id'], [{'query_id': q} for q in selected], '\t', False)
    command = invoke(args.binary, [args.state / 'private-bodies.tsv', args.output / 'selected.tsv', args.output / 'artifacts'], args.output)
    records = read_csv(args.output / 'artifacts/records.csv')[1]
    metrics = read_csv(args.output / 'artifacts/encryption-metrics.csv')[1]
    if (len(records) != len(selected) or {r['record_id'] for r in records} != set(selected) or
            len({r['protocol_rid'] for r in records}) != len(selected) or len(metrics) != len(selected) * 3 or
            {(r['query_id'], int(r['repeat'])) for r in metrics} != {(q, rep) for q in selected for rep in range(3)}):
        raise ValueError('encryption output coverage mismatch')
    for row in records:
        cipher = args.output / 'artifacts' / row['cipher_path']
        if (row['cipher_path'] != 'blobs/' + row['protocol_rid'] + '.bin' or
                not cipher.resolve().is_relative_to((args.output / 'artifacts').resolve()) or
                row['tag_hex'] != eligible[row['record_id']]['tag_hex'] or
                cipher.stat().st_size != int(row['cipher_bytes']) or sha(cipher) != row['cipher_sha256']):
            raise ValueError('encrypted query integrity mismatch')
    for row in metrics:
        for name in ['fe_us', 'derive_us', 'encrypt_us', 'self_check_us', 'prepare_total_us']:
            value = float(row[name])
            if not math.isfinite(value) or value < 0:
                raise ValueError('invalid encryption timing')
    report = dict(status='prepared_local_only', run_id=state['run_id'], prepared_queries=len(selected),
                  benchmark_queries=sum(eligible[q]['dataset'] == 'bench_5000' for q in selected),
                  verify_queries=sum(eligible[q]['dataset'] == 'verify_100' for q in selected),
                  timing_rows=len(metrics), retained_ciphertexts=len(records),
                  cipher_bytes=sum(int(r['cipher_bytes']) for r in records),
                  encryption_binary_sha256=sha(args.binary), command=command,
                  records_sha256=sha(args.output / 'artifacts/records.csv'),
                  metrics_sha256=sha(args.output / 'artifacts/encryption-metrics.csv'),
                  retention_policy='retain_repeat_0_only; repeat_1_2_are_fresh_crypto_trials_discarded_after_AEAD_self_check',
                  timing_scope='client_initialization_microbenchmark_not_4110_end_to_end',
                  reference_index_mutated=False, server_upload_completed=False,
                  upload_gate='server lookup and terminal candidate decisions must be checked before transfer')
    (args.output / 'fallback-report.json').write_text(json.dumps(report, indent=2))
    print(json.dumps({k: report[k] for k in ['status', 'prepared_queries', 'timing_rows', 'cipher_bytes']}, indent=2))


if __name__ == '__main__':
    main()
