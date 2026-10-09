"""4110: full frozen lookup followed by first-candidate challenges, no private bodies."""
import argparse
import csv
import json
import os
import platform
import shutil
import sqlite3
import subprocess
import time
from pathlib import Path
from cipher_handoff import verify, validate_inputs, fingerprint
from client_messages import TASK, CHALLENGE, bundle, write_csv
from import_prefuzz_artifacts import read_csv, sha


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['package', 'request', 'store', 'scratch', 'output', 'lookup-binary', 'session-binary']:
        p.add_argument('--' + name, type=Path, required=True)
    args = p.parse_args()
    if os.name != 'posix' or args.scratch.resolve().as_posix().startswith('/mnt/'):
        raise ValueError('use Linux native scratch, not Windows/WSL mounted drives')
    if args.output.exists() or args.scratch.exists():
        raise FileExistsError('output and scratch must be new directories')
    verify(args.package)
    refs, expected_cipher_ids = validate_inputs(args.package)
    request = json.loads(args.request.read_text())
    digest = sha(args.package / 'handoff-manifest.json')
    expected = dict(schema='prefuzzdup-client-request-v1', package_manifest_sha256=digest,
                    reference_count=413921, benchmark_queries=5000, verify_queries=100,
                    client_tag_validation='passed', real_queries=4245, synthetic_queries=855,
                    thresholds=[4, 5, 6], modes=['nearest', 'all'], repeat=3, repeat_base=0,
                    challenge_ttl_seconds=1728000, jaccard_threshold=0.5)
    if any(request.get(k) != value for k, value in expected.items()):
        raise ValueError('client request differs from frozen experiment')
    run = request['run_id']
    if not run or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in run):
        raise ValueError('invalid run ID')
    report = json.loads((args.store / 'import-report.json').read_text())
    if (report['status'] != 'passed' or report['records'] != 2259 or
            report['handoff_manifest_sha256'] != digest or
            report['db_sha256'] != sha(args.store / 'protocol.sqlite')):
        raise ValueError('imported server store differs from accepted report')
    args.output.mkdir(parents=True)
    args.scratch.mkdir(parents=True)
    logs = args.output / 'logs'; logs.mkdir()
    raw = args.output / 'lookup'; raw.mkdir()
    # CSV and all index I/O use native scratch. Copy results back after each run.
    native_inputs = args.scratch / 'inputs'; native_inputs.mkdir()
    for path in (args.package / 'inputs').glob('*.csv'):
        shutil.copyfile(path, native_inputs / path.name)
    groups = {}
    queries = {}
    for dataset in ['verify_100', 'bench_5000']:
        groups[dataset] = {r['query_id']: r for r in read_csv(native_inputs / ('query_groups_' + dataset + '.csv'))[1]}
        queries[dataset] = {r['id']: r for r in read_csv(native_inputs / ('queries_' + dataset + '.csv'))[1]}
    queue, commands = [], []
    for dataset in ['verify_100', 'bench_5000']:
        for threshold in [4, 5, 6]:
            for mode in ['nearest', 'all']:
                name = f'{dataset}_{mode}_t{threshold}'
                target = args.scratch / (name + '.csv')
                cmd = [str(args.lookup_binary.resolve()), '--records', str(native_inputs / 'reference.csv'),
                       '--queries', str(native_inputs / ('queries_' + dataset + '.csv')),
                       '--db', str(args.scratch / f'index_t{threshold}.sqlite'),
                       '--tag-bits', '256', '--threshold', f'default={threshold}', '--fpp', '0.01',
                       '--strategies', 'prefuzz', '--mode', mode, '--repeat', '3',
                       '--sqlite-cache-kib', '0', '--out', str(target)]
                if dataset == 'verify_100':
                    cmd.append('--verify-equivalence')
                begin = time.perf_counter()
                with (logs / (name + '.stdout')).open('wb') as out, (logs / (name + '.stderr')).open('wb') as err:
                    subprocess.run(cmd, stdout=out, stderr=err, check=True)
                if dataset == 'verify_100' and 'equivalence_check=passed' not in (logs / (name + '.stdout')).read_text():
                    raise ValueError('missing equivalence verification')
                commands.append(dict(name=name, command=cmd, wall_seconds=time.perf_counter() - begin))
                rows = read_csv(target)[1]
                expected_keys = {(qid, rep) for qid in queries[dataset] for rep in range(3)}
                actual = {(r['query_id'], int(r['repeat'])) for r in rows}
                if len(rows) != len(expected_keys) or actual != expected_keys:
                    raise ValueError('lookup output key coverage mismatch')
                for row in rows:
                    qid = row['query_id']; tag = queries[dataset][qid]['tag_hex']
                    candidates = json.loads(row['candidates_json'])
                    if (row['strategy'] != 'prefuzz' or row['mode'] != mode or
                            int(row['candidate_count']) != len(candidates) or
                            (mode == 'nearest' and len(candidates) > 1) or
                            candidates != sorted(candidates, key=lambda c: (c[1], c[0])) or
                            len({rid for rid, _ in candidates}) != len(candidates)):
                        raise ValueError('invalid candidate ordering/count/mode')
                    for rid, distance in candidates:
                        if rid not in refs or distance > threshold or (int(refs[rid], 16) ^ int(tag, 16)).bit_count() != distance:
                            raise ValueError('invalid candidate distance')
                    eligible = groups[dataset][qid]['protocol_eligible'] == 'True'
                    if eligible and any(rid not in expected_cipher_ids for rid, _ in candidates):
                        raise ValueError('real candidate has no prepared ciphertext')
                    queue.append(dict(run=run, uid='enron-client', dataset=dataset, query_id=qid,
                                      mode=mode, threshold=str(threshold), repeat=row['repeat'], query_tag=tag,
                                      protocol_eligible=eligible, candidates=candidates,
                                      status='lookup_only_synthetic' if not eligible else ('pending' if candidates else 'no_candidate')))
                shutil.copyfile(target, raw / target.name)
                print(name + ': passed', flush=True)
    with (args.scratch / 'server-queue.jsonl').open('x') as f:
        for row in queue:
            f.write(json.dumps(row) + '\n')
    tasks = [{**r, 'record_id': r['candidates'][0][0], 'token': ''} for r in queue if r['status'] == 'pending']
    fields, records = read_csv(args.package / 'artifacts/records.csv')
    record_tsv, task_tsv = args.scratch / 'records.tsv', args.scratch / 'issue.tsv'
    write_csv(record_tsv, fields, records, '\t', False)
    write_csv(task_tsv, TASK, tasks, '\t', False)
    cmd = [str(args.session_binary.resolve()), 'issue', str(args.store.resolve()),
           str(args.scratch / 'session.sqlite'), str(record_tsv), str(task_tsv), str(args.output / 'challenge-metrics.csv')]
    with (logs / 'issue.stdout').open('wb') as out, (logs / 'issue.stderr').open('wb') as err:
        subprocess.run(cmd, stdout=out, stderr=err, check=True)
    issued = read_csv(args.output / 'challenge-metrics.csv')[1]
    if len(issued) != len(tasks) or any(any(r[n] != t[n] for n in TASK[:-1]) or r['status'] != 'issued' for r, t in zip(issued, tasks)):
        raise ValueError('issued challenge coverage mismatch')
    challenge = args.output / 'challenges'; challenge.mkdir()
    write_csv(challenge / 'challenges.csv', CHALLENGE, [{**r, 'candidate_rank': '0'} for r in issued])
    bundle(challenge, 'prefuzzdup-challenges-v1', run, digest, 'challenges.csv')
    environment = dict(platform=platform.platform(), cpu_info=Path('/proc/cpuinfo').read_text(),
                       code_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
                       compiler=subprocess.check_output(['g++', '--version'], text=True),
                       openssl=subprocess.check_output(['openssl', 'version'], text=True),
                       sqlite_python_version=sqlite3.sqlite_version,
                       mem_info=Path('/proc/meminfo').read_text(), os_page_cache_cleared=False,
                       sqlite_cache_kib=0, sqlite_mmap=0, git_transfer_measured=False,
                       binaries={str(p): sha(p) for p in [args.lookup_binary, args.session_binary]})
    (args.output / 'environment.json').write_text(json.dumps(environment, indent=2))
    manifest = dict(status='awaiting_client_proofs', run_id=run, package_manifest_sha256=digest,
                    client_request_sha256=sha(args.request), commands=commands,
                    benchmark_rows=90000, verify_rows=1800, challenges=len(issued),
                    synthetic_rows=sum(r['status'] == 'lookup_only_synthetic' for r in queue),
                    no_candidate_rows=sum(r['status'] == 'no_candidate' for r in queue),
                    sqlite_sizes={p.name: p.stat().st_size for p in args.scratch.glob('index_t*.sqlite')},
                    files={p.relative_to(args.output).as_posix(): fingerprint(p) for p in sorted(args.output.rglob('*')) if p.is_file()})
    (args.output / 'server-round-manifest.json').write_text(json.dumps(manifest, indent=2))
    print(json.dumps({k: manifest[k] for k in ['status', 'benchmark_rows', 'verify_rows', 'challenges']}, indent=2))


if __name__ == '__main__':
    main()
