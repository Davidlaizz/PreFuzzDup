"""Publish only an audited request and aggregate client preparation evidence."""
import argparse
import json
import math
import shutil
import statistics
import subprocess
from pathlib import Path
from import_prefuzz_artifacts import read_csv, sha


def describe(values):
    data = sorted(values)
    if not data or any(not math.isfinite(x) or x < 0 for x in data):
        raise ValueError('invalid timing samples')
    return dict(count=len(data), mean_us=statistics.mean(data), median_us=statistics.median(data),
                p95_us=data[math.ceil(.95 * len(data)) - 1], p99_us=data[math.ceil(.99 * len(data)) - 1])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['state', 'fallback', 'roundtrip', 'full-check', 'dest']:
        p.add_argument('--' + name, type=Path, required=True)
    args = p.parse_args()
    state = json.loads((args.state / 'client-state.json').read_text())
    request = json.loads((args.state / 'client-request.json').read_text())
    fallback = json.loads((args.fallback / 'fallback-report.json').read_text())
    roundtrip = json.loads((args.roundtrip / 'integration-report.json').read_text())
    full_check = json.loads((args.full_check / 'integration-report.json').read_text())
    if (state['status'] != 'passed' or state['run_id'] != request['run_id'] or
            state['private_bodies_sha256'] != sha(args.state / 'private-bodies.tsv') or
            state['tag_metrics_sha256'] != sha(args.state / 'tag-metrics.csv') or
            fallback['run_id'] != request['run_id'] or fallback['prepared_queries'] != 3830 or
            fallback['status'] != 'prepared_local_only' or
            fallback['metrics_sha256'] != sha(args.fallback / 'artifacts/encryption-metrics.csv') or
            fallback['records_sha256'] != sha(args.fallback / 'artifacts/records.csv') or
            roundtrip['status'] != 'passed' or roundtrip['decrypted_and_confirmed'] != 18 or
            full_check['status'] != 'passed' or full_check['lookup_rows_checked_against_independent_truth'] != 91800):
        raise ValueError('client readiness evidence is incomplete or inconsistent')
    records = read_csv(args.fallback / 'artifacts/records.csv')[1]
    if len(records) != 3830 or len({r['record_id'] for r in records}) != 3830:
        raise ValueError('fallback record coverage mismatch')
    for row in records:
        path = args.fallback / 'artifacts' / row['cipher_path']
        if (row['cipher_path'] != 'blobs/' + row['protocol_rid'] + '.bin' or
                not path.resolve().is_relative_to((args.fallback / 'artifacts').resolve()) or
                path.stat().st_size != int(row['cipher_bytes']) or sha(path) != row['cipher_sha256']):
            raise ValueError('staged fallback ciphertext mismatch')
    tags = read_csv(args.state / 'tag-metrics.csv')[1]
    crypto = read_csv(args.fallback / 'artifacts/encryption-metrics.csv')[1]
    if len(tags) != 12735 or len(crypto) != 11490:
        raise ValueError('client timing row mismatch')
    summary = dict(status='ready_for_server_first_round', run_id=state['run_id'],
                   source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
                   real_queries=4245, synthetic_queries=855, groups=state['groups'],
                   reference_ciphertexts_on_server=2259, staged_new_upload_queries=3830,
                   staged_new_upload_cipher_bytes=fallback['cipher_bytes'],
                   new_uploads_transferred=False, actual_4110_proofs_completed=False,
                   tag_generation=describe([float(r['tag_us']) for r in tags]),
                   encryption={n: describe([float(r[n]) for r in crypto]) for n in
                               ['fe_us', 'derive_us', 'encrypt_us', 'self_check_us', 'prepare_total_us']},
                   orchestrator_platform=state['platform'],
                   compute_environment=json.loads((args.state / 'runtime-environment.json').read_text()),
                   ciphertext_retention=fallback['retention_policy'],
                   reference_initialization_timing='historical prepare_total_us only; no retrospective splitting',
                   integration_checks={'real_cipher_roundtrip': roundtrip, 'full_lookup': full_check},
                   communication_model=request['communication_model'], communication_measured=False,
                   computation_scope='local client preparation; integration timings excluded from formal 4110 results',
                   package_manifest_sha256=state['package_manifest_sha256'],
                   evidence_sha256={name: sha(path) for name, path in {
                       'tag_metrics': args.state / 'tag-metrics.csv',
                       'encryption_metrics': args.fallback / 'artifacts/encryption-metrics.csv',
                       'roundtrip_report': args.roundtrip / 'integration-report.json',
                       'full_check_report': args.full_check / 'integration-report.json'}.items()})
    args.dest.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(args.state / 'client-request.json', args.dest / 'client-request.json')
    (args.dest / 'client-readiness.json').write_text(json.dumps(summary, indent=2))
    lines = ['# PreFuzzDup 客户端准备结果', '',
             '本机客户端的前置准备已通过；4110 正式挑战、证明和恢复尚未执行。', '',
             '| 项目 | 数量 |', '|---|---:|', '| 参考标签 | 413,921 |', '| 正式查询 / 验证查询 | 5,000 / 100 |',
             '| 真实查询 / 仅检索合成查询 | 4,245 / 855 |', '| 客户端标签计时行 | 12,735 |',
             '| 服务端已有参考密文 | 2,259 |', '| 本地待上传新查询密文 | 3,830 |',
             '| 新查询密文本体字节 | 7,208,897 |', '| 新查询加密计时行 | 11,490 |', '',
             '新上传密文只按真实查询 ID 各保留一份；额外两次计时重新加密并自检后丢弃，不能解释为每个阈值/模式都已上传。', '',
             '| 本机阶段 | 样本数 | mean (us) | median (us) | p95 (us) | p99 (us) |',
             '|---|---:|---:|---:|---:|---:|']
    for name, stats in [('tag_generation', summary['tag_generation']), *summary['encryption'].items()]:
        lines.append(f"| {name} | {stats['count']} | {stats['mean_us']:.3f} | {stats['median_us']:.3f} | {stats['p95_us']:.3f} | {stats['p99_us']:.3f} |")
    lines += ['', 'FE 阶段含恢复表示、随机记录 ID 和 FE 生成；derive 含密钥派生、nonce/数据密钥生成；encrypt 只含文件 AES-GCM 与数据密钥封装两次加密；self_check 含记录字段赋值与本地 AEAD 自检。', '',
              '这些是客户端准备阶段测量，不包含 Git、人工等待或服务端检索。通信仅按 RTT 1 ms、1 Gbit/s 估算，当前没有实测网络时间。历史 2,259 份参考密文只有整体准备耗时，不倒推加密阶段数据。', '',
              '本机集成验收：18 次真实密文签名/验签/解密/确认通过，18 次重放拒绝；全量 91,800 行检索结果与独立候选真值一致。这些不作为 4110 正式性能结果。', '',
              '服务端执行步骤见 [首轮交接文档](../../docs/prefuzzdup-protocol-round-handoff.md)。只提交此目录中的公开请求和摘要，不提交本地正文、私钥、SQLite 或待上传密文目录。']
    (args.dest / 'README.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(json.dumps({'status': summary['status'], 'dest': str(args.dest)}, indent=2))


if __name__ == '__main__':
    main()
