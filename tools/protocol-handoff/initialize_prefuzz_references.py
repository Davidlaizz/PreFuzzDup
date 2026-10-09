"""Windows client initializer; invokes the original crypto through WSL."""
import argparse
import csv
import json
import subprocess
from pathlib import Path
from prefuzz_artifacts import sha, rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--maildir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    plan = json.loads((args.plan / 'prefuzz_artifact_plan.json').read_text())
    for name, digest in plan['output_sha256'].items():
        if Path(name).name != name or sha(args.plan / name) != digest:
            raise ValueError('plan input hash mismatch')
    records = rows(args.plan / 'reference_cipher_inputs.csv')
    if len(records) != 2259 or len({r['record_id'] for r in records}) != 2259:
        raise ValueError('expected 2259 distinct reference IDs')
    input_path = args.output / 'private-bodies.tsv'
    with input_path.open('x', encoding='utf-8', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        for r in records:
            path = (args.maildir / r['source_path']).resolve()
            if not path.is_relative_to(args.maildir.resolve()):
                raise ValueError('source outside maildir')
            raw = path.read_bytes().replace(b'\r\n', b'\n')
            _, separator, body = raw.partition(b'\n\n')
            body = body.strip()
            import hashlib
            if not separator or len(body) != int(r['body_size_bytes']) or hashlib.sha256(body).hexdigest() != r['body_sha256']:
                raise ValueError('raw body mismatch: ' + r['record_id'])
            writer.writerow([r['record_id'], r['body_sha256'], r['tag_hex'], body.hex()])
    binary = Path('results-local/tool-build/prepare-reference-cipher')
    command = ['wsl', '-e', binary.as_posix(), input_path.as_posix(), (args.output / 'artifacts').as_posix()]
    with (args.output / 'stdout.log').open('wb') as out, (args.output / 'stderr.log').open('wb') as err:
        subprocess.run(command, stdout=out, stderr=err, check=True)
    artifact_dir = args.output / 'artifacts'
    generated = rows(artifact_dir / 'records.csv')
    if {r['record_id'] for r in generated} != {r['record_id'] for r in records} or len(generated) != 2259 or len({r['protocol_rid'] for r in generated}) != 2259:
        raise ValueError('generated ID mapping mismatch')
    for r in generated:
        path = artifact_dir / r['cipher_path']
        if path.stat().st_size != int(r['cipher_bytes']) or sha(path) != r['cipher_sha256']:
            raise ValueError('ciphertext hash or size mismatch')
    report = dict(status='passed', records=2259, ciphertext_generated=True,
                  cipher_bytes=sum(int(r['cipher_bytes']) for r in generated),
                  metadata_csv_bytes=(artifact_dir / 'records.csv').stat().st_size,
                  metadata_sha256=sha(artifact_dir / 'records.csv'), binary_sha256=sha(binary),
                  plan_sha256=sha(args.plan / 'prefuzz_artifact_plan.json'), command=command,
                  local_aead_self_check='passed', handoff_ready=False,
                  timing_scope='prepare_total_us includes FE, derivation, encryption and self-check; excludes I/O and tag validation',
                  private_plaintext_file=input_path.name)
    (args.output / 'initialization.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
