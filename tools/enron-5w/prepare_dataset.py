"""Build the 1/10 Enron body sample and 256-bit PreFuzzDup text tags.

Phase "prepare" writes everything into a staging directory. After the external
C++ verifier passes, phase "publish" re-checks all outputs, writes README.md
and dataset.json, then renames staging to the final 5wTest directory.
"""
import argparse
import csv
import hashlib
import json
import os
import platform
import random
import re
import struct
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

TOOL_VERSION = "1.0.0"
SEED = 20260920
EXPECTED_TOTAL = 517401
SAMPLE_SIZE = 51740
DOMAIN = b"PreFuzzDup/tag/text/v1"
DOMAIN_FIELD = struct.pack(">I", len(DOMAIN)) + DOMAIN
WORD_RE = re.compile(rb"[0-9a-z]+")

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "enron_mail_20150507"
MAILDIR = CORPUS / "maildir"
ARCHIVE = ROOT / "enron_mail_20150507.tar.gz"
STAGING = CORPUS / "5wTest.staging"
TARGET = CORPUS / "5wTest"


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def words_of(body: bytes) -> list[bytes]:
    # Equivalent to the C++ normalize_text + istringstream splitting:
    # keep ASCII alphanumeric runs only, lowercase A-Z, then split on spaces.
    return WORD_RE.findall(body.lower())


def simhash_tag(words: list[bytes]) -> bytes:
    """Replicate PreFuzzDup simhash_text byte-for-byte."""
    if not words:
        words = [b"empty"]
    if len(words) < 3:
        features = [words[0]]
    else:
        features = [
            b"\x1f".join((words[i], words[i + 1], words[i + 2]))
            for i in range(len(words) - 2)
        ]
    count = len(features)
    digests = np.empty((count, 32), dtype=np.uint8)
    for i, feature in enumerate(features):
        digest = hashlib.sha256(
            DOMAIN_FIELD + struct.pack(">I", len(feature)) + feature
        ).digest()
        digests[i] = np.frombuffer(digest, dtype=np.uint8)
    # C++ getbit/setbit use bit 8*b+j of byte b (LSB-first within each byte).
    bits = ((digests[:, :, None] >> np.arange(8, dtype=np.uint8)) & 1).reshape(count, 256)
    ones = bits.sum(axis=0, dtype=np.int32)
    tag_bits = (2 * ones - count) >= 0
    return np.packbits(tag_bits, bitorder="little").tobytes()


def extract_body(raw: bytes, source_rel: str) -> bytes:
    raw = raw.replace(b"\r\n", b"\n")
    _, separator, body = raw.partition(b"\n\n")
    if not separator:
        fail(f"no header/body separator: maildir/{source_rel}")
    return body.strip()


def enumerate_emails() -> list[str]:
    paths: list[str] = []
    for dirpath, _dirnames, filenames in os.walk(MAILDIR):
        base = Path(dirpath)
        for name in filenames:
            rel = (base / name).relative_to(MAILDIR).as_posix()
            if "/" not in rel:
                fail(f"unexpected file directly under maildir: {rel}")
            paths.append(rel)
    paths.sort()
    if len(paths) != EXPECTED_TOTAL:
        fail(f"expected {EXPECTED_TOTAL} mail files, found {len(paths)}")
    return paths


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_csv(path: Path, header: list[str], rows: list[tuple]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(header)
        writer.writerows(rows)


def read_csv_rows(path: Path) -> list[list[str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return [row for row in csv.reader(handle) if row]


EDGE_CASES: list[tuple[str, bytes]] = [
    ("empty", b""),
    ("one_word", b"hello"),
    ("two_words", b"hello world"),
    ("three_words", b"alpha beta gamma"),
    ("four_words", b"alpha beta gamma delta"),
    ("case_punctuation", b"HeLLo, WORLD!!! hello world"),
    ("newlines_tabs", b"  Alpha\t\tBeta\n\nGamma  \r\n Delta \n"),
    ("repeated_words", b"word word word word word"),
    ("non_ascii_separators", b"\xff Caf\xc3\xa9 \x80\x81 42"),
]


def validate_csv_outputs() -> None:
    tag_rows = read_csv_rows(STAGING / "tags.csv")
    manifest_rows = read_csv_rows(STAGING / "manifest.csv")
    if tag_rows[0] != ["id", "type", "tag_hex"]:
        fail("tags.csv header mismatch")
    if manifest_rows[0] != [
        "id", "mailbox", "source_path", "body_path", "body_sha256",
        "body_size_bytes", "normalized_word_count",
    ]:
        fail("manifest.csv header mismatch")
    tag_data = tag_rows[1:]
    manifest_data = manifest_rows[1:]
    if len(tag_data) != SAMPLE_SIZE or len(manifest_data) != SAMPLE_SIZE:
        fail(f"row count mismatch: tags={len(tag_data)}, manifest={len(manifest_data)}")
    tag_hex_re = re.compile(r"^[0-9a-f]{64}$")
    tag_ids, manifest_ids, sources = set(), set(), set()
    digest_tags: dict[str, str] = {}
    for index, (tag_row, manifest_row) in enumerate(zip(tag_data, manifest_data), 1):
        expected_id = f"enron_{index:06d}"
        if tag_row[0] != expected_id or manifest_row[0] != expected_id:
            fail(f"id sequence mismatch at row {index}: {tag_row[0]} / {manifest_row[0]}")
        if tag_row[1] != "text":
            fail(f"non-text type at row {index}: {tag_row[1]}")
        if not tag_hex_re.fullmatch(tag_row[2]):
            fail(f"invalid tag hex at row {index}")
        if manifest_row[5] != str(int(manifest_row[5])) or manifest_row[6] != str(int(manifest_row[6])):
            fail(f"invalid numeric field at row {index}")
        tag_ids.add(tag_row[0])
        manifest_ids.add(manifest_row[0])
        sources.add(manifest_row[2])
        digest = manifest_row[4]
        previous = digest_tags.setdefault(digest, tag_row[2])
        if previous != tag_row[2]:
            fail(f"same body digest has different tags at row {index}")
    if len(tag_ids) != SAMPLE_SIZE or len(manifest_ids) != SAMPLE_SIZE:
        fail("duplicate ids detected")
    if len(sources) != SAMPLE_SIZE:
        fail("duplicate source paths detected")
    for name, content in (("tags.csv", b"\xef\xbb\xbf"), ("manifest.csv", b"\xef\xbb\xbf")):
        if (STAGING / name).read_bytes().startswith(content):
            fail(f"{name} has a UTF-8 BOM")


def cmd_prepare() -> None:
    if STAGING.exists():
        fail(f"staging directory already exists: {STAGING}")
    if TARGET.exists() and any(TARGET.iterdir()):
        fail(f"target directory is not empty: {TARGET}")
    if not MAILDIR.is_dir():
        fail(f"maildir not found: {MAILDIR}")

    started = time.time()
    print(f"[1/6] enumerating {MAILDIR} ...", flush=True)
    paths = enumerate_emails()

    print(f"[2/6] sampling {SAMPLE_SIZE} of {len(paths)} with seed {SEED} ...", flush=True)
    sample = random.Random(SEED).sample(paths, SAMPLE_SIZE)
    sample.sort()
    if len(set(sample)) != SAMPLE_SIZE:
        fail("sample contains duplicate paths")

    bodies_dir = STAGING / "bodies"
    bodies_dir.mkdir(parents=True)
    records: list[tuple] = []
    digest_counts: Counter = Counter()
    tag_cache: dict[bytes, str] = {}
    empty_word_bodies = 0
    total_words = 0
    total_body_bytes = 0
    print("[3/6] extracting bodies and computing tags ...", flush=True)
    for index, rel in enumerate(sample, 1):
        sample_id = f"enron_{index:06d}"
        source = MAILDIR.joinpath(*rel.split("/"))
        try:
            raw = source.read_bytes()
        except OSError as error:
            fail(f"cannot read maildir/{rel}: {error}")
        body = extract_body(raw, rel)
        body_file = bodies_dir / f"{sample_id}.txt"
        body_file.write_bytes(body)
        digest = hashlib.sha256(body).hexdigest()
        digest_counts[digest] += 1
        words = words_of(body)
        if not words:
            empty_word_bodies += 1
        total_words += len(words)
        total_body_bytes += len(body)
        normalized = b" ".join(words)
        tag_hex = tag_cache.get(normalized)
        if tag_hex is None:
            tag_hex = simhash_tag(words).hex()
            tag_cache[normalized] = tag_hex
        mailbox = rel.split("/", 1)[0]
        records.append((
            sample_id, mailbox, f"maildir/{rel}", f"bodies/{sample_id}.txt",
            digest, len(body), len(words), tag_hex,
        ))
        if index % 10000 == 0:
            print(f"  processed {index}/{SAMPLE_SIZE}", flush=True)

    print("[4/6] writing tags.csv and manifest.csv ...", flush=True)
    tag_rows = [(r[0], "text", r[7]) for r in records]
    manifest_rows = [r[:7] for r in records]
    write_csv(STAGING / "tags.csv", ["id", "type", "tag_hex"], tag_rows)
    write_csv(
        STAGING / "manifest.csv",
        ["id", "mailbox", "source_path", "body_path", "body_sha256",
         "body_size_bytes", "normalized_word_count"],
        manifest_rows,
    )

    print("[5/6] writing edge cases and running internal checks ...", flush=True)
    edge_rows = []
    for name, data in EDGE_CASES:
        edge_rows.append((name, data.hex(), simhash_tag(words_of(data)).hex()))
    write_csv(STAGING / "edge_cases.csv", ["name", "input_hex", "expected_hex"], edge_rows)
    validate_csv_outputs()

    print("[6/6] hashing source archive ...", flush=True)
    archive_sha = sha256_file(ARCHIVE)
    summary = {
        "tool_version": TOOL_VERSION,
        "corpus_file_count": len(paths),
        "sample_size": SAMPLE_SIZE,
        "seed": SEED,
        "archive_sha256": archive_sha,
        "unique_bodies": len(digest_counts),
        "extra_exact_body_copies": SAMPLE_SIZE - len(digest_counts),
        "exact_duplicate_groups": sum(1 for count in digest_counts.values() if count > 1),
        "empty_word_bodies": empty_word_bodies,
        "total_normalized_words": total_words,
        "total_body_bytes": total_body_bytes,
        "elapsed_seconds": round(time.time() - started, 1),
        "python_version": platform.python_version(),
        "numpy_version": np.__version__,
    }
    (STAGING / "prepare_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
    print(f"staging ready: {STAGING}", flush=True)
    print("next: compile and run verify_tag.cpp against this staging directory", flush=True)


def verify_bodies_against_manifest() -> tuple[int, int]:
    rows = read_csv_rows(STAGING / "manifest.csv")[1:]
    total_bytes = 0
    for row in rows:
        body_path = STAGING / row[3]
        data = body_path.read_bytes()
        total_bytes += len(data)
        if len(data) != int(row[5]):
            fail(f"body size mismatch: {row[0]}")
        if hashlib.sha256(data).hexdigest() != row[4]:
            fail(f"body sha256 mismatch: {row[0]}")
    return len(rows), total_bytes


def write_dataset_docs(summary: dict, cpp: dict) -> None:
    stats = {
        key: summary[key]
        for key in (
            "corpus_file_count", "sample_size", "unique_bodies",
            "extra_exact_body_copies", "exact_duplicate_groups",
            "empty_word_bodies", "total_normalized_words", "total_body_bytes",
        )
    }
    readme = [
        "# Enron 十分之一正文抽样与标签数据集",
        "",
        "本目录是按固定种子从 CMU Enron Email Dataset（2015-05-07）抽取的正文样本，",
        "保留自然重复，并为每个正文生成 256 位 PreFuzzDup 文本 SimHash 标签。",
        "本阶段仅准备数据：未划分参考库与查询集，未建立数据库，未运行三套算法性能测试。",
        "",
        "## 文件",
        "",
        "| 文件 | 内容 |",
        "| --- | --- |",
        "| `bodies/enron_000001.txt` ... `bodies/enron_051740.txt` | 提取后的正文，字节原样保留 |",
        "| `tags.csv` | `id,type,tag_hex`，type 全部为 `text`，供三套检索程序共同使用 |",
        "| `manifest.csv` | 编号、邮箱、来源路径、正文路径、正文 SHA-256、字节数、规范化词数 |",
        "| `dataset.json` | 抽样参数、预处理与 SimHash 口径、工具版本、输入清单与输出校验 |",
        "",
        "## 规则",
        "",
        "- 全库 517,401 封邮件按相对路径排序，种子 20260920 无放回抽取 51,740 封，保留重复。",
        "- 正文提取沿用全量统计口径：CRLF 统一为 LF，按第一个空行去除外层邮件头，去首尾空白；不做 MIME 解码。",
        "- 分词只保留 ASCII 字母数字并转小写；使用连续三词特征；不足三词时仅用第一个词；无词时用 `empty`。",
        "- 域标识 `PreFuzzDup/tag/text/v1` 与特征均按 4 字节大端长度前缀编码后 SHA-256；字节内 LSB-first 投票，零票置 1。",
        "",
        "## 验证结果",
        "",
        f"- 样本 / 正文 / 清单 / 标签记录均为 {SAMPLE_SIZE:,}，编号唯一，来源路径不重复。",
        f"- 唯一正文 {stats['unique_bodies']:,}，额外重复副本 {stats['extra_exact_body_copies']:,}，重复组 {stats['exact_duplicate_groups']:,}。",
        f"- 无有效词正文 {stats['empty_word_bodies']:,} 封（保留在样本中，标签由 `empty` 特征生成）。",
        f"- 独立 C++ 校验器调用 `PreFuzzDup/src/main.cpp` 现有 `make_tag`：边界用例 {cpp['edge_cases_matched']}/{cpp['edge_cases_checked']} 一致，正文标签 {cpp['bodies_matched']:,}/{cpp['bodies_checked']:,} 逐字节一致。",
        "- 全部正文重新读取并核对 SHA-256 与字节数；CSV 为无 BOM UTF-8，LF 换行。",
        "",
        "完整机器可读信息见 `dataset.json`。",
    ]
    readme_path = STAGING / "README.md"
    readme_path.write_text("\n".join(readme) + "\n", encoding="utf-8", newline="\n")

    dataset = {
        "dataset_name": "enron_5w_body_tags_v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "data preparation only; no reference/query split, no database, no benchmark run",
        "sample": {
            "size": SAMPLE_SIZE,
            "corpus_file_count": summary["corpus_file_count"],
            "fraction": "1/10",
            "random_seed": SEED,
            "method": (
                "enumerate all files under enron_mail_20150507/maildir, sort by POSIX relative path, "
                "random.Random(seed).sample without replacement, then sort sampled paths and assign "
                "ids enron_000001..enron_051740"
            ),
            "id_format": "enron_%06d",
            "natural_duplicates_retained": True,
        },
        "body_preprocessing": [
            "replace CRLF with LF",
            "remove outer headers at the first empty line",
            "strip leading and trailing whitespace from the body",
            "retain quotes, forwarded text and signatures; no MIME decoding",
            "fail loudly on unreadable files or missing header/body separator",
        ],
        "simhash": {
            "domain": DOMAIN.decode(),
            "tokenization": "ASCII alphanumeric runs, lowercased, separators collapsed",
            "feature_rule": "consecutive 3-word shingles joined by byte 0x1f; if fewer than 3 words, exactly one feature using the first word; if no words, feature is 'empty'",
            "encoding": "SHA-256 over u32-be length-prefixed domain followed by u32-be length-prefixed feature",
            "bit_order": "bit b maps to byte b//8, bit b%8 (LSB-first)",
            "vote_rule": "score >= 0 sets 1, so a zero vote sets 1",
            "output": "32 bytes as 64 lowercase hex characters",
            "reference": "PreFuzzDup/src/main.cpp simhash_text/make_tag",
        },
        "tool": {
            "path": "tools/enron-5w/prepare_dataset.py",
            "version": TOOL_VERSION,
            "python_version": summary["python_version"],
            "numpy_version": summary["numpy_version"],
        },
        "inputs": {
            "archive": "enron_mail_20150507.tar.gz",
            "archive_sha256": summary["archive_sha256"],
            "maildir": "enron_mail_20150507/maildir",
            "maildir_file_count": summary["corpus_file_count"],
        },
        "statistics": stats,
        "outputs": {
            "bodies_dir": {"path": "bodies", "count": SAMPLE_SIZE},
            "tags_csv": {
                "path": "tags.csv", "rows": SAMPLE_SIZE,
                "sha256": sha256_file(STAGING / "tags.csv"),
                "size_bytes": (STAGING / "tags.csv").stat().st_size,
            },
            "manifest_csv": {
                "path": "manifest.csv", "rows": SAMPLE_SIZE,
                "sha256": sha256_file(STAGING / "manifest.csv"),
                "size_bytes": (STAGING / "manifest.csv").stat().st_size,
            },
            "readme_md": {
                "path": "README.md",
                "sha256": sha256_file(readme_path),
                "size_bytes": readme_path.stat().st_size,
            },
        },
        "verification": {
            "python_internal_checks": "passed",
            "cpp_verifier": "tools/enron-5w/verify_tag.cpp",
            "cpp_verifies_by_including": "PreFuzzDup/src/main.cpp existing make_tag/simhash_text",
            "cpp_summary": {
                "edge_cases_checked": cpp["edge_cases_checked"],
                "edge_cases_matched": cpp["edge_cases_matched"],
                "bodies_checked": cpp["bodies_checked"],
                "bodies_matched": cpp["bodies_matched"],
                "mismatch_count": cpp["mismatch_count"],
            },
            "body_files_rehashed": "all 51740 bodies match manifest sha256 and size",
        },
    }
    (STAGING / "dataset.json").write_text(
        json.dumps(dataset, ensure_ascii=False, indent=2), encoding="utf-8", newline="\n"
    )


def cmd_publish() -> None:
    required = [
        "bodies", "tags.csv", "manifest.csv", "edge_cases.csv",
        "prepare_summary.json", "cpp_verification.json",
    ]
    for name in required:
        if not (STAGING / name).exists():
            fail(f"missing staging artifact: {name}")
    summary = json.loads((STAGING / "prepare_summary.json").read_text(encoding="utf-8"))
    cpp = json.loads((STAGING / "cpp_verification.json").read_text(encoding="utf-8"))
    if cpp.get("mismatch_count") != 0:
        fail("C++ verifier reported mismatches")
    if cpp.get("edge_cases_matched") != cpp.get("edge_cases_checked"):
        fail("C++ verifier edge cases did not all match")
    if cpp.get("bodies_checked") != SAMPLE_SIZE or cpp.get("bodies_matched") != SAMPLE_SIZE:
        fail("C++ verifier did not confirm all body tags")

    print("[1/4] re-validating CSV outputs ...", flush=True)
    validate_csv_outputs()
    print("[2/4] re-hashing all body files ...", flush=True)
    body_count, total_bytes = verify_bodies_against_manifest()
    if body_count != SAMPLE_SIZE or total_bytes != summary["total_body_bytes"]:
        fail("body re-hash totals mismatch")
    print("[3/4] writing README.md and dataset.json ...", flush=True)
    write_dataset_docs(summary, cpp)
    if TARGET.exists():
        if any(TARGET.iterdir()):
            fail(f"target directory is not empty: {TARGET}")
        TARGET.rmdir()
    os.rename(STAGING, TARGET)
    print("[4/4] confirming gitignore coverage ...", flush=True)
    check = subprocess.run(
        ["git", "check-ignore", "-v", "--", TARGET.as_posix() + "/tags.csv"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if check.returncode != 0:
        fail(f"git check-ignore failed for dataset output: {check.stderr.strip()}")
    status = subprocess.run(
        ["git", "status", "--porcelain", "--", CORPUS.as_posix()],
        cwd=ROOT, capture_output=True, text=True,
    )
    if status.stdout.strip():
        fail(f"dataset paths appear in git status: {status.stdout.strip()}")
    result = {
        "published": str(TARGET),
        "sample_size": SAMPLE_SIZE,
        "unique_bodies": summary["unique_bodies"],
        "extra_exact_body_copies": summary["extra_exact_body_copies"],
        "exact_duplicate_groups": summary["exact_duplicate_groups"],
        "empty_word_bodies": summary["empty_word_bodies"],
        "cpp_verification": "51740/51740 bodies and all edge cases matched",
        "gitignore_rule": check.stdout.strip(),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=["prepare", "publish"])
    args = parser.parse_args()
    if args.phase == "prepare":
        cmd_prepare()
    else:
        cmd_publish()


if __name__ == "__main__":
    main()
