#!/usr/bin/env python3
"""Prepare tags and provenance for all Enron maildir bodies."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import random
import re
import shutil
import struct
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import numpy as np


TOOL_VERSION = "1.0.0"
EXPECTED_TOTAL = 517_401
REFERENCE_SIZE = 413_921
QUERY_POOL_SIZE = 103_480
SPLIT_SEED = 20_260_921
DOMAIN = b"PreFuzzDup/tag/text/v1"
DOMAIN_FIELD = struct.pack(">I", len(DOMAIN)) + DOMAIN
WORD_RE = re.compile(rb"[0-9a-z]+")
TAG_CHUNK = 65_536

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "enron_mail_20150507"
MAILDIR = CORPUS / "maildir"
ARCHIVE = CORPUS.parent / "enron_mail_20150507.tar.gz"
STAGING = CORPUS / "full50wTest.staging"
TARGET = CORPUS / "full50wTest"

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


def fail(message: str) -> None:
    raise RuntimeError(message)


def words_of(body: bytes) -> list[bytes]:
    return WORD_RE.findall(body.lower())


def extract_body(raw: bytes, source_rel: str) -> bytes:
    raw = raw.replace(b"\r\n", b"\n")
    _, separator, body = raw.partition(b"\n\n")
    if not separator:
        fail(f"no header/body separator: maildir/{source_rel}")
    return body.strip()


def simhash_tag(words: list[bytes]) -> bytes:
    if not words:
        words = [b"empty"]
    if len(words) < 3:
        features = [words[0]]
    else:
        features = [
            b"\x1f".join((words[index], words[index + 1], words[index + 2]))
            for index in range(len(words) - 2)
        ]
    score = np.zeros(256, dtype=np.int64)
    total = len(features)
    for begin in range(0, total, TAG_CHUNK):
        chunk = features[begin : min(begin + TAG_CHUNK, total)]
        digests = np.empty((len(chunk), 32), dtype=np.uint8)
        for index, feature in enumerate(chunk):
            digest = hashlib.sha256(
                DOMAIN_FIELD + struct.pack(">I", len(feature)) + feature
            ).digest()
            digests[index] = np.frombuffer(digest, dtype=np.uint8)
        bits = ((digests[:, :, None] >> np.arange(8, dtype=np.uint8)) & 1).reshape(
            len(chunk), 256
        )
        score += 2 * bits.sum(axis=0, dtype=np.int64) - len(chunk)
    tag_bits = score >= 0
    return np.packbits(tag_bits, bitorder="little").tobytes()


ONE_WORD_TEXT = simhash_tag(words_of(b"hello"))


def enumerate_emails() -> list[str]:
    paths: list[str] = []
    for directory, _directories, filenames in os.walk(MAILDIR):
        base = Path(directory)
        for name in filenames:
            relative = (base / name).relative_to(MAILDIR).as_posix()
            if "/" not in relative:
                fail(f"unexpected file directly under maildir: {relative}")
            paths.append(relative)
    paths.sort()
    if len(paths) != EXPECTED_TOTAL:
        fail(f"expected {EXPECTED_TOTAL} mail files, found {len(paths)}")
    return paths


def split_full_ids(ids: list[str], seed: int) -> tuple[list[str], list[str]]:
    if len(ids) != EXPECTED_TOTAL:
        fail(f"expected {EXPECTED_TOTAL} IDs, got {len(ids)}")
    selected = set(random.Random(seed).sample(sorted(ids), QUERY_POOL_SIZE))
    reference = [item for item in sorted(ids) if item not in selected]
    query_pool = [item for item in sorted(ids) if item in selected]
    if len(reference) != REFERENCE_SIZE or len(query_pool) != QUERY_POOL_SIZE:
        fail("unexpected full split size")
    return reference, query_pool


def worker_metadata(relative: str) -> tuple[str, str, int, str, int]:
    source = MAILDIR.joinpath(*relative.split("/"))
    try:
        raw = source.read_bytes()
    except OSError as error:
        fail(f"cannot read maildir/{relative}: {error}")
    body = extract_body(raw, relative)
    words = words_of(body)
    normalized = b" ".join(words)
    return (
        hashlib.sha256(body).hexdigest(),
        len(body),
        hashlib.sha256(normalized).hexdigest(),
        len(words),
        relative,
    )


def worker_tags(relative_items: list[tuple[str, str]]) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for normalized_hash, relative in relative_items:
        source = MAILDIR.joinpath(*relative.split("/"))
        raw = source.read_bytes()
        body = extract_body(raw, relative)
        result.append((normalized_hash, simhash_tag(words_of(body)).hex()))
    return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_metadata(
    paths: list[str],
    output: Path,
    workers: int,
) -> tuple[Counter[str], dict[str, str], dict[str, int]]:
    body_counts: Counter[str] = Counter()
    normalized_first: dict[str, str] = {}
    normalized_counts: dict[str, int] = {}
    fields = [
        "id", "mailbox", "source_path", "body_sha256", "body_size_bytes",
        "normalized_sha256", "normalized_word_count",
    ]
    with output.open("w", newline="", encoding="utf-8") as target:
        writer = csv.DictWriter(target, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        with ProcessPoolExecutor(max_workers=workers) as executor:
            iterator = executor.map(worker_metadata, paths, chunksize=64)
            for index, (body_hash, body_size, normalized_hash, word_count, relative) in enumerate(iterator, 1):
                record_id = f"enron_full_{index:06d}"
                mailbox = relative.split("/", 1)[0]
                writer.writerow(
                    {
                        "id": record_id,
                        "mailbox": mailbox,
                        "source_path": relative,
                        "body_sha256": body_hash,
                        "body_size_bytes": body_size,
                        "normalized_sha256": normalized_hash,
                        "normalized_word_count": word_count,
                    }
                )
                body_counts[body_hash] += 1
                normalized_counts[normalized_hash] = normalized_counts.get(normalized_hash, 0) + 1
                normalized_first.setdefault(normalized_hash, relative)
                if index % 50_000 == 0:
                    print(f"  metadata {index}/{EXPECTED_TOTAL}", flush=True)
    return body_counts, normalized_first, normalized_counts


def compute_all_tags(
    normalized_first: dict[str, str],
    output: Path,
    workers: int,
) -> dict[str, str]:
    items = list(normalized_first.items())
    batch_size = 256
    batches = [items[begin : begin + batch_size] for begin in range(0, len(items), batch_size)]
    tags: dict[str, str] = {}
    completed = 0
    with ProcessPoolExecutor(max_workers=workers) as executor:
        for batch in executor.map(worker_tags, batches, chunksize=1):
            for normalized_hash, tag in batch:
                if normalized_hash in tags:
                    fail(f"duplicate normalized hash task: {normalized_hash}")
                tags[normalized_hash] = tag
            completed += len(batch)
            if completed % 25_000 < batch_size:
                print(f"  tags {completed}/{len(items)}", flush=True)
    if len(tags) != len(items):
        fail("tag worker returned missing normalized hashes")
    with output.open("w", newline="", encoding="utf-8") as target:
        writer = csv.DictWriter(target, fieldnames=["normalized_sha256", "tag_hex"], lineterminator="\n")
        writer.writeheader()
        for normalized_hash, tag in tags.items():
            writer.writerow({"normalized_sha256": normalized_hash, "tag_hex": tag})
    return tags


def duplicate_distribution(counts: Iterable[int]) -> dict[str, Any]:
    values = sorted(counts)
    if not values:
        fail("cannot summarize an empty duplicate distribution")
    def percentile(quantile: float) -> int:
        position = round((len(values) - 1) * quantile)
        return values[position]
    buckets = {
        "1": 0,
        "2": 0,
        "3_10": 0,
        "11_100": 0,
        "over_100": 0,
    }
    for value in values:
        if value == 1:
            buckets["1"] += 1
        elif value == 2:
            buckets["2"] += 1
        elif value <= 10:
            buckets["3_10"] += 1
        elif value <= 100:
            buckets["11_100"] += 1
        else:
            buckets["over_100"] += 1
    return {
        "groups": len(values),
        "max": values[-1],
        "p50": percentile(0.50),
        "p95": percentile(0.95),
        "p99": percentile(0.99),
        "buckets": buckets,
    }


def read_metadata_rows(path: Path) -> Iterable[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as source:
        for row in csv.DictReader(source):
            yield row


def write_public_csvs(
    metadata_path: Path,
    normalized_tags: dict[str, str],
    tags_path: Path,
    manifest_path: Path,
) -> dict[str, int]:
    tag_rows = 0
    manifest_rows = 0
    source_paths: set[str] = set()
    ids: set[str] = set()
    empty_words = 0
    total_words = 0
    total_body_bytes = 0
    with tags_path.open("w", newline="", encoding="utf-8") as tag_target, manifest_path.open(
        "w", newline="", encoding="utf-8"
    ) as manifest_target:
        tag_writer = csv.DictWriter(
            tag_target, fieldnames=["id", "type", "tag_hex"], lineterminator="\n"
        )
        manifest_writer = csv.DictWriter(
            manifest_target,
            fieldnames=[
                "id", "mailbox", "source_path", "body_sha256",
                "body_size_bytes", "normalized_word_count",
            ],
            lineterminator="\n",
        )
        tag_writer.writeheader()
        manifest_writer.writeheader()
        for row in read_metadata_rows(metadata_path):
            if row["id"] in ids or row["source_path"] in source_paths:
                fail(f"duplicate ID or source path: {row['id']}")
            ids.add(row["id"])
            source_paths.add(row["source_path"])
            tag = normalized_tags.get(row["normalized_sha256"])
            if tag is None:
                fail(f"missing tag for normalized body: {row['id']}")
            tag_writer.writerow({"id": row["id"], "type": "text", "tag_hex": tag})
            manifest_writer.writerow(
                {
                    "id": row["id"],
                    "mailbox": row["mailbox"],
                    "source_path": row["source_path"],
                    "body_sha256": row["body_sha256"],
                    "body_size_bytes": row["body_size_bytes"],
                    "normalized_word_count": row["normalized_word_count"],
                }
            )
            tag_rows += 1
            manifest_rows += 1
            words = int(row["normalized_word_count"])
            if words == 0:
                empty_words += 1
            total_words += words
            total_body_bytes += int(row["body_size_bytes"])
    if tag_rows != EXPECTED_TOTAL or manifest_rows != EXPECTED_TOTAL:
        fail(f"unexpected public row count: tags={tag_rows}, manifest={manifest_rows}")
    return {
        "rows": tag_rows,
        "empty_word_bodies": empty_words,
        "total_normalized_words": total_words,
        "total_body_bytes": total_body_bytes,
    }


def validate_public_outputs(staging: Path) -> None:
    expected_tag = re.compile(r"^[0-9a-f]{64}$")
    seen_ids: set[str] = set()
    with (staging / "tags.csv").open(newline="", encoding="utf-8") as tags, (
        staging / "manifest.csv"
    ).open(newline="", encoding="utf-8") as manifests:
        tag_reader = csv.DictReader(tags)
        manifest_reader = csv.DictReader(manifests)
        if tag_reader.fieldnames != ["id", "type", "tag_hex"]:
            fail("tags.csv header mismatch")
        if manifest_reader.fieldnames != [
            "id", "mailbox", "source_path", "body_sha256",
            "body_size_bytes", "normalized_word_count",
        ]:
            fail("manifest.csv header mismatch")
        count = 0
        for tag_row, manifest_row in zip(tag_reader, manifest_reader):
            count += 1
            if tag_row["id"] != manifest_row["id"] or tag_row["id"] in seen_ids:
                fail(f"tag/manifest ID mismatch or duplicate at row {count}")
            seen_ids.add(tag_row["id"])
            if tag_row["type"] != "text" or not expected_tag.fullmatch(tag_row["tag_hex"]):
                fail(f"invalid tag row at row {count}")
            if int(manifest_row["body_size_bytes"]) < 0 or int(manifest_row["normalized_word_count"]) < 0:
                fail(f"invalid numeric manifest field at row {count}")
        if count != EXPECTED_TOTAL:
            fail(f"expected {EXPECTED_TOTAL} public rows, found {count}")
        next_tags = next(tag_reader, None)
        next_manifests = next(manifest_reader, None)
        if next_tags is not None or next_manifests is not None:
            fail("tags.csv and manifest.csv row counts differ")


def cmd_prepare(workers: int) -> None:
    started = time.perf_counter()
    if STAGING.exists():
        fail(f"staging directory already exists: {STAGING}")
    if TARGET.exists():
        fail(f"target directory already exists: {TARGET}")
    if not MAILDIR.is_dir():
        fail(f"maildir not found: {MAILDIR}")
    STAGING.mkdir(parents=True)
    try:
        print(f"[1/6] enumerating {MAILDIR} ...", flush=True)
        paths = enumerate_emails()

        print(f"[2/6] extracting metadata with {workers} workers ...", flush=True)
        body_counts, normalized_first, normalized_counts = write_metadata(
            paths, STAGING / "metadata.csv", workers
        )

        print(f"[3/6] computing {len(normalized_first):,} unique normalized-body tags ...", flush=True)
        normalized_tags = compute_all_tags(
            normalized_first, STAGING / "normalized_tags.csv", workers
        )

        print("[4/6] writing public tags.csv and manifest.csv ...", flush=True)
        public_stats = write_public_csvs(
            STAGING / "metadata.csv",
            normalized_tags,
            STAGING / "tags.csv",
            STAGING / "manifest.csv",
        )

        print("[5/6] writing edge cases and validating outputs ...", flush=True)
        with (STAGING / "edge_cases.csv").open(
            "w", newline="", encoding="utf-8"
        ) as target:
            writer = csv.DictWriter(
                target, fieldnames=["name", "input_hex", "expected_hex"], lineterminator="\n"
            )
            writer.writeheader()
            for name, data in EDGE_CASES:
                writer.writerow(
                    {
                        "name": name,
                        "input_hex": data.hex(),
                        "expected_hex": simhash_tag(words_of(data)).hex(),
                    }
                )
        validate_public_outputs(STAGING)

        print("[6/6] hashing archive and writing summary ...", flush=True)
        archive_hash = sha256_file(ARCHIVE)
        unique_bodies = len(body_counts)
        summary = {
            "tool_version": TOOL_VERSION,
            "corpus_file_count": len(paths),
            "sample_size": EXPECTED_TOTAL,
            "archive_sha256": archive_hash,
            "unique_bodies": unique_bodies,
            "extra_exact_body_copies": EXPECTED_TOTAL - unique_bodies,
            "exact_duplicate_groups": sum(value > 1 for value in body_counts.values()),
            "exact_duplicate_distribution": duplicate_distribution(body_counts.values()),
            "unique_normalized_bodies": len(normalized_counts),
            "normalized_duplicate_distribution": duplicate_distribution(normalized_counts.values()),
            "empty_word_bodies": public_stats["empty_word_bodies"],
            "total_normalized_words": public_stats["total_normalized_words"],
            "total_body_bytes": public_stats["total_body_bytes"],
            "workers": workers,
            "elapsed_seconds": round(time.perf_counter() - started, 3),
            "python_version": platform.python_version(),
            "numpy_version": np.__version__,
        }
        expected_body_stats = {
            "body_files": EXPECTED_TOTAL,
            "unique_bodies": 247_872,
            "extra_exact_body_copies": 269_529,
            "exact_duplicate_groups": 132_046,
        }
        actual_body_stats = {
            "body_files": summary["corpus_file_count"],
            "unique_bodies": summary["unique_bodies"],
            "extra_exact_body_copies": summary["extra_exact_body_copies"],
            "exact_duplicate_groups": summary["exact_duplicate_groups"],
        }
        if actual_body_stats != expected_body_stats:
            fail(f"body statistics differ from authoritative full scan: {actual_body_stats}")
        (STAGING / "prepare_summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
        print(f"staging ready: {STAGING}", flush=True)
        print("next: compile and run verify_full_tag.cpp, then run publish", flush=True)
    except Exception:
        print(f"staging retained for diagnosis: {STAGING}", file=sys.stderr)
        raise


def cmd_publish() -> None:
    required = [
        "tags.csv", "manifest.csv", "metadata.csv", "normalized_tags.csv",
        "edge_cases.csv", "prepare_summary.json", "cpp_verification.json",
    ]
    for name in required:
        if not (STAGING / name).is_file():
            fail(f"missing staging artifact: {name}")
    summary = json.loads((STAGING / "prepare_summary.json").read_text(encoding="utf-8"))
    cpp = json.loads((STAGING / "cpp_verification.json").read_text(encoding="utf-8"))
    if cpp.get("mismatch_count") != 0:
        fail("C++ verifier reported mismatches")
    if cpp.get("bodies_checked") != EXPECTED_TOTAL or cpp.get("bodies_matched") != EXPECTED_TOTAL:
        fail("C++ verifier did not check every body successfully")
    if cpp.get("edge_cases_matched") != cpp.get("edge_cases_checked"):
        fail("C++ verifier edge cases did not pass")

    dataset = {
        "dataset_name": "enron_full_body_tags_v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "full-corpus data preparation; no reference/query split or benchmark run",
        "source": {
            "maildir_file_count": EXPECTED_TOTAL,
            "archive_sha256": summary["archive_sha256"],
            "natural_duplicates_retained": True,
        },
        "id_format": "enron_full_%06d",
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
        "statistics": {
            key: summary[key]
            for key in (
                "corpus_file_count", "sample_size", "unique_bodies",
                "extra_exact_body_copies", "exact_duplicate_groups",
                "exact_duplicate_distribution", "unique_normalized_bodies",
                "normalized_duplicate_distribution", "empty_word_bodies",
                "total_normalized_words", "total_body_bytes",
            )
        },
        "verification": {
            "python_internal_checks": "passed",
            "cpp_verifier": "tools/enron-full/verify_full_tag.cpp",
            "cpp_verifies_by_including": "PreFuzzDup/src/main.cpp make_tag/simhash_text",
            "cpp_summary": {
                "edge_cases_checked": cpp["edge_cases_checked"],
                "edge_cases_matched": cpp["edge_cases_matched"],
                "bodies_checked": cpp["bodies_checked"],
                "bodies_matched": cpp["bodies_matched"],
                "distinct_tag_computations": cpp.get("distinct_tag_computations"),
                "mismatch_count": cpp["mismatch_count"],
            },
        },
        "outputs": {
            "tags_csv": {"rows": EXPECTED_TOTAL, "sha256": sha256_file(STAGING / "tags.csv")},
            "manifest_csv": {"rows": EXPECTED_TOTAL, "sha256": sha256_file(STAGING / "manifest.csv")},
            "edge_cases_csv": {"sha256": sha256_file(STAGING / "edge_cases.csv")},
        },
    }
    (STAGING / "dataset.json").write_text(
        json.dumps(dataset, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    readme = [
        "# Enron 全量正文标签数据集",
        "",
        "本目录覆盖 `enron_mail_20150507/maildir` 下全部 517,401 封邮件，保留自然重复，",
        "并为每个正文生成 256 位 PreFuzzDup 文本 SimHash 标签。正文不另行复制，来源以",
        "`manifest.csv` 的 `source_path` 回指原始 maildir 文件。",
        "",
        "预处理、分词、特征编码和标签输出与 `5wTest` 完全一致。全量标签已由独立 C++",
        "校验器逐行核对；相同正文只重算一次标签，其余副本通过确定性映射核对。",
        "",
        "本阶段仅准备数据，尚未划分参考库/查询集，也未运行三套检索基准。",
    ]
    (STAGING / "README.md").write_text("\n".join(readme) + "\n", encoding="utf-8", newline="\n")
    STAGING.rename(TARGET)
    print(f"published: {TARGET}")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "publish"))
    parser.add_argument("--workers", type=int, default=max(1, min(8, os.cpu_count() or 1)))
    arguments = parser.parse_args()
    if arguments.workers <= 0:
        fail("workers must be positive")
    return arguments


def main() -> int:
    arguments = parse_arguments()
    try:
        if arguments.phase == "prepare":
            cmd_prepare(arguments.workers)
        else:
            cmd_publish()
        return 0
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
