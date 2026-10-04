#!/usr/bin/env python3
"""Compute U_ready, the union of reference candidates for all bench/verify queries.

Runs a full numpy scan against every reference tag at the maximum threshold
(default 6) and writes the ordered union of (record_id, min_distance) so the
server knows exactly which reference records need protocol artefacts.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INPUTS = ROOT / "results-local/three-scheme-full-protocol/inputs"
TARGET = ROOT / "enron_mail_20150507/full50wTest"
MAX_THRESHOLD = 6
OUTPUT = INPUTS / "candidate_union_t6.csv"
SUMMARY = INPUTS / "candidate_union_summary.json"

sys.path.insert(0, str(Path(__file__).resolve().parent))
import prepare_queries as prep


def load_tags() -> dict[str, bytes]:
    body_sha: dict[str, str] = {}
    norm_sha: dict[str, str] = {}
    with (TARGET / "metadata.csv").open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            body_sha[row["id"]] = row["body_sha256"]
            norm_sha[row["id"]] = row["normalized_sha256"]
    tags: dict[str, bytes] = {}
    with (TARGET / "normalized_tags.csv").open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            tags[row["normalized_sha256"]] = bytes.fromhex(row["tag_hex"])
    return {i: tags[norm_sha[i]] for i in body_sha}


def load_query_ids() -> list[str]:
    ids: list[str] = []
    for name in ("queries_bench_5000.csv", "queries_verify_100.csv"):
        with (INPUTS / name).open(newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                ids.append(row["id"])
    return ids


def main() -> None:
    all_tags = load_tags()
    all_ids = sorted(all_tags.keys())
    import random
    rng = random.Random(20_260_921)
    query_pool = set(rng.sample(all_ids, 103_480))
    reference_ids = [i for i in all_ids if i not in query_pool]
    reference_tags = [all_tags[i] for i in reference_ids]
    index = prep.DistanceIndex(reference_tags)

    query_ids = load_query_ids()
    # Map synthetic query IDs (which are not dataset IDs) to their flipped tag.
    synthetic_tags: dict[str, bytes] = {}
    for name in ("queries_bench_5000.csv", "queries_verify_100.csv"):
        with (INPUTS / name).open(newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if row["id"].startswith("synthetic_"):
                    synthetic_tags[row["id"]] = bytes.fromhex(row["tag_hex"])

    union: dict[str, int] = {}
    import numpy as np
    for position, qid in enumerate(query_ids):
        if qid in all_tags:
            tag = all_tags[qid]
        elif qid in synthetic_tags:
            tag = synthetic_tags[qid]
        else:
            raise RuntimeError(f"unknown query id: {qid}")
        distances = index.distances(tag)
        for ref_pos, distance in enumerate(distances):
            if distance <= MAX_THRESHOLD:
                rid = reference_ids[ref_pos]
                if rid not in union or distance < union[rid]:
                    union[rid] = int(distance)
        if (position + 1) % 500 == 0:
            print(f"queries {position + 1}/{len(query_ids)} union={len(union)}", flush=True)

    ordered = sorted(union.items(), key=lambda kv: (kv[1], kv[0]))
    with OUTPUT.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, lineterminator="\n")
        writer.writerow(["record_id", "min_distance"])
        writer.writerows(ordered)

    summary = {
        "max_threshold": MAX_THRESHOLD,
        "query_count": len(query_ids),
        "unique_candidate_records": len(union),
        "reference_count": len(reference_ids),
        "output": OUTPUT.name,
    }
    with SUMMARY.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
