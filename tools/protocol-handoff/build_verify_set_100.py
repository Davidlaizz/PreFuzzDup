#!/usr/bin/env python3
"""Build an independent 100-query verify set from the full query pool.

Unlike the bench 5,000, the verify set is sampled directly from the query
pool and must not reuse any bench query ID. Synthetic near queries follow
route 1 (tag bit-flip + lightly edited base body) and their bodies are
written next to the bench synthetic bodies.
"""

from __future__ import annotations

import csv
import json
import os
import random
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "enron_mail_20150507/full50wTest"
MAILDIR = ROOT / "enron_mail_20150507/maildir"
INPUTS = ROOT / "results-local/three-scheme-full-protocol/inputs"

EXPECTED_TOTAL = 517_401
REFERENCE_SIZE = 413_921
QUERY_POOL_SIZE = 103_480
SPLIT_SEED = 20_260_921

VERIFY_SEED = 20261002
QUOTAS = {"exact_ref": 30, "near_ref": 40, "no_match_ref": 30}
NEAR_NATURAL_COUNT = 0
NEAR_SYNTHETIC_COUNT = QUOTAS["near_ref"] - NEAR_NATURAL_COUNT
NEAR_MIN_DISTANCE = 1
NEAR_MAX_DISTANCE = 4

sys.path.insert(0, str(Path(__file__).resolve().parent))
import prepare_queries as prep


def load_metadata() -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    body_sha: dict[str, str] = {}
    norm_sha: dict[str, str] = {}
    source_path: dict[str, str] = {}
    with (TARGET / "metadata.csv").open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            body_sha[row["id"]] = row["body_sha256"]
            norm_sha[row["id"]] = row["normalized_sha256"]
    with (TARGET / "manifest.csv").open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            source_path[row["id"]] = row["source_path"]
    return body_sha, norm_sha, source_path


def load_tags() -> dict[str, bytes]:
    tags: dict[str, bytes] = {}
    with (TARGET / "normalized_tags.csv").open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            tags[row["normalized_sha256"]] = bytes.fromhex(row["tag_hex"])
    return tags


def load_distances() -> dict[str, int]:
    distances: dict[str, int] = {}
    with (TARGET / "query_pool_distances.csv").open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            distances[row["id"]] = int(row["dmin"])
    return distances


def body_of(record_id: str, source_path: dict[str, str]) -> bytes:
    raw = (MAILDIR / source_path[record_id].replace("/", os.sep)).read_bytes()
    raw = raw.replace(b"\r\n", b"\n")
    _, separator, body = raw.partition(b"\n\n")
    if not separator:
        raise RuntimeError(f"no header/body separator for {record_id}")
    return body.strip()


def main() -> None:
    body_sha, norm_sha, source_path = load_metadata()
    tags = load_tags()
    distances = load_distances()

    all_ids = sorted(body_sha.keys())
    if len(all_ids) != EXPECTED_TOTAL:
        raise RuntimeError(f"expected {EXPECTED_TOTAL} IDs, got {len(all_ids)}")

    rng_split = random.Random(SPLIT_SEED)
    query_pool = set(rng_split.sample(all_ids, QUERY_POOL_SIZE))
    reference_ids = [i for i in all_ids if i not in query_pool]
    if len(reference_ids) != REFERENCE_SIZE:
        raise RuntimeError(f"expected reference {REFERENCE_SIZE}, got {len(reference_ids)}")

    reference_tags = {i: tags[norm_sha[i]] for i in reference_ids}
    reference_body_set = {body_sha[i] for i in reference_ids}
    index = prep.DistanceIndex([reference_tags[i] for i in reference_ids])
    reference_position = {rid: pos for pos, rid in enumerate(reference_ids)}

    exact_available = sorted(q for q in query_pool if body_sha[q] in reference_body_set)
    near_available = sorted(
        q for q in query_pool
        if body_sha[q] not in reference_body_set
        and NEAR_MIN_DISTANCE <= distances[q] <= NEAR_MAX_DISTANCE
    )
    no_match_available = sorted(
        q for q in query_pool
        if body_sha[q] not in reference_body_set
        and distances[q] > NEAR_MAX_DISTANCE
    )
    print(f"pool exact={len(exact_available)} near={len(near_available)} no_match={len(no_match_available)}", flush=True)

    selected_exact = prep.sample_ids(exact_available, QUOTAS["exact_ref"], VERIFY_SEED)
    selected_near = prep.sample_ids(near_available, NEAR_NATURAL_COUNT, VERIFY_SEED + 1)
    selected_no_match = prep.sample_ids(no_match_available, QUOTAS["no_match_ref"], VERIFY_SEED + 2)

    bench_ids: set[str] = set()
    with (INPUTS / "queries_bench_5000.csv").open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            bench_ids.add(row["id"])

    def exclude_bench(candidates: list[str]) -> list[str]:
        return [q for q in candidates if q not in bench_ids]

    selected_exact = prep.sample_ids(exclude_bench(exact_available), QUOTAS["exact_ref"], VERIFY_SEED)
    if NEAR_NATURAL_COUNT:
        selected_near = prep.sample_ids(exclude_bench(near_available), NEAR_NATURAL_COUNT, VERIFY_SEED + 1)
    else:
        selected_near = []
    selected_no_match = prep.sample_ids(exclude_bench(no_match_available), QUOTAS["no_match_ref"], VERIFY_SEED + 2)

    overlap = (set(selected_exact) | set(selected_near) | set(selected_no_match)) & bench_ids
    if overlap:
        raise RuntimeError(f"verify set overlaps bench: {sorted(overlap)[:5]}")

    bodies_dir = INPUTS / "bodies_verify"
    rng = random.Random(VERIFY_SEED + 3)
    synthetic: list[dict] = []
    used_bases: set[str] = set()
    candidate_bases = prep.sample_ids(reference_ids, len(reference_ids), VERIFY_SEED + 4)
    for rid in candidate_bases:
        if len(synthetic) >= NEAR_SYNTHETIC_COUNT:
            break
        if rid in used_bases:
            continue
        try:
            body = body_of(rid, source_path)
        except Exception as exc:
            print(f"skip base {rid}: {exc}", flush=True)
            continue
        if len(prep.word_spans(body)) < 10:
            continue
        result = prep.perturb_until_near(body, index, rng, reference_position[rid])
        if result is None:
            continue
        edited_body, flipped_tag, dmin = result
        query_id = f"synthetic_near_verify_{len(synthetic) + 1:03d}"
        record = prep.store_body(bodies_dir, query_id, edited_body, prep.tag_of(edited_body))
        used_bases.add(rid)
        synthetic.append({
            "query_id": query_id,
            "base_id": rid,
            "dmin": dmin,
            "tag_hex": flipped_tag.hex(),
            "body_tag_hex": record["tag_hex"],
            "body_sha256": record["body_sha256"],
        })
        if len(synthetic) % 10 == 0:
            print(f"verify synthetic {len(synthetic)}/{NEAR_SYNTHETIC_COUNT}", flush=True)

    if len(synthetic) != NEAR_SYNTHETIC_COUNT:
        raise RuntimeError(f"synthesized {len(synthetic)}/{NEAR_SYNTHETIC_COUNT}")

    query_rows: list[dict] = []
    group_rows: list[dict] = []
    for qid in selected_exact:
        query_rows.append({"id": qid, "type": "text", "tag_hex": tags[norm_sha[qid]].hex()})
        group_rows.append({"query_id": qid, "group": "exact_ref", "dmin": 0, "base_id": ""})
    for qid in selected_near:
        query_rows.append({"id": qid, "type": "text", "tag_hex": tags[norm_sha[qid]].hex()})
        group_rows.append({"query_id": qid, "group": "near_ref", "dmin": distances[qid], "base_id": ""})
    for item in synthetic:
        query_rows.append({"id": item["query_id"], "type": "text", "tag_hex": item["tag_hex"]})
        group_rows.append({"query_id": item["query_id"], "group": "near_ref_synthetic", "dmin": item["dmin"], "base_id": item["base_id"]})
    for qid in selected_no_match:
        query_rows.append({"id": qid, "type": "text", "tag_hex": tags[norm_sha[qid]].hex()})
        group_rows.append({"query_id": qid, "group": "no_match_ref", "dmin": distances[qid], "base_id": ""})

    rng.shuffle(query_rows)
    group_map = {r["query_id"]: r for r in group_rows}

    with (INPUTS / "queries_verify_100.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["id", "type", "tag_hex"], lineterminator="\n")
        writer.writeheader()
        writer.writerows(query_rows)

    with (INPUTS / "query_groups_verify_100.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["query_id", "group", "dmin", "base_id"], lineterminator="\n")
        writer.writeheader()
        for row in query_rows:
            writer.writerow(group_map[row["id"]])

    summary = {
        "verify_query_count": len(query_rows),
        "group_counts": dict(Counter(r["group"] for r in group_rows)),
        "natural_near_count": len(selected_near),
        "synthetic_near_count": len(synthetic),
        "verify_seed": VERIFY_SEED,
        "overlaps_bench": 0,
        "synthetic_bodies_dir": "bodies_verify",
        "synthetic_bodies_count": len(synthetic),
    }
    with (INPUTS / "verify_split_summary.json").open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print("wrote verify 100", len(query_rows))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
