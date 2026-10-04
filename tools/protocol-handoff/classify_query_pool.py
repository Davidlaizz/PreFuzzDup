#!/usr/bin/env python3
"""Classify Enron full query pool by exact body match and min tag distance."""

from __future__ import annotations

import csv
import random
from collections import Counter
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "enron_mail_20150507/full50wTest"
EXPECTED_TOTAL = 517_401
REFERENCE_SIZE = 413_921
QUERY_POOL_SIZE = 103_480
SPLIT_SEED = 20_260_921


def main() -> None:
    ids: list[str] = []
    body_sha: dict[str, str] = {}
    norm_sha: dict[str, str] = {}
    with (TARGET / "metadata.csv").open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ids.append(row["id"])
            body_sha[row["id"]] = row["body_sha256"]
            norm_sha[row["id"]] = row["normalized_sha256"]
    if len(ids) != EXPECTED_TOTAL:
        raise RuntimeError(f"expected {EXPECTED_TOTAL} records, got {len(ids)}")

    ref_tags: dict[str, bytes] = {}
    with (TARGET / "normalized_tags.csv").open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ref_tags[row["normalized_sha256"]] = bytes.fromhex(row["tag_hex"])

    rng = random.Random(SPLIT_SEED)
    query_pool = set(rng.sample(sorted(ids), QUERY_POOL_SIZE))
    reference = [i for i in sorted(ids) if i not in query_pool]
    if len(reference) != REFERENCE_SIZE or len(query_pool) != QUERY_POOL_SIZE:
        raise RuntimeError("split size mismatch")

    ref_norms = [norm_sha[i] for i in reference]
    ref_body_set = {body_sha[i] for i in reference}

    ref_packed = np.frombuffer(
        b"".join(ref_tags[n] for n in ref_norms), dtype=np.uint8
    ).reshape(-1, 32)
    ref_uint64 = ref_packed.view(np.uint64).reshape(-1, 4)  # (R, 4)

    query_ids = sorted(query_pool)
    q_packed = np.frombuffer(
        b"".join(ref_tags[norm_sha[i]] for i in query_ids), dtype=np.uint8
    ).reshape(-1, 32)
    q_uint64 = q_packed.view(np.uint64).reshape(-1, 4)  # (Q, 4)

    qbatch = 256
    rbatch = 20_000
    qcount = len(query_ids)
    dmin_partial = np.full(qcount, 256, dtype=np.int64)

    for q_start in range(0, qcount, qbatch):
        q_end = min(q_start + qbatch, qcount)
        qb = q_uint64[q_start:q_end][:, np.newaxis, :]  # (Bq, 1, 4)
        for r_start in range(0, REFERENCE_SIZE, rbatch):
            r_end = min(r_start + rbatch, REFERENCE_SIZE)
            rb = ref_uint64[r_start:r_end][np.newaxis, :, :]  # (1, Br, 4)
            xor = qb ^ rb  # (Bq, Br, 4)
            pop = np.bitwise_count(xor).sum(axis=2)  # (Bq, Br)
            local_min = pop.min(axis=1).astype(np.int64)
            slice_ = dmin_partial[q_start:q_end]
            np.minimum(slice_, local_min, out=slice_)
        if ((q_end // qbatch) % 5) == 0:
            print(f"  distance batch {q_end}/{qcount}", flush=True)

    dmin_list = dmin_partial.tolist()

    exact: list[str] = []
    near: list[tuple[str, int]] = []
    boundary: list[tuple[str, int]] = []
    no_match: list[tuple[str, int]] = []
    tag_zero_diff_body: list[tuple[str, int]] = []

    for qid, dmin in zip(query_ids, dmin_list):
        if body_sha[qid] in ref_body_set:
            exact.append(qid)
            continue
        if 1 <= dmin <= 4:
            near.append((qid, dmin))
        elif 5 <= dmin <= 6:
            boundary.append((qid, dmin))
        elif dmin == 0:
            tag_zero_diff_body.append((qid, dmin))
        else:
            no_match.append((qid, dmin))

    print(f"reference records: {len(reference)}")
    print(f"query pool: {len(query_pool)}")
    print(f"exact_ref available: {len(exact)}")
    print(f"near_ref (1<=d<=4) available: {len(near)}")
    print(f"boundary (5<=d<=6) available: {len(boundary)}")
    print(f"tag_zero_diff_body: {len(tag_zero_diff_body)}")
    print(f"no_match_ref (d>6) available: {len(no_match)}")
    print("near distance distribution:", dict(sorted(Counter(d for _, d in near).items())))
    print("boundary distance distribution:", dict(sorted(Counter(d for _, d in boundary).items())))


if __name__ == "__main__":
    main()