#!/usr/bin/env python3
"""Precompute min tag distance for every query-pool record."""

from __future__ import annotations

import csv
import random
import struct
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "enron_mail_20150507/full50wTest"
EXPECTED_TOTAL = 517_401
QUERY_POOL_SIZE = 103_480
SPLIT_SEED = 20_260_921


def main() -> None:
    ids = []
    norm_sha = {}
    with (TARGET / "metadata.csv").open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ids.append(row["id"])
            norm_sha[row["id"]] = row["normalized_sha256"]

    ref_tags = {}
    with (TARGET / "normalized_tags.csv").open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ref_tags[row["normalized_sha256"]] = bytes.fromhex(row["tag_hex"])

    rng = random.Random(SPLIT_SEED)
    query_pool = set(rng.sample(sorted(ids), QUERY_POOL_SIZE))
    reference = [i for i in sorted(ids) if i not in query_pool]

    ref_norms = [norm_sha[i] for i in reference]
    ref_packed = np.frombuffer(b"".join(ref_tags[n] for n in ref_norms), dtype=np.uint8).reshape(-1, 32)
    ref_uint64 = ref_packed.view(np.uint64).reshape(-1, 4)

    query_ids = sorted(query_pool)
    q_packed = np.frombuffer(b"".join(ref_tags[norm_sha[i]] for i in query_ids), dtype=np.uint8).reshape(-1, 32)
    q_uint64 = q_packed.view(np.uint64).reshape(-1, 4)

    qbatch = 256
    rbatch = 20_000
    qcount = len(query_ids)
    dmin_partial = np.full(qcount, 256, dtype=np.int64)

    for q_start in range(0, qcount, qbatch):
        q_end = min(q_start + qbatch, qcount)
        qb = q_uint64[q_start:q_end][:, np.newaxis, :]
        for r_start in range(0, len(reference), rbatch):
            r_end = min(r_start + rbatch, len(reference))
            rb = ref_uint64[r_start:r_end][np.newaxis, :, :]
            xor = qb ^ rb
            pop = np.bitwise_count(xor).sum(axis=2)
            local_min = pop.min(axis=1).astype(np.int64)
            slice_ = dmin_partial[q_start:q_end]
            np.minimum(slice_, local_min, out=slice_)
        if (q_end % (qbatch * 10)) == 0:
            print(f"  distance batch {q_end}/{qcount}", flush=True)

    out = TARGET / "query_pool_distances.csv"
    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, lineterminator="\n")
        writer.writerow(["id", "dmin"])
        for qid, d in zip(query_ids, dmin_partial.tolist()):
            writer.writerow([qid, d])
    print(f"wrote {out}")


if __name__ == "__main__":
    main()