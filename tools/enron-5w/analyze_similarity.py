"""Ground-truth similarity statistics for the 51,740-body Enron sample.

Labels use text bytes directly (SHA-256 and 5-word shingle Jaccard), not the
SimHash tags. Candidate recall follows the earlier full-corpus probe: shared
5-word shingles with document frequency <= 40, up to the 12 rarest shared
shingles per body. Recall is not exhaustive, so "none found" is not proof of
semantic unrelatedness.
"""
import csv
import hashlib
import json
import random
import re
import time
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "enron_mail_20150507" / "5wTest"
OUT = ROOT / "results-local/enron-5w"
WORD_RE = re.compile(rb"[0-9a-z]+")
SEED = 20260920
RANDOM_PAIRS = 10000


def shingle_hashes(body: bytes) -> np.ndarray:
    words = WORD_RE.findall(body.lower())
    if len(words) < 5:
        return np.empty(0, dtype=np.int64)
    values = []
    for i in range(len(words) - 4):
        shingle = b" ".join(words[i : i + 5])
        digest = hashlib.blake2b(shingle, digest_size=8).digest()
        values.append(int.from_bytes(digest, "little", signed=True))
    return np.unique(np.asarray(values, dtype=np.int64))


def classify_pair(a: int, b: int, digests: list[str],
                  shingles: list[np.ndarray]) -> tuple[str, float]:
    if digests[a] == digests[b]:
        return "exact_body", 1.0
    x, y = shingles[a], shingles[b]
    if x.size == 0 or y.size == 0:
        return "low_text_overlap", 0.0
    inter = np.intersect1d(x, y, assume_unique=True).size
    union = x.size + y.size - inter
    value = inter / union
    if value >= 0.5:
        return "possible_similar", value
    if value < 0.1:
        return "low_text_overlap", value
    return "uncertain", value


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    started = time.time()
    with (DATA / "manifest.csv").open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != 51740:
        raise SystemExit(f"unexpected manifest rows: {len(rows)}")
    ids = [row["id"] for row in rows]
    digests = [row["body_sha256"] for row in rows]
    word_counts = [int(row["normalized_word_count"]) for row in rows]

    shingles: list[np.ndarray] = []
    for index, row in enumerate(rows, 1):
        body = (DATA / row["body_path"]).read_bytes()
        shingles.append(shingle_hashes(body))
        if index % 10000 == 0:
            print(f"shingled {index}/51740", flush=True)

    all_hashes = np.concatenate([x for x in shingles if x.size])
    all_hashes.sort()
    adjacent = all_hashes[1:] == all_hashes[:-1]
    member_mask = np.zeros(all_hashes.shape, dtype=bool)
    member_mask[:-1] |= adjacent
    member_mask[1:] |= adjacent
    duplicated = np.unique(all_hashes[member_mask])
    del all_hashes, adjacent, member_mask

    postings: dict[int, list[int]] = defaultdict(list)
    for doc, arr in enumerate(shingles):
        if arr.size == 0:
            continue
        pos = np.searchsorted(duplicated, arr)
        np.clip(pos, 0, duplicated.size - 1, out=pos)
        for value in arr[duplicated[pos] == arr]:
            postings[int(value)].append(doc)

    pairs = set()
    for a, arr in enumerate(shingles):
        if arr.size == 0:
            continue
        usable = []
        for value in arr:
            hit = postings.get(int(value))
            if hit is not None and 1 < len(hit) <= 40:
                usable.append((len(hit), int(value)))
        for _, value in sorted(usable)[:12]:
            for b in postings[value]:
                if a != b:
                    pairs.add((a, b) if a < b else (b, a))
        if (a + 1) % 10000 == 0:
            print(f"recall {a + 1}/51740, pairs={len(pairs)}", flush=True)

    rng = random.Random(SEED)
    random_pairs = set()
    while len(random_pairs) < RANDOM_PAIRS:
        a, b = rng.sample(range(len(rows)), 2)
        random_pairs.add((a, b) if a < b else (b, a))

    pair_stats = {}
    pair_docs = {"possible_similar": set(), "exact_body": set()}
    jaccards = {"body_candidate_pairs": [], "random_pairs": []}
    for name, source in (("body_candidate_pairs", pairs), ("random_pairs", random_pairs)):
        bins = Counter()
        for a, b in sorted(source):
            label, value = classify_pair(a, b, digests, shingles)
            bins[label] += 1
            jaccards[name].append(value)
            if label in pair_docs:
                pair_docs[label].update((a, b))
        pair_stats[name] = {"pair_count": len(source), "classes": bins}

    digest_counts = Counter(digests)
    exact_docs = {i for i, digest in enumerate(digests) if digest_counts[digest] > 1}
    exact_pairs_total = sum(count * (count - 1) // 2 for count in digest_counts.values() if count > 1)
    possible_docs = pair_docs["possible_similar"] - exact_docs
    none_docs = set(range(len(rows))) - exact_docs - possible_docs

    doc_classes = {
        "exact_body_exists": len(exact_docs),
        "possible_similar_found_no_exact": len(possible_docs),
        "none_found_by_this_recall": len(none_docs),
    }
    short_docs = sum(1 for count in word_counts if count < 5)
    under_20_docs = sum(1 for count in word_counts if count < 20)

    result = {
        "dataset": str(DATA),
        "documents": len(rows),
        "seed": SEED,
        "document_classes": doc_classes,
        "documents_with_fewer_than_5_words": short_docs,
        "documents_with_fewer_than_20_words": under_20_docs,
        "exact_pairs_from_all_sha256_groups": exact_pairs_total,
        "pair_statistics": pair_stats,
        "mean_jaccard": {name: round(sum(values) / len(values), 6) for name, values in jaccards.items()},
        "elapsed_seconds": round(time.time() - started, 1),
        "method": [
            "Exact bodies use equal SHA-256 (byte equality for identical digests).",
            "Non-identical pairs use 5-word shingle Jaccard: >=0.5 possible, <0.1 low overlap, else uncertain.",
            "Candidate recall: up to 12 rarest shared 5-word shingles per body, document frequency <=40; recall is not exhaustive.",
            "Random pairs use the same seed 20260920 and are a baseline, not a truth-complete partition.",
            "Document classes use precedence: exact twin exists, then possible-similar candidate found, then none found.",
            "None-found means not discovered by this recall rule and exact hashing; it does not prove semantic unrelatedness.",
        ],
    }
    (OUT / "similarity-stats.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    report = [
        "# 5wTest 正文真实相似度统计", "",
        f"样本邮件 {len(rows):,} 封。真值判定不用 SimHash：完全相同按正文 SHA-256，",
        "其余按五词片段 Jaccard（>=0.5 可能相似，<0.1 低文本重合，中间待定）。", "",
        "## 按邮件数口径（优先级判定）", "",
        "| 类别 | 邮件数 | 占比 |", "| --- | ---: | ---: |",
    ]
    total = len(rows)
    for key, label in (
        ("exact_body_exists", "存在完全相同正文"),
        ("possible_similar_found_no_exact", "无完全相同但发现可能相似"),
        ("none_found_by_this_recall", "未发现相似"),
    ):
        count = doc_classes[key]
        report.append(f"| {label} | {count:,} | {count / total:.2%} |")
    report += [
        "", "## 按邮件对口径", "",
        "| 配对来源 | 总对数 | 正文完全相同 | 可能相似 | 低文本重合 | 待定 |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, stat in pair_stats.items():
        c = stat["classes"]
        report.append(
            f"| {name} | {stat['pair_count']:,} | {c['exact_body']:,} | "
            f"{c['possible_similar']:,} | {c['low_text_overlap']:,} | {c['uncertain']:,} |"
        )
    report += [
        "", f"全量 SHA-256 重复组内的完全相同邮件对共 {exact_pairs_total:,} 对（不受候选召回限制）。",
        f"少于 5 词（无五词片段）的邮件 {short_docs:,} 封，少于 20 词的 {under_20_docs:,} 封；完全相同仍可通过 SHA-256 判定。",
        "", "候选召回不穷尽全部配对；随机对仅作基线。二者不可相加，也不能外推为全库比例。",
        "“未发现相似”不是语义无关证明。完整数据见 similarity-stats.json。",
    ]
    (OUT / "similarity-report.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "method"}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
