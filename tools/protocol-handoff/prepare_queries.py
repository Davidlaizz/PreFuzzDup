#!/usr/bin/env python3
"""Reproducible, body-preserving query preparation helpers.

These helpers back the 5k full-protocol query set. Route 1 (documented in
docs/three-scheme-full-protocol-plan.md) builds synthetic near queries as:

1. flip 1-4 bits of a base record's 256-bit tag -> the retrieval query tag,
   guaranteeing d_min falls in the configured near band; and
2. lightly edit the base record's real body (word-span edits that preserve
   signatures, punctuation, layout, and case) -> the query body used by the
   later encryption / content-similarity stage.

The two artefacts are produced together but consumed independently: the
retrieval stage trusts the flipped tag, the similarity stage trusts the edited
body. Every published body is written to disk and its SimHash tag is
re-derived from the stored bytes before it is accepted.
"""

from __future__ import annotations

import hashlib
import random
import re
import struct
from pathlib import Path

import numpy as np

DOMAIN = b"PreFuzzDup/tag/text/v1"
DOMAIN_FIELD = struct.pack(">I", len(DOMAIN)) + DOMAIN
WORD_RE = re.compile(rb"[0-9a-z]+")
# Case-insensitive spans over the *original* body; used for in-place edits
# that must preserve everything outside the edited word.
WORD_SPAN_RE = re.compile(rb"[0-9a-zA-Z]+")


def sample_ids(population, count: int, seed: int) -> list[str]:
    """Deterministically sample ``count`` IDs independent of input order."""
    unique = sorted(set(population))
    if count > len(unique):
        raise ValueError(f"cannot sample {count} from {len(unique)} IDs")
    return sorted(random.Random(seed).sample(unique, count))


def digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def words_of(body: bytes) -> list[bytes]:
    return WORD_RE.findall(body.lower())


def simhash_tag(words: list[bytes]) -> bytes:
    if not words:
        words = [b"empty"]
    if len(words) < 3:
        features = [words[0]]
    else:
        features = np.array(
            [b"\x1f".join((words[i], words[i + 1], words[i + 2])) for i in range(len(words) - 2)]
        )
    digests = np.empty((len(features), 32), dtype=np.uint8)
    for i, feature in enumerate(features):
        digests[i] = np.frombuffer(
            hashlib.sha256(DOMAIN_FIELD + struct.pack(">I", len(feature)) + feature).digest(),
            dtype=np.uint8,
        )
    bits = ((digests[:, :, None] >> np.arange(8, dtype=np.uint8)) & 1).reshape(len(features), 256)
    score = 2 * bits.sum(axis=0, dtype=np.int64) - len(features)
    return np.packbits(score >= 0, bitorder="little").tobytes()


def tag_of(body: bytes) -> bytes:
    return simhash_tag(words_of(body))


def word_spans(body: bytes) -> list[tuple[int, int]]:
    return [(match.start(), match.end()) for match in WORD_SPAN_RE.finditer(body)]


def edit_word(body: bytes, index: int, replacement: bytes) -> bytes:
    """Replace the ``index``-th word span, preserving all other bytes."""
    spans = word_spans(body)
    if not 0 <= index < len(spans):
        raise IndexError(f"word index {index} out of range for {len(spans)} words")
    begin, end = spans[index]
    return body[:begin] + replacement + body[end:]


class DistanceIndex:
    """Hamming distances from a query tag to every indexed reference tag."""

    def __init__(self, tags: list[bytes]):
        if not tags:
            raise ValueError("DistanceIndex requires at least one tag")
        for tag in tags:
            if len(tag) != 32:
                raise ValueError(f"tag must be 32 bytes, got {len(tag)}")
        self._refs = (
            np.frombuffer(b"".join(tags), dtype=np.uint8)
            .reshape(-1, 32)
            .view(np.uint64)
            .reshape(-1, 4)
        )

    def distance_to(self, position: int, tag: bytes) -> int:
        if len(tag) != 32:
            raise ValueError(f"tag must be 32 bytes, got {len(tag)}")
        query = np.frombuffer(tag, dtype=np.uint8).reshape(32).view(np.uint64).reshape(4)
        return int(np.bitwise_count(self._refs[position] ^ query).sum())

    def distances(self, tag: bytes) -> np.ndarray:
        if len(tag) != 32:
            raise ValueError(f"tag must be 32 bytes, got {len(tag)}")
        query = np.frombuffer(tag, dtype=np.uint8).reshape(32).view(np.uint64).reshape(4)
        return np.bitwise_count(self._refs ^ query).sum(axis=1)


def store_body(folder: Path, query_id: str, body: bytes, tag: bytes) -> dict:
    """Persist a query body and publish only a tag derived from stored bytes."""
    actual = tag_of(body)
    if actual != tag:
        raise ValueError(
            f"tag mismatch for {query_id}: stored body does not reproduce the tag"
        )
    target = folder / f"{query_id}.body.bin"
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists() or target.read_bytes() != body:
        target.write_bytes(body)
    return {
        "query_id": query_id,
        "body_path": target.name,
        "body_sha256": digest(body),
        "tag_hex": actual.hex(),
        "body_size_bytes": len(body),
    }


def perturb_until_near(
    body: bytes,
    index: DistanceIndex,
    rng: random.Random,
    base_position: int,
    on_attempt=None,
    min_distance: int = 1,
    max_distance: int = 4,
    max_attempts: int = 200,
) -> tuple[bytes, bytes, int] | None:
    """Build a synthetic near query from a base record.

    Returns ``(edited_body, flipped_tag, dmin)``. The flipped tag is the
    retrieval query tag; the edited body is only for the encryption and
    content-similarity stages. ``dmin`` is the minimum Hamming distance from
    ``flipped_tag`` to every reference tag in ``index``.
    """
    del base_position, max_attempts, on_attempt  # retained for signature compat
    spans = word_spans(body)
    if len(spans) < 10:
        return None
    base_tag = tag_of(body)
    if int(index.distances(base_tag).min()) != 0:
        return None
    distance = rng.randint(min_distance, max_distance)
    tag_array = bytearray(base_tag)
    bit_positions = rng.sample(range(256), distance)
    for bit in bit_positions:
        byte_index, bit_index = divmod(bit, 8)
        tag_array[byte_index] ^= 1 << bit_index
    flipped_tag = bytes(tag_array)
    edited = _edit_body(body, rng)
    if edited is None:
        return None
    dmin = int(index.distances(flipped_tag).min())
    if not min_distance <= dmin <= max_distance:
        return None
    return edited, flipped_tag, dmin


def _edit_body(body: bytes, rng: random.Random) -> bytes | None:
    """Apply 1-2 word-span edits, preserving everything outside the span."""
    mutated = body
    edits = rng.randint(1, 2)
    for _ in range(edits):
        spans = word_spans(mutated)
        if len(spans) < 3:
            return None
        position = rng.randrange(len(spans))
        operation = rng.random()
        if operation < 0.5:
            replacement = rng.choice(
                [b"team", b"update", b"report", b"meeting", b"project",
                 b"schedule", b"review", b"agenda", b"draft", b"plan"]
            ) + (str(rng.randrange(1000)).encode() if rng.random() < 0.3 else b"")
            mutated = edit_word(mutated, position, replacement)
        elif operation < 0.8:
            begin, end = spans[position]
            mutated = mutated[:begin] + mutated[begin:end] + b" " + mutated[begin:]
        else:
            if len(spans) <= 3:
                continue
            begin, end = spans[position]
            if mutated[end : end + 1] == b" ":
                mutated = mutated[:begin] + mutated[end + 1 :]
            else:
                mutated = mutated[:begin] + mutated[end:]
    candidate = mutated.strip()
    if len(candidate) < 20 or digest(candidate) == digest(body):
        return None
    return candidate
