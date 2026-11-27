"""Content-Addressed Binary SHA-256 Merkle Tree for `O(changed)` Incremental Re-Ingestion."""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class MerkleDeltaResult:
    document_id: str
    previous_root_hash: str | None
    new_root_hash: str
    changed_indices: tuple[int, ...]
    unchanged_count: int


def compute_merkle_root(leaf_hashes: list[str]) -> str:
    """Compute canonical binary SHA-256 Merkle root (`0x00` leaf domain, `0x01` internal node)."""
    if not leaf_hashes:
        return _sha256_hex(b"EMPTY_MERKLE_TREE")
    level = [_sha256_hex(b"\x00" + h.encode("ascii")) for h in leaf_hashes]
    while len(level) > 1:
        next_level: list[str] = []
        for idx in range(0, len(level), 2):
            left = level[idx]
            right = level[idx + 1] if (idx + 1) < len(level) else left
            next_level.append(_sha256_hex(b"\x01" + (left + right).encode("ascii")))
        level = next_level
    return level[0]


class MerkleSyncTracker:
    """Tracks per-document leaf SHA-256 hashes so minor edits skip 99% of redundant embeddings."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._doc_trees: dict[str, tuple[str, dict[str, str]]] = {}

    def compute_and_commit_delta(
        self,
        *,
        tenant_id: str,
        document_id: str,
        chunk_ids_and_contents: list[tuple[str, str]],
    ) -> MerkleDeltaResult:
        doc_key = f"{tenant_id}:{document_id}"
        ordered_leaf_hashes: list[str] = []
        new_leaf_map: dict[str, str] = {}
        for cid, content in chunk_ids_and_contents:
            lh = _sha256_hex(f"{cid}|{content}".encode())
            ordered_leaf_hashes.append(lh)
            new_leaf_map[cid] = lh

        new_root = compute_merkle_root(ordered_leaf_hashes)

        with self._lock:
            prev = self._doc_trees.get(doc_key)
            if prev is None:
                self._doc_trees[doc_key] = (new_root, new_leaf_map)
                return MerkleDeltaResult(
                    document_id=document_id,
                    previous_root_hash=None,
                    new_root_hash=new_root,
                    changed_indices=tuple(range(len(chunk_ids_and_contents))),
                    unchanged_count=0,
                )

            prev_root, prev_map = prev
            if prev_root == new_root and len(prev_map) == len(new_leaf_map):
                return MerkleDeltaResult(
                    document_id=document_id,
                    previous_root_hash=prev_root,
                    new_root_hash=new_root,
                    changed_indices=(),
                    unchanged_count=len(chunk_ids_and_contents),
                )

            changed: list[int] = []
            unchanged = 0
            for idx, (cid, _) in enumerate(chunk_ids_and_contents):
                if prev_map.get(cid) != new_leaf_map[cid]:
                    changed.append(idx)
                else:
                    unchanged += 1

            self._doc_trees[doc_key] = (new_root, new_leaf_map)
            return MerkleDeltaResult(
                document_id=document_id,
                previous_root_hash=prev_root,
                new_root_hash=new_root,
                changed_indices=tuple(changed),
                unchanged_count=unchanged,
            )
