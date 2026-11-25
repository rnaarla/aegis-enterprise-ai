"""Property-Based SSE Fuzzing (500 random partitions) & Optimal DSA Unit Verification."""

from __future__ import annotations

import random

import pytest

from aegis_core.dsa import BoundedLRUTTLCache, MinHeapTTLIndex
from aegis_core.settings import AegisServiceSettings
from pii_unmasking_proxy.sse_stream import StreamingSurrogateRehydrator, mask_text_entities
from pii_unmasking_proxy.vault import EnvelopeEncryptedPIIVault
from shadow_replay_harness.specifications import (
    BlockedSAPVendorSnapshotSpec,
    ExceedsExecutivePOGateSpec,
    JuniorAnalystRequesterSpec,
    ShadowEvaluationContext,
)

pytestmark = pytest.mark.unit


def test_dsa_bounded_lru_ttl_cache_invariants() -> None:
    now = 1_000.0
    cache: BoundedLRUTTLCache[str, int] = BoundedLRUTTLCache(
        max_size=3,
        default_ttl_seconds=10.0,
        clock=lambda: now,
    )

    with pytest.raises(ValueError, match="max_size"):
        BoundedLRUTTLCache(max_size=0)
    with pytest.raises(ValueError, match="default_ttl_seconds"):
        BoundedLRUTTLCache(default_ttl_seconds=0.0)

    cache.put("a", 1)
    cache.put("b", 2)
    cache.put("c", 3)
    # Touch 'a' so 'b' becomes LRU victim
    assert cache.get("a") == 1
    cache.put("d", 4)
    assert len(cache) == 3
    assert cache.get("b") is None
    assert cache.get("a") == 1

    # Updating existing key preserves max_size
    cache.put("a", 99)
    assert cache.get("a") == 99

    # Zero/negative TTL deletes immediately
    cache.put("a", 0, ttl_seconds=0.0)
    assert cache.get("a") is None

    # Advance monotonic clock past TTL -> lazy O(1) eviction
    now = 1_025.0
    assert cache.get("c") is None
    assert cache.get("d") is None
    assert len(cache) == 0


def test_dsa_min_heap_ttl_tie_breaking_and_tombstone_compaction() -> None:
    heap: MinHeapTTLIndex[str] = MinHeapTTLIndex()
    # Push 100 items with identical expiration timestamp (tests monotonic seq tie-breaker)
    for idx in range(100):
        heap.push(f"k-{idx}", 500.0)
    # Discard 85 items to trigger 4x tombstone compaction on next pop_expired
    for idx in range(85):
        heap.discard(f"k-{idx}")
    assert len(heap) == 15

    none_yet = heap.pop_expired(499.9)
    assert none_yet == []

    expired = heap.pop_expired(500.0)
    assert sorted(expired) == sorted(f"k-{idx}" for idx in range(85, 100))
    assert len(heap) == 0


def test_property_fuzz_500_random_sse_chunk_splits_preserve_exact_identity() -> None:
    """Property test: $\\forall$ random chunkings $P$, `rehydrate(P(mask(text))) == text`."""
    vault = EnvelopeEncryptedPIIVault(max_sessions=8)
    session_id = "fuzz-session-001"

    # Rich adversarial document including cataphoric honorific ("Ms. Vance" BEFORE "Elena Vance"),
    # math inequalities `< 50000`, unknown angle brackets `<TAG>`, SSN, Visa card, IBAN, & email!
    original_text = (
        "Alert: If deal_size < 50000 or spread < 2.5, notify Ms. Vance immediately! "
        "Authorized signatory Elena Vance (SSN 123-45-6789, corp card 4532015112830366, "
        "email elena.vance@meridian.fin, wire US64SVBK000098124401) approved <TIER_A> settlement."
    )

    masked_text, tags = mask_text_entities(
        original_text,
        lambda etype, val: vault.mask_entity(
            session_id=session_id, entity_type=etype, raw_value=val
        ),
    )
    assert "123-45-6789" not in masked_text
    assert "4532015112830366" not in masked_text
    assert "Elena Vance" not in masked_text
    # Cataphoric co-reference resolved both "Ms. Vance" and "Elena Vance" to `<PERSON_001>`!
    assert masked_text.count("<PERSON_001>") == 2
    assert len(tags) >= 5

    rng = random.Random(20261125)  # noqa: S311
    for trial in range(500):
        rehydrator = StreamingSurrogateRehydrator(
            lambda tag: vault.unmask_tag(session_id=session_id, surrogate_tag=tag)
        )
        cursor = 0
        pieces: list[str] = []
        while cursor < len(masked_text):
            step = rng.randint(1, 17)
            chunk = masked_text[cursor : cursor + step]
            cursor += step
            pieces.append(rehydrator.feed(chunk))
            if trial % 11 == 0:
                pieces.append(rehydrator.feed(""))
        pieces.append(rehydrator.flush())
        reconstructed = "".join(pieces)
        # Note: both "Ms. Vance" and "Elena Vance" unmask to canonical "Elena Vance"
        expected = original_text.replace("Ms. Vance", "Elena Vance")
        assert reconstructed == expected, f"Fuzz failure on trial {trial}"


def test_ooad_specification_boolean_combinators_and_settings() -> None:
    ctx = ShadowEvaluationContext(
        system_prompt="Enforce 50,000 USD gate and MNPI clearance",
        requester_role="junior_analyst",
        user_message="Request PO",
        snapshot_at_t0={"vendor_blocked": False},
        parsed_amount_usd=75_000.0,
    )
    spec_or = BlockedSAPVendorSnapshotSpec() | ExceedsExecutivePOGateSpec(50_000.0)
    spec_and_not = JuniorAnalystRequesterSpec() & ~BlockedSAPVendorSnapshotSpec()
    assert spec_or.is_satisfied_by(ctx) is True
    assert spec_and_not.is_satisfied_by(ctx) is True

    settings = AegisServiceSettings()
    assert settings.max_token_ttl_seconds == 300
