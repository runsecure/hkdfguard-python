"""Replication states: parsing X-Vault-Index, merging them, and carrying one from a response to a request."""

from __future__ import annotations

import base64
import hashlib
import hmac

import pytest
from hkdfguard.integration.hashicorpvault import VaultReplication, VaultReplicationState, VaultRequestOptions
from hkdfguard.integration.hashicorpvault._replication import ReplicationStateCache, compare_replication_states
from vault_client_test_support import FakeVault, MakeClient


def state(cluster: str, local: int, replicated: int, key: bytes | None = None) -> str:
    text = f"v1:{cluster}:{local}:{replicated}"
    mac = hmac.new(key, text.encode(), hashlib.sha256).hexdigest() if key else "00ff"
    return base64.b64encode(f"{text}:{mac}".encode()).decode()


def test_parse_reads_indexes_as_unsigned() -> None:
    parsed = VaultReplicationState.parse(state("c1", 2**64 - 1, 7))
    assert parsed == VaultReplicationState("c1", 2**64 - 1, 7)


def test_parse_verifies_the_hmac_given_a_key() -> None:
    raw = state("c1", 1, 2, b"key")
    assert VaultReplicationState.parse(raw, b"key").local_index == 1
    with pytest.raises(ValueError, match="mismatch"):
        VaultReplicationState.parse(raw, b"other")


@pytest.mark.parametrize("raw", ["not base64!", base64.b64encode(b"nocolons").decode(), base64.b64encode(b"v1:c:1:2:zz").decode(),
                                 base64.b64encode(b"v2:c:1:2:00").decode(), base64.b64encode(b"v1::1:2:00").decode(),
                                 base64.b64encode(b"v1:c:-1:2:00").decode(), base64.b64encode(f"v1:c:{2**64}:2:00".encode()).decode()])
def test_parse_refuses_what_isnt_a_state(raw: str) -> None:
    with pytest.raises(ValueError):
        VaultReplicationState.parse(raw)


def test_compare_and_merge_keep_the_newest_states() -> None:
    old, new, mixed = state("c", 1, 1), state("c", 2, 2), state("c", 3, 0)
    assert compare_replication_states(new, old) == 1
    assert compare_replication_states(old, new) == -1
    assert compare_replication_states(mixed, new) == 0
    with pytest.raises(ValueError, match="different clusters"):
        compare_replication_states(old, state("d", 1, 1))
    assert VaultReplication.merge_replication_states([], new) == [new]
    assert VaultReplication.merge_replication_states([old], new) == [new]
    assert VaultReplication.merge_replication_states([new], old) == [new]
    assert VaultReplication.merge_replication_states([mixed], new) == sorted([mixed, new])
    assert VaultReplication.merge_replication_states(["garbage"], new) == [new]
    assert VaultReplication.merge_replication_states([old, old, old], new) == [new]


def test_record_and_require_carry_a_state_from_a_response_to_a_request(vault: FakeVault, make_client: MakeClient) -> None:
    raw = state("c", 5, 5)
    vault.then(200, "{}", X_Vault_Index=raw)
    recorded: list[str | None] = []
    client = make_client()
    client.write("a", {}, VaultRequestOptions(response_callbacks=[VaultReplication.record_replication_state(recorded.append)]))
    client.read("b", VaultRequestOptions(request_callbacks=[VaultReplication.require_replication_states(*[s for s in recorded if s])]))
    client.read("c", VaultRequestOptions(response_callbacks=[VaultReplication.record_replication_state(recorded.append)]))
    assert recorded == [raw, None]
    assert vault.requests[1].header("X-Vault-Index") == raw


def test_the_cache_keeps_only_what_is_a_replication_state() -> None:
    # Whatever it keeps goes back to Vault with every later request: a folded line, stray text or a
    # value that isn't base64 of v1:cluster:local:replicated:hmac is dropped instead.
    cache = ReplicationStateCache()
    for bad in ("not base64!", state("c", 1, 1) + "\r\n X-Injected: 1", base64.b64encode(b"v2:c:1:1:00").decode(), "a" * 40):
        cache.record({"X-Vault-Index": bad})
        assert cache.snapshot() == ()
    cache.record({"X-Vault-Index": state("c", 1, 1)})
    assert cache.snapshot() == (state("c", 1, 1),)


def test_the_cache_ignores_responses_without_a_state_and_copies_are_independent() -> None:
    cache = ReplicationStateCache()
    cache.record({})
    assert cache.snapshot() == ()
    cache.record({"X-Vault-Index": state("c", 1, 1)})
    copy = cache.copy()
    copy.record({"X-Vault-Index": state("c", 2, 2)})
    assert cache.snapshot() == (state("c", 1, 1),)
    assert copy.snapshot() == (state("c", 2, 2),)
