"""Read-your-writes across a Vault Enterprise cluster: the replication states (X-Vault-Index) Vault
returns and requires, and how a VaultClient forwards requests to the active node."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from hkdfguard.integration.hashicorpvault._options import VaultRequest, VaultRequestCallback, VaultResponseCallback

INDEX_HEADER: Final = "X-Vault-Index"


class ReplicationForwardingMode(Enum):
    """Whether a performance standby forwards requests to the active node (Vault Enterprise)."""

    NONE = "none"
    """No forwarding header."""

    ALWAYS = "always"
    """X-Vault-Forward: a performance standby forwards every request to the active node; see
    https://developer.hashicorp.com/vault/docs/enterprise/consistency#unconditional-forwarding-performance-standbys-only."""

    INCONSISTENT = "inconsistent"
    """X-Vault-Inconsistent: a performance standby forwards a request to the active node only when it
    hasn't caught up with the replication state it requires - see
    :func:`VaultReplication.require_replication_states`."""


@dataclass(frozen=True, slots=True)
class VaultReplicationState:
    """A cluster's replication state from an X-Vault-Index header: the sdk's WALState."""

    cluster: str
    """The cluster's id."""
    local_index: int
    """The local write-ahead log index, unsigned."""
    replicated_index: int
    """The replicated write-ahead log index, unsigned."""

    @staticmethod
    def parse(raw: str, hmac_key: bytes | None = None) -> VaultReplicationState:
        """The state ``raw`` holds: base64 of v1:cluster-id:local-index:replicated-index:hmac. With an
        ``hmac_key``, the hmac (hex HMAC-SHA256 of everything before it) is verified as well.

        :raises ValueError: ``raw`` isn't a replication state, or its HMAC doesn't match
        """
        if not isinstance(raw, str):
            raise TypeError("raw must be a str.")
        try:
            decoded = base64.b64decode(raw, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError) as error:
            raise ValueError(f"Could not decode the replication state: {error}") from error

        state, colon, hmac_text = decoded.rpartition(":")
        if not colon:
            raise ValueError("Invalid replication state header format.")
        try:
            state_hmac = bytes.fromhex(hmac_text)
        except ValueError as error:
            raise ValueError(f"Invalid replication state header HMAC '{hmac_text}'.") from error
        if hmac_key and not hmac.compare_digest(hmac.new(hmac_key, state.encode("utf-8"), hashlib.sha256).digest(), state_hmac):
            raise ValueError("Invalid replication state header HMAC (mismatch).")

        pieces = state.split(":")
        if len(pieces) != 4 or pieces[0] != "v1" or not pieces[1]:
            raise ValueError("Invalid replication state header format.")
        return VaultReplicationState(pieces[1], _parse_index(pieces[2], "local"), _parse_index(pieces[3], "replicated"))


class VaultReplication:
    """Read-your-writes across a Vault Enterprise cluster by hand - what
    :attr:`VaultClientOptions.enforce_read_your_writes_consistency` does for every request: record
    the state a write's response carries, then require it of a later read; see
    https://developer.hashicorp.com/vault/docs/enterprise/consistency#conditional-forwarding-performance-standbys-only."""

    __slots__ = ()

    @staticmethod
    def record_replication_state(record: Callable[[str | None], object]) -> VaultResponseCallback:
        """A response callback handing ``record`` the response's replication state (X-Vault-Index),
        or ``None`` if it has none."""
        if record is None:
            raise TypeError("record must not be None.")

        def callback(_request: VaultRequest, _status: int, headers: object) -> None:
            record(_header(headers, INDEX_HEADER))

        return callback

    @staticmethod
    def require_replication_states(*states: str) -> VaultRequestCallback:
        """A request callback requiring ``states`` (X-Vault-Index) of the node that answers - states
        recorded with :meth:`record_replication_state`."""
        copied = tuple(states)

        def callback(request: VaultRequest) -> None:
            for state in copied:
                request.add_header(INDEX_HEADER, state)

        return callback

    @staticmethod
    def merge_replication_states(old_states: Sequence[str], new_state: str) -> list[str]:
        """The states to require after seeing ``new_state``, given those required so far: each old
        state newer than ``new_state`` kept, ``new_state`` kept if newer than any - both when neither
        is newer - sorted, with no duplicates. Just ``new_state`` when there are no old states or more
        than two, or when any can't be compared with it (unparsable, or another cluster's)."""
        if old_states is None or new_state is None:
            raise TypeError("old_states and new_state must not be None.")
        if not old_states or len(old_states) > 2:
            return [new_state]

        merged: list[str] = []
        for old in old_states:
            try:
                comparison = compare_replication_states(old, new_state)
            except ValueError:
                return [new_state]
            if comparison == 1:
                merged.append(old)
            elif comparison == -1:
                merged.append(new_state)
            else:
                merged += (old, new_state)

        # strutil.RemoveDuplicates: trimmed, empties dropped, distinct, sorted.
        return sorted({state.strip() for state in merged if state.strip()})


def compare_replication_states(s1: str, s2: str) -> int:
    """1 if ``s1`` is newer than ``s2`` or the same, -1 if older, 0 if neither is.

    :raises ValueError: either isn't a replication state, or they're different clusters'
    """
    r1 = VaultReplicationState.parse(s1)
    r2 = VaultReplicationState.parse(s2)
    if r1.cluster != r2.cluster:
        raise ValueError("Can't compare replication states from different clusters.")
    local = (r1.local_index > r2.local_index) - (r1.local_index < r2.local_index)
    replicated = (r1.replicated_index > r2.replicated_index) - (r1.replicated_index < r2.replicated_index)
    if local >= 0 and replicated >= 0:
        return 1
    if local <= 0 and replicated <= 0:
        return -1
    return 0


class ReplicationStateCache:
    """The replication states a client has seen, for
    :attr:`VaultClientOptions.enforce_read_your_writes_consistency`: at most two, as
    :meth:`VaultReplication.merge_replication_states` keeps them."""

    __slots__ = ("_lock", "_states")

    def __init__(self, states: Sequence[str] = ()) -> None:
        self._states: tuple[str, ...] = tuple(states)
        self._lock = threading.Lock()

    def record(self, headers: object) -> None:
        """Merges the state ``headers`` carry, if any, into those seen. A value that isn't a
        replication state is dropped: it would be sent back with every later request."""
        state = _header(headers, INDEX_HEADER)
        if not state:
            return
        try:
            # Strict base64 of v1:cluster:local:replicated:hmac - no whitespace, so no folded line or
            # stray header text is ever kept and echoed.
            VaultReplicationState.parse(state)
        except ValueError:
            return
        with self._lock:
            self._states = tuple(VaultReplication.merge_replication_states(self._states, state))

    def snapshot(self) -> tuple[str, ...]:
        """The states seen so far, to require of the next request."""
        with self._lock:
            return self._states

    def copy(self) -> ReplicationStateCache:
        return ReplicationStateCache(self.snapshot())


def _header(headers: object, name: str) -> str | None:
    # The first value of name in an http.client.HTTPMessage (or any mapping of headers).
    get = getattr(headers, "get", None)
    if get is None:
        return None
    value = get(name)
    return value if isinstance(value, str) else None


def _parse_index(digits: str, which: str) -> int:
    # A ulong: ASCII digits only, as .NET's NumberStyles.None reads them.
    if not digits or not digits.isascii() or not digits.isdigit() or int(digits) >= 1 << 64:
        raise ValueError(f"Invalid {which} index in replication state header.")
    return int(digits)
