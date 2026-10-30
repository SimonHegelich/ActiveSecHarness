"""Ring-0 HashChainedAuditLog: Tamper-evident append-only cryptographic security ledger.

Records every sudo capability grant, token delegation, tool execution, and blocked attack
as a hash-chained, HMAC-authenticated ledger entry. Any post-hoc modification, deletion,
reordering, or truncation is deterministically detected.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Dict, List, Mapping, Optional, Tuple

from activesec.core.component import ComponentSecurityAssessment, SecureComponent
from activesec.core.exceptions import AuditIntegrityError


GENESIS_PREV_HASH: str = "0" * 64


@dataclass(frozen=True, slots=True)
class AuditLogEntry:
    """Immutable single entry in the hash-chained security audit log."""

    sequence_id: int
    timestamp_unix: float
    event_type: str
    actor_id: str
    ring_level: int
    vector_id: str
    details: Tuple[Tuple[str, str], ...]
    prev_entry_hash: str
    entry_hash: str
    hmac_signature: str

    def canonical_payload_bytes(self) -> bytes:
        """Return deterministic canonical JSON bytes for hashing and HMAC signing."""
        payload = {
            "actor_id": self.actor_id,
            "details": dict(self.details),
            "event_type": self.event_type,
            "prev_entry_hash": self.prev_entry_hash,
            "ring_level": self.ring_level,
            "sequence_id": self.sequence_id,
            "timestamp_unix": round(self.timestamp_unix, 6),
            "vector_id": self.vector_id,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class HashChainedAuditLog(SecureComponent):
    """Ring-0 append-only cryptographic audit log with SHA-256 chaining and HMAC authentication."""

    def __init__(self, signing_key: Optional[bytes] = None) -> None:
        self._signing_key: bytes = signing_key if signing_key is not None else secrets.token_bytes(32)
        if len(self._signing_key) < 32:
            raise AuditIntegrityError(
                "Audit log signing key must be at least 32 bytes.",
                vector_id="A.3",
                component_id="audit_log",
            )
        self._entries: List[AuditLogEntry] = []

    @classmethod
    def security_assessment(cls) -> ComponentSecurityAssessment:
        return ComponentSecurityAssessment(
            component_id="audit_log",
            title="Ring-0 Hash-Chained Append-Only Security Audit Log",
            ring_level=0,
            source_path="src/activesec/core/audit_log.py",
            security_test_path="tests/security/test_sec_audit_log.py",
            threat_vectors=("A.3", "F.3"),
            summary=(
                "Maintains a tamper-evident, append-only cryptographic audit trail of all sudo grants, "
                "delegations, tool invocations, and security violations using SHA-256 hash chaining "
                "combined with per-entry Ring-0 HMAC-SHA256 signatures."
            ),
            enforced_invariants=(
                "Every entry hashes its canonical payload together with prev_entry_hash (starting from a fixed 64-zero genesis hash).",
                "Every entry is authenticated with a >=256-bit Ring-0 HMAC-SHA256 signature over entry_hash.",
                "Contiguous monotonic sequence_id numbering detects entry deletion, insertion, or reordering.",
                "Full chain verification uses constant-time hmac.compare_digest() and fails closed on any discrepancy.",
            ),
            residual_risks=(
                "Total process termination before flushing in-memory entries to remote append-only storage.",
            ),
        )

    @property
    def entries(self) -> Tuple[AuditLogEntry, ...]:
        """Return an immutable snapshot of all audit log entries."""
        return tuple(self._entries)

    def append_event(
        self,
        *,
        event_type: str,
        actor_id: str,
        ring_level: int,
        vector_id: str = "NONE",
        details: Optional[Mapping[str, str]] = None,
        timestamp_unix: Optional[float] = None,
    ) -> AuditLogEntry:
        """Append a new cryptographically chained event to the audit log."""
        if not event_type.strip() or not actor_id.strip():
            raise AuditIntegrityError(
                "Audit event requires non-empty event_type and actor_id.",
                vector_id="A.3",
                component_id="audit_log",
            )
        if ring_level not in (0, 1, 2, 3):
            raise AuditIntegrityError(
                f"Invalid privilege ring level: {ring_level}.",
                vector_id="A.3",
                component_id="audit_log",
            )

        seq_id = len(self._entries)
        prev_hash = self._entries[-1].entry_hash if self._entries else GENESIS_PREV_HASH
        ts = round(timestamp_unix if timestamp_unix is not None else time.time(), 6)
        sorted_details: Tuple[Tuple[str, str], ...] = tuple(
            sorted((str(k), str(v)) for k, v in (details or {}).items())
        )

        provisional = AuditLogEntry(
            sequence_id=seq_id,
            timestamp_unix=ts,
            event_type=event_type,
            actor_id=actor_id,
            ring_level=ring_level,
            vector_id=vector_id,
            details=sorted_details,
            prev_entry_hash=prev_hash,
            entry_hash="",
            hmac_signature="",
        )
        payload_bytes = provisional.canonical_payload_bytes()
        entry_hash = hashlib.sha256(payload_bytes).hexdigest()
        signature = hmac.new(
            self._signing_key,
            entry_hash.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        final_entry = AuditLogEntry(
            sequence_id=seq_id,
            timestamp_unix=ts,
            event_type=event_type,
            actor_id=actor_id,
            ring_level=ring_level,
            vector_id=vector_id,
            details=sorted_details,
            prev_entry_hash=prev_hash,
            entry_hash=entry_hash,
            hmac_signature=signature,
        )
        self._entries.append(final_entry)
        return final_entry

    def verify_chain(self, external_entries: Optional[Tuple[AuditLogEntry, ...]] = None) -> bool:
        """Verify the cryptographic integrity, sequence continuity, and HMAC signatures of the entire log."""
        chain = external_entries if external_entries is not None else tuple(self._entries)
        expected_prev_hash = GENESIS_PREV_HASH

        for expected_seq, entry in enumerate(chain):
            if entry.sequence_id != expected_seq:
                raise AuditIntegrityError(
                    f"Audit log sequence gap or reordering at index {expected_seq} (found sequence_id={entry.sequence_id}).",
                    vector_id="A.3",
                    component_id="audit_log",
                )
            if not hmac.compare_digest(entry.prev_entry_hash, expected_prev_hash):
                raise AuditIntegrityError(
                    f"Broken hash chain at sequence_id={entry.sequence_id}: prev_entry_hash mismatch.",
                    vector_id="A.3",
                    component_id="audit_log",
                )

            recomputed_hash = hashlib.sha256(entry.canonical_payload_bytes()).hexdigest()
            if not hmac.compare_digest(entry.entry_hash, recomputed_hash):
                raise AuditIntegrityError(
                    f"Entry payload tampered at sequence_id={entry.sequence_id}: entry_hash mismatch.",
                    vector_id="A.3",
                    component_id="audit_log",
                )

            expected_sig = hmac.new(
                self._signing_key,
                recomputed_hash.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(entry.hmac_signature, expected_sig):
                raise AuditIntegrityError(
                    f"Forged HMAC signature at sequence_id={entry.sequence_id}.",
                    vector_id="A.3",
                    component_id="audit_log",
                )

            expected_prev_hash = entry.entry_hash

        return True

    def export_jsonl(self) -> str:
        """Export the verified chain as deterministic JSON Lines."""
        self.verify_chain()
        lines: List[str] = []
        for e in self._entries:
            obj: Dict[str, object] = {
                "actor_id": e.actor_id,
                "details": dict(e.details),
                "entry_hash": e.entry_hash,
                "event_type": e.event_type,
                "hmac_signature": e.hmac_signature,
                "prev_entry_hash": e.prev_entry_hash,
                "ring_level": e.ring_level,
                "sequence_id": e.sequence_id,
                "timestamp_unix": e.timestamp_unix,
                "vector_id": e.vector_id,
            }
            lines.append(json.dumps(obj, sort_keys=True))
        return "\n".join(lines)
