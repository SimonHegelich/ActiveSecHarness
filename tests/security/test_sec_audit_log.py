"""Adversarial security tests for HashChainedAuditLog (src/activesec/core/audit_log.py).

Verifies detection of payload tampering, entry deletion/truncation, sequence reordering,
and unauthenticated hash chain recomputation without the Ring-0 HMAC key.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from activesec.core.audit_log import HashChainedAuditLog
from activesec.core.exceptions import AuditIntegrityError


@pytest.mark.security
def test_sec_audit_log_detects_payload_tampering() -> None:
    """[Vector A.3: Harness Tampering] Detects modification of any field in a historical audit entry."""
    log = HashChainedAuditLog()
    log.append_event(event_type="SUDO_GRANT", actor_id="user", ring_level=1, details={"scope": "read"})
    log.append_event(event_type="TOOL_EXEC", actor_id="agent-1", ring_level=3, details={"cmd": "pytest"})
    assert log.verify_chain() is True

    entries = list(log.entries)
    # Attacker alters actor_id or details of entry 0
    entries[0] = replace(entries[0], details=(("scope", "full_root_shell"),))

    with pytest.raises(AuditIntegrityError) as exc_info:
        log.verify_chain(tuple(entries))
    assert exc_info.value.vector_id == "A.3"


@pytest.mark.security
def test_sec_audit_log_detects_entry_deletion_and_reordering() -> None:
    """[Vector A.3: Log Erasure] Detects deletion of middle/initial entries or sequence reordering."""
    log = HashChainedAuditLog()
    e0 = log.append_event(event_type="INIT", actor_id="kernel", ring_level=0)
    e1 = log.append_event(event_type="ALERT_BLOCKED", actor_id="agent-x", ring_level=3, vector_id="F.2")
    e2 = log.append_event(event_type="CLEANUP", actor_id="kernel", ring_level=0)

    # Attacker deletes the incriminating middle alert entry e1
    with pytest.raises(AuditIntegrityError):
        log.verify_chain((e0, e2))

    # Attacker swaps order of e1 and e2
    with pytest.raises(AuditIntegrityError):
        log.verify_chain((e0, e2, e1))


@pytest.mark.security
def test_sec_audit_log_blocks_hash_recomputation_without_hmac_key() -> None:
    """[Vector A.3: Cryptographic Forgery] Recomputing SHA-256 chain without Ring-0 HMAC key is rejected."""
    log = HashChainedAuditLog()
    e0 = log.append_event(event_type="SUDO_GRANT", actor_id="user", ring_level=1)

    # Attacker modifies event_type AND recomputes entry_hash, but lacks _signing_key
    forged_draft = replace(e0, event_type="FORGED_ROOT_GRANT")
    forged_hash = hashlib.sha256(forged_draft.canonical_payload_bytes()).hexdigest()
    forged_entry = replace(forged_draft, entry_hash=forged_hash)

    with pytest.raises(AuditIntegrityError) as exc_info:
        log.verify_chain((forged_entry,))
    assert "Forged HMAC signature" in str(exc_info.value)
