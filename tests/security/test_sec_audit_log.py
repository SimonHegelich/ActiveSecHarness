"""Adversarial security tests for HashChainedAuditLog (src/activesec/core/audit_log.py).

Verifies detection of payload tampering, entry deletion/truncation, sequence reordering,
unauthenticated hash chain recomputation without the Ring-0 HMAC key, deterministic
salted-HMAC secret redaction with correlation fingerprints, ANSI/Trojan-Source log
injection neutralization, split-horizon Tier-2 payload encryption, and 0o600 vault
file + symlink/capability/sandbox protection.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import time
from dataclasses import replace
from pathlib import Path

import pytest

from activesec.core.audit_log import HashChainedAuditLog
from activesec.core.capability_token import CapabilityCaveat, CapabilityEngine
from activesec.core.exceptions import (
    AuditIntegrityError,
    CapabilityViolationError,
    SandboxSecurityError,
)
from activesec.guards.sandbox_guard import SandboxGuard


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


@pytest.mark.security
def test_sec_audit_log_zero_secret_scrubbing_and_correlation_fingerprints(tmp_path: Path) -> None:
    """[Vector D.2: Secret Leakage in Logs] Scrubs passwords, API keys, PEM keys, Bearer tokens, and CLI flags with deterministic salted HMAC correlation."""
    log = HashChainedAuditLog()

    shared_password = "MyUltraSecretRootPass!2026"
    openai_key = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456"
    pem_key = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ==\n"
        "-----END OPENSSH PRIVATE KEY-----"
    )
    bearer_secret = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.supersecret"
    high_entropy_token = "K9#mP2$vL8@nQ5!xR7^wZ4_yB1*cF6"

    # Event 1 leaks the shared password via CLI --password flag, plus OpenAI and PEM keys
    e0 = log.append_event(
        event_type="TOOL_EXEC_BLOCKED",
        actor_id="agent-1",
        ring_level=3,
        vector_id="D.2",
        details={
            "cli_cmd": f"db_client --password={shared_password} --token={high_entropy_token}",
            "env_dump": f"OPENAI_API_KEY={openai_key}",
            "ssh_material": pem_key,
            "http_header": f"Authorization: Bearer {bearer_secret}",
        },
    )

    # Event 2 leaks the EXACT SAME shared_password via short -p flag and sensitive 'password' key
    e1 = log.append_event(
        event_type="AUTH_FAILURE",
        actor_id="agent-2",
        ring_level=3,
        vector_id="D.1",
        details={
            "short_cli": f"mysql -u admin -p {shared_password}",
            "password": shared_password,
        },
    )

    vault_file = tmp_path / "audit_vault" / "session.audit.jsonl"
    log.write_vault_file(vault_file)
    exported_jsonl = log.export_jsonl(include_cleartext_details=True)
    disk_content = vault_file.read_text(encoding="utf-8")

    # 1. Verify zero cleartext secrets in memory, JSONL export, or disk vault
    for raw_secret in (
        shared_password,
        openai_key,
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ==",
        bearer_secret,
        high_entropy_token,
    ):
        assert raw_secret not in str(e0.details)
        assert raw_secret not in str(e1.details)
        assert raw_secret not in exported_jsonl
        assert raw_secret not in disk_content

    # 2. Verify deterministic 10-char HMAC correlation fingerprint across events for the same secret
    expected_fp = log.compute_secret_fingerprint(shared_password)
    assert len(expected_fp) == 10
    e0_map = dict(e0.details)
    e1_map = dict(e1.details)

    assert f"<REDACTED:SECRET:{expected_fp}>" in e0_map["cli_cmd"]
    assert f"<REDACTED:SECRET:{expected_fp}>" in e1_map["short_cli"]
    assert e1_map["password"] == f"<REDACTED:SECRET:{expected_fp}>"
    assert "<REDACTED:OPENAI_KEY:" in e0_map["env_dump"]
    assert "<REDACTED:PEM_PRIVATE_KEY:" in e0_map["ssh_material"]
    assert f"<REDACTED:SECRET:{log.compute_secret_fingerprint(bearer_secret)}>" in e0_map["http_header"]
    assert f"<REDACTED:SECRET:{log.compute_secret_fingerprint(high_entropy_token)}>" in e0_map["cli_cmd"]


@pytest.mark.security
def test_sec_audit_log_neutralizes_ansi_escapes_and_trojan_unicode() -> None:
    """[Vector B.4 & A.3: Log Injection & Terminal Hijacking] Strips ANSI escape sequences, null bytes, C0 controls, and Trojan Source Bidi characters."""
    log = HashChainedAuditLog()
    malicious_input = (
        "normal_cmd\x1b[31m\x1b]0;PWNED_TERMINAL_TITLE\x07"
        "\u202eEVIL_BIDI\u200b\x00\r\n{\"sequence_id\":999,\"event_type\":\"FAKE_SUDO_GRANT\"}"
    )

    entry = log.append_event(
        event_type="ALERT\x1b[2J\u202e",
        actor_id="agent\x00_rogue",
        ring_level=3,
        vector_id="B.4",
        details={"payload": malicious_input},
    )

    sanitized_val = dict(entry.details)["payload"]
    # No raw ESC (\x1b), BEL (\x07), NUL (\x00), unescaped newline (\n), or Trojan Bidi (\u202e, \u200b)
    assert "\x1b" not in sanitized_val
    assert "\x07" not in sanitized_val
    assert "\x00" not in sanitized_val
    assert "\u202e" not in sanitized_val
    assert "\u200b" not in sanitized_val
    assert "\n" not in sanitized_val
    assert "\\n" in sanitized_val
    assert entry.event_type == "ALERT"
    assert entry.actor_id == "agent_rogue"
    # Exported JSONL must have exactly 1 line for 1 entry (multiline log injection prevented)
    assert len(log.export_jsonl().splitlines()) == 1


@pytest.mark.security
def test_sec_audit_log_split_horizon_encryption_hides_forensic_details() -> None:
    """[Vector A.3 & F.3: Reconnaissance & Exploit Blueprint Protection] Seals Tier-2 details in exported JSONL and recovers them only with Ring-0/1 decryption key."""
    log = HashChainedAuditLog()
    sensitive_details = {
        "file_path": "/home/simon/project/src/auth_kernel.py",
        "vuln_summary": "SSRF bypass attempted via IPv4-mapped IPv6 ::ffff:169.254.169.254",
        "stack_trace": "File 'network_guard.py', line 142, in validate_url_target",
    }
    entry = log.append_event(
        event_type="GUARD_VIOLATION",
        actor_id="subagent-worker-7",
        ring_level=3,
        vector_id="C.2",
        details=sensitive_details,
    )

    # 1. Public JSONL export contains Tier-1 metadata + encrypted_payload, but ZERO cleartext forensic strings
    public_jsonl = log.export_jsonl()
    assert "GUARD_VIOLATION" in public_jsonl
    assert "subagent-worker-7" in public_jsonl
    assert "encrypted_payload" in public_jsonl
    assert "/home/simon/project/src/auth_kernel.py" not in public_jsonl
    assert "169.254.169.254" not in public_jsonl
    assert "network_guard.py" not in public_jsonl
    assert '"details"' not in public_jsonl

    # 2. Authorized Ring-1 caller with key recovers 100% of sanitized forensic details
    recovered = log.decrypt_entry_details(entry)
    assert recovered == sensitive_details

    # 3. Tampering with encrypted_payload ciphertext or authentication tag fails closed
    parts = entry.encrypted_payload.split(":")
    flipped_tag = ("0" if parts[3][0] != "0" else "1") + parts[3][1:]
    tampered_entry = replace(entry, encrypted_payload=":".join([parts[0], parts[1], parts[2], flipped_tag]))
    with pytest.raises(AuditIntegrityError):
        log.decrypt_entry_details(tampered_entry)

    # 4. Separate AuditLog instance with a different key cannot decrypt the entry
    unauthorized_log = HashChainedAuditLog()
    with pytest.raises(AuditIntegrityError):
        unauthorized_log.decrypt_entry_details(entry)


@pytest.mark.security
def test_sec_audit_log_vault_0600_permissions_and_symlink_defense(tmp_path: Path) -> None:
    """[Vector A.3 & A.4: Physical Vault Tampering & Symlink Attack] Enforces 0o600 vault permissions, rejects symlinks, and blocks agent capability/sandbox access."""
    key = os.urandom(32)
    log = HashChainedAuditLog(signing_key=key)
    log.append_event(
        event_type="SUDO_APPROVAL",
        actor_id="operator-ring1",
        ring_level=1,
        details={"approved_cmd": "pytest tests/security", "target": "/srv/app"},
    )

    vault_dir = tmp_path / "audit_vault"
    vault_path = vault_dir / "security.audit.jsonl"
    written_path = log.write_vault_file(vault_path)

    # 1. Verify strict 0o600 file mode and 0o700 directory mode
    file_mode = stat.S_IMODE(os.lstat(written_path).st_mode)
    dir_mode = stat.S_IMODE(os.lstat(vault_dir).st_mode)
    assert file_mode == 0o600
    assert dir_mode == 0o700

    # 2. Verify round-trip reload and full decryption with the same key
    reloaded_log = HashChainedAuditLog(signing_key=key)
    loaded_entries = reloaded_log.load_vault_file(vault_path)
    assert len(loaded_entries) == 1
    assert dict(loaded_entries[0].details)["approved_cmd"] == "pytest tests/security"

    # 3. If file permissions are weakened (e.g. group/world readable 0o644), load_vault_file fails closed
    os.chmod(vault_path, 0o644)
    with pytest.raises(AuditIntegrityError) as perm_exc:
        reloaded_log.load_vault_file(vault_path)
    assert "insecure group/world permissions" in str(perm_exc.value)
    os.chmod(vault_path, 0o600)

    # 4. Symlink attack on write_vault_file and load_vault_file must be rejected
    symlink_target = tmp_path / "hijacked.txt"
    symlink_target.write_text("placeholder", encoding="utf-8")
    symlink_vault = tmp_path / "symlink.audit.jsonl"
    os.symlink(symlink_target, symlink_vault)

    with pytest.raises(AuditIntegrityError):
        log.write_vault_file(symlink_vault)
    with pytest.raises(AuditIntegrityError):
        log.load_vault_file(symlink_vault)

    # 5. CapabilityEngine and SandboxGuard strictly block agent access to audit_vault and .audit.jsonl
    cap_engine = CapabilityEngine()
    caveat = CapabilityCaveat(
        allowed_tools=frozenset({"fs:read"}),
        path_prefixes=(str(tmp_path),),
        expires_at_unix=time.time() + 300,
    )
    token = cap_engine.issue_root_token(
        subject_agent_id="agent-3",
        task_purpose="Read workspace",
        caveat=caveat,
    )
    with pytest.raises(CapabilityViolationError) as cap_exc:
        cap_engine.verify_tool_call(
            token=token,
            agent_id="agent-3",
            tool_name="fs:read",
            target_path=str(vault_path),
        )
    assert cap_exc.value.vector_id == "A.4"

    sandbox = SandboxGuard()
    with pytest.raises(SandboxSecurityError) as sb_exc:
        sandbox.build_bwrap_command(
            ["python3", "-V"],
            workspace_dir=str(tmp_path),
            extra_ro_binds=[str(vault_path)],
        )
    assert sb_exc.value.vector_id == "E.1"
