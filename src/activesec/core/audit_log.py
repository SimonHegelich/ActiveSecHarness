"""Ring-0 HashChainedAuditLog: Tamper-evident, split-horizon encrypted security ledger.

Records every sudo capability grant, token delegation, tool execution, and blocked attack
as a hash-chained, HMAC-authenticated ledger entry with:
1. Two-stage pre-logging sanitization (deterministic salted HMAC secret redaction +
   ANSI escape, control character, and Trojan Source Unicode neutralization).
2. Split-horizon Tier-1 (public structural header) and Tier-2 (authenticated encrypted
   forensic payload) architecture using per-entry HKDF-HMAC-SHA256 subkeys and
   Encrypt-then-MAC stream sealing.
3. Physical vault persistence enforcing strict 0o600 file permissions, 0o700 parent
   directory permissions, atomic rename writes, and symlink rejection.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Tuple

from activesec.core.component import ComponentSecurityAssessment, SecureComponent
from activesec.core.exceptions import AuditIntegrityError
from activesec.sovereign.deobfuscator import TROJAN_SOURCE_UNICODE_CHARS


GENESIS_PREV_HASH: str = "0" * 64

_ANSI_ESCAPE_RE: re.Pattern[str] = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]|[\x1b\x9b]"
)

_SENSITIVE_KEY_NAMES: Tuple[str, ...] = (
    "password",
    "passwd",
    "passphrase",
    "secret",
    "api_key",
    "apikey",
    "token",
    "access_token",
    "auth_token",
    "refresh_token",
    "client_secret",
    "private_key",
    "authorization",
    "credential",
)


@dataclass(frozen=True, slots=True)
class AuditLogEntry:
    """Immutable split-horizon entry in the hash-chained security audit log.

    Tier 1 (Public/Structural Header):
        sequence_id, timestamp_unix, event_type, actor_id, ring_level, vector_id,
        prev_entry_hash, entry_hash, hmac_signature.
    Tier 2 (Sealed Forensic Payload):
        encrypted_payload (ciphertext + nonce + Encrypt-then-MAC tag) and sanitized
        in-memory details tuple.
    """

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
    encrypted_payload: str = ""

    def tier1_header_dict(self) -> Dict[str, object]:
        """Return the Tier-1 public structural header fields safe for real-time telemetry."""
        return {
            "actor_id": self.actor_id,
            "entry_hash": self.entry_hash,
            "event_type": self.event_type,
            "hmac_signature": self.hmac_signature,
            "prev_entry_hash": self.prev_entry_hash,
            "ring_level": self.ring_level,
            "sequence_id": self.sequence_id,
            "timestamp_unix": round(self.timestamp_unix, 6),
            "vector_id": self.vector_id,
        }

    def canonical_payload_bytes(self) -> bytes:
        """Return deterministic canonical JSON bytes for hashing and HMAC signing."""
        payload: Dict[str, object] = {
            "actor_id": self.actor_id,
            "details": dict(self.details),
            "encrypted_payload": self.encrypted_payload,
            "event_type": self.event_type,
            "prev_entry_hash": self.prev_entry_hash,
            "ring_level": self.ring_level,
            "sequence_id": self.sequence_id,
            "timestamp_unix": round(self.timestamp_unix, 6),
            "vector_id": self.vector_id,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class HashChainedAuditLog(SecureComponent):
    """Ring-0 append-only cryptographic audit log with DLP sanitization, split-horizon encryption, and 0600 vaulting."""

    _STANDALONE_SECRET_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
        (
            "PEM_PRIVATE_KEY",
            re.compile(
                r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |)?PRIVATE KEY-----"
                r"[\s\S]*?"
                r"-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |)?PRIVATE KEY-----"
            ),
        ),
        ("OPENAI_KEY", re.compile(r"\bsk-(?:proj-|ant-|svcacct-)?[A-Za-z0-9_-]{16,}\b")),
        ("GITHUB_TOKEN", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
        ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
        ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    )

    _AUTH_HEADER_PATTERN: re.Pattern[str] = re.compile(
        r"(?i)\b((?:Authorization\s*[:=]\s*)?(?:Bearer|Basic)\s+)([A-Za-z0-9._~+/=-]{8,})"
    )

    _CLI_LONG_FLAG_PATTERN: re.Pattern[str] = re.compile(
        r"(?i)(--(?:password|passwd|pass|secret|token|api-key|apikey|auth-token|access-token|client-secret)"
        r"(?:\s*=\s*|\s+))(['\"]?)([^\s'\";&|]+)\2"
    )

    _CLI_SHORT_PASS_PATTERN: re.Pattern[str] = re.compile(
        r"(?<!mkdir\s)(?:^|(?<=\s))(-p\s+)(['\"]?)([^\s'\";&|/][^\s'\";&|]{3,})\2"
    )

    _GENERIC_ASSIGNMENT_PATTERN: re.Pattern[str] = re.compile(
        r"(?i)(?<!<REDACTED:)\b((?:api_key|secret_key|password|passwd|secret|access_token|auth_token|client_secret|private_key)"
        r"\s*[:=]\s*)(['\"]?)([^\s'\";,&|>]{4,})\2"
    )

    _CANDIDATE_TOKEN_PATTERN: re.Pattern[str] = re.compile(
        r"(?<![A-Za-z0-9_/<>:-])[A-Za-z0-9+/=_!@#$%^&*-]{20,}(?![A-Za-z0-9_>:-])"
    )

    def __init__(
        self,
        signing_key: Optional[bytes] = None,
        *,
        encryption_key: Optional[bytes] = None,
        redaction_salt: Optional[bytes] = None,
    ) -> None:
        self._signing_key: bytes = signing_key if signing_key is not None else secrets.token_bytes(32)
        if len(self._signing_key) < 32:
            raise AuditIntegrityError(
                "Audit log signing key must be at least 32 bytes.",
                vector_id="A.3",
                component_id="audit_log",
            )
        if encryption_key is not None and len(encryption_key) < 32:
            raise AuditIntegrityError(
                "Audit log encryption key must be at least 32 bytes.",
                vector_id="A.3",
                component_id="audit_log",
            )
        self._encryption_key: bytes = (
            encryption_key
            if encryption_key is not None
            else hmac.new(self._signing_key, b"activesec.audit.tier2.encryption.v1", hashlib.sha256).digest()
        )
        self._redaction_salt: bytes = (
            redaction_salt
            if redaction_salt is not None
            else hmac.new(self._signing_key, b"activesec.audit.redaction.salt.v1", hashlib.sha256).digest()
        )
        self._entries: List[AuditLogEntry] = []

    @classmethod
    def security_assessment(cls) -> ComponentSecurityAssessment:
        return ComponentSecurityAssessment(
            component_id="audit_log",
            title="Ring-0 Hash-Chained, Split-Horizon Encrypted & Sanitized Security Audit Log",
            ring_level=0,
            source_path="src/activesec/core/audit_log.py",
            security_test_path="tests/security/test_sec_audit_log.py",
            threat_vectors=("A.3", "B.4", "D.2", "F.3"),
            summary=(
                "Maintains a tamper-evident, append-only cryptographic audit trail of all sudo grants, "
                "delegations, tool invocations, and security violations using SHA-256 hash chaining, "
                "Ring-0 HMAC-SHA256 signatures, deterministic salted HMAC secret scrubbing, "
                "anti-log-injection terminal/Unicode sanitization, split-horizon Tier-2 payload "
                "encryption (Encrypt-then-MAC), and strict 0o600 vault file protection."
            ),
            enforced_invariants=(
                "Every entry hashes its canonical payload together with prev_entry_hash (starting from a fixed 64-zero genesis hash).",
                "Every entry is authenticated with a >=256-bit Ring-0 HMAC-SHA256 signature over entry_hash.",
                "Two-stage pre-logging sanitization scrubs passwords, API keys, PEM keys, Bearer/Basic tokens, CLI secret flags, and high-entropy secrets into deterministic <REDACTED:TYPE:hmac_10chars> fingerprints before storage or hashing.",
                "All logged strings strip ANSI escape sequences, null bytes, C0/C1 control characters, and Trojan Source Unicode codepoints to prevent log injection and terminal hijacking.",
                "Tier-2 forensic details are sealed with per-entry HKDF-HMAC-SHA256 stream encryption and Encrypt-then-MAC authentication tags so exported JSONL and disk vaults never expose cleartext vulnerability or path blueprints.",
                "Physical vault writes enforce 0o700 directory and 0o600 file permissions atomically while rejecting symlinks and group/world-accessible files.",
            ),
            residual_risks=(
                "Total process termination before flushing in-memory entries to the 0o600 vault or remote append-only sink.",
            ),
        )

    @property
    def entries(self) -> Tuple[AuditLogEntry, ...]:
        """Return an immutable snapshot of all audit log entries."""
        return tuple(self._entries)

    def compute_secret_fingerprint(self, raw_secret: str) -> str:
        """Compute a deterministic 10-character session-salted HMAC-SHA256 fingerprint for a secret."""
        normalized = raw_secret.strip()
        return hmac.new(
            self._redaction_salt,
            normalized.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:10]

    @staticmethod
    def _shannon_entropy_bits(token: str) -> Tuple[float, float]:
        if not token:
            return (0.0, 0.0)
        length = len(token)
        counts: Dict[str, int] = {}
        for ch in token:
            counts[ch] = counts.get(ch, 0) + 1
        bits_per_char = -sum((c / length) * math.log2(c / length) for c in counts.values())
        return (bits_per_char, bits_per_char * length)

    @classmethod
    def _looks_like_high_entropy_secret(cls, token: str) -> bool:
        if len(token) < 20 or "REDACTED" in token:
            return False
        has_lower = any(c.islower() for c in token)
        has_upper = any(c.isupper() for c in token)
        has_digit = any(c.isdigit() for c in token)
        if not (has_lower and has_upper and has_digit):
            return False
        bits_per_char, total_bits = cls._shannon_entropy_bits(token)
        return bits_per_char >= 3.85 and total_bits >= 80.0

    @staticmethod
    def _strip_invisible_and_ansi(text: str) -> str:
        """Remove ANSI escape sequences, null bytes, and Trojan Source Unicode characters."""
        without_ansi = _ANSI_ESCAPE_RE.sub("", text)
        cleaned_chars: List[str] = []
        for ch in without_ansi:
            cp = ord(ch)
            if cp == 0 or cp in TROJAN_SOURCE_UNICODE_CHARS:
                continue
            cleaned_chars.append(ch)
        return "".join(cleaned_chars)

    @staticmethod
    def _neutralize_control_chars(text: str) -> str:
        """Escape newlines/tabs and strip remaining C0/C1 control characters."""
        out: List[str] = []
        for ch in text:
            cp = ord(ch)
            if ch == "\n":
                out.append("\\n")
            elif ch == "\r":
                out.append("\\r")
            elif ch == "\t":
                out.append("\\t")
            elif cp < 0x20 or (0x7F <= cp <= 0x9F):
                continue
            else:
                out.append(ch)
        return "".join(out)

    def sanitize_log_text(self, text: str, *, key_hint: str = "") -> str:
        """Perform two-stage sanitization: secret redaction + terminal/Unicode injection stripping."""
        # Pre-stage: remove invisible Trojan Unicode, null bytes, and ANSI escapes first so they
        # cannot split or camouflage a secret pattern.
        stage1 = self._strip_invisible_and_ansi(str(text))

        # 1. Standalone known secret patterns (PEM, OpenAI, GitHub, AWS, Slack)
        for secret_type, pattern in self._STANDALONE_SECRET_PATTERNS:
            def _replace_standalone(match: re.Match[str], stype: str = secret_type) -> str:
                raw_secret = match.group(0)
                fp = self.compute_secret_fingerprint(raw_secret)
                return f"<REDACTED:{stype}:{fp}>"

            stage1 = pattern.sub(_replace_standalone, stage1)

        # 2. Bearer / Basic Authorization headers
        def _replace_auth_header(match: re.Match[str]) -> str:
            prefix = match.group(1)
            raw_secret = match.group(2)
            if raw_secret.startswith("<REDACTED:"):
                return match.group(0)
            fp = self.compute_secret_fingerprint(raw_secret)
            return f"{prefix}<REDACTED:SECRET:{fp}>"

        stage1 = self._AUTH_HEADER_PATTERN.sub(_replace_auth_header, stage1)

        # 3. CLI long flags (--password=..., --token=..., etc.)
        def _replace_cli_long(match: re.Match[str]) -> str:
            flag_prefix = match.group(1)
            raw_secret = match.group(3)
            if raw_secret.startswith("<REDACTED:"):
                return match.group(0)
            fp = self.compute_secret_fingerprint(raw_secret)
            return f"{flag_prefix}<REDACTED:SECRET:{fp}>"

        stage1 = self._CLI_LONG_FLAG_PATTERN.sub(_replace_cli_long, stage1)

        # 4. CLI short password flag (-p <secret>)
        def _replace_cli_short(match: re.Match[str]) -> str:
            flag_prefix = match.group(1)
            raw_secret = match.group(3)
            if raw_secret.startswith("<REDACTED:"):
                return match.group(0)
            fp = self.compute_secret_fingerprint(raw_secret)
            return f"{flag_prefix}<REDACTED:SECRET:{fp}>"

        stage1 = self._CLI_SHORT_PASS_PATTERN.sub(_replace_cli_short, stage1)

        # 5. Generic key=value / key: value secret assignments
        def _replace_assignment(match: re.Match[str]) -> str:
            assign_prefix = match.group(1)
            raw_secret = match.group(3)
            if raw_secret.startswith("<REDACTED:"):
                return match.group(0)
            fp = self.compute_secret_fingerprint(raw_secret)
            return f"{assign_prefix}<REDACTED:SECRET:{fp}>"

        stage1 = self._GENERIC_ASSIGNMENT_PATTERN.sub(_replace_assignment, stage1)

        # 6. High-entropy secret tokens
        def _replace_high_entropy(match: re.Match[str]) -> str:
            candidate = match.group(0)
            if self._looks_like_high_entropy_secret(candidate):
                fp = self.compute_secret_fingerprint(candidate)
                return f"<REDACTED:SECRET:{fp}>"
            return candidate

        stage1 = self._CANDIDATE_TOKEN_PATTERN.sub(_replace_high_entropy, stage1)

        # 7. Sensitive dictionary key name enforcement
        lower_key = key_hint.strip().lower()
        if (
            lower_key
            and any( lower_key == sk or lower_key.endswith("_" + sk) or lower_key.startswith(sk + "_") for sk in _SENSITIVE_KEY_NAMES )
            and "<REDACTED:" not in stage1
            and stage1.strip()
        ):
            fp = self.compute_secret_fingerprint(stage1.strip())
            stage1 = f"<REDACTED:SECRET:{fp}>"

        # Stage 2: Escape newlines/CR/tabs and strip all remaining C0/C1 control characters
        return self._neutralize_control_chars(stage1)

    def _derive_entry_subkeys(self, sequence_id: int, nonce: bytes) -> Tuple[bytes, bytes]:
        """Derive per-entry encryption and MAC subkeys using HKDF-style HMAC-SHA256."""
        prk = hmac.new(
            self._encryption_key,
            f"entry:{sequence_id}:".encode("utf-8") + nonce,
            hashlib.sha256,
        ).digest()
        enc_subkey = hmac.new(prk, b"tier2-stream-enc\x01", hashlib.sha256).digest()
        mac_subkey = hmac.new(prk, b"tier2-etm-auth\x02", hashlib.sha256).digest()
        return (enc_subkey, mac_subkey)

    @staticmethod
    def _xor_keystream(data: bytes, enc_subkey: bytes, nonce: bytes) -> bytes:
        """Encrypt or decrypt bytes using an HMAC-SHA256 counter-mode keystream."""
        output = bytearray(len(data))
        block_count = (len(data) + 31) // 32
        for counter in range(block_count):
            keystream_block = hmac.new(
                enc_subkey,
                nonce + counter.to_bytes(8, "big"),
                hashlib.sha256,
            ).digest()
            start = counter * 32
            end = min(start + 32, len(data))
            for idx in range(start, end):
                output[idx] = data[idx] ^ keystream_block[idx - start]
        return bytes(output)

    @staticmethod
    def _build_entry_aad(
        *,
        sequence_id: int,
        event_type: str,
        actor_id: str,
        ring_level: int,
        vector_id: str,
    ) -> bytes:
        return f"{sequence_id}|{event_type}|{actor_id}|{ring_level}|{vector_id}".encode("utf-8")

    def _seal_tier2_details(
        self,
        *,
        sequence_id: int,
        event_type: str,
        actor_id: str,
        ring_level: int,
        vector_id: str,
        details: Tuple[Tuple[str, str], ...],
    ) -> str:
        """Seal sanitized Tier-2 details into an authenticated ciphertext envelope."""
        nonce = secrets.token_bytes(16)
        enc_subkey, mac_subkey = self._derive_entry_subkeys(sequence_id, nonce)
        plaintext = json.dumps(dict(details), sort_keys=True, separators=(",", ":")).encode("utf-8")
        ciphertext = self._xor_keystream(plaintext, enc_subkey, nonce)
        aad = self._build_entry_aad(
            sequence_id=sequence_id,
            event_type=event_type,
            actor_id=actor_id,
            ring_level=ring_level,
            vector_id=vector_id,
        )
        auth_tag = hmac.new(
            mac_subkey,
            aad + b"|" + nonce + b"|" + ciphertext,
            hashlib.sha256,
        ).hexdigest()
        return f"v1:{nonce.hex()}:{ciphertext.hex()}:{auth_tag}"

    def decrypt_entry_details(self, entry: AuditLogEntry) -> Dict[str, str]:
        """Verify the Encrypt-then-MAC tag and decrypt the sealed Tier-2 forensic payload."""
        parts = entry.encrypted_payload.split(":")
        if len(parts) != 4 or parts[0] != "v1":
            raise AuditIntegrityError(
                f"Malformed Tier-2 encrypted_payload envelope at sequence_id={entry.sequence_id}.",
                vector_id="A.3",
                component_id="audit_log",
            )
        try:
            nonce = bytes.fromhex(parts[1])
            ciphertext = bytes.fromhex(parts[2])
        except ValueError as exc:
            raise AuditIntegrityError(
                f"Corrupted hex encoding in encrypted_payload at sequence_id={entry.sequence_id}.",
                vector_id="A.3",
                component_id="audit_log",
            ) from exc
        auth_tag = parts[3]
        if len(nonce) != 16:
            raise AuditIntegrityError(
                f"Invalid Tier-2 nonce length at sequence_id={entry.sequence_id}.",
                vector_id="A.3",
                component_id="audit_log",
            )

        enc_subkey, mac_subkey = self._derive_entry_subkeys(entry.sequence_id, nonce)
        aad = self._build_entry_aad(
            sequence_id=entry.sequence_id,
            event_type=entry.event_type,
            actor_id=entry.actor_id,
            ring_level=entry.ring_level,
            vector_id=entry.vector_id,
        )
        expected_tag = hmac.new(
            mac_subkey,
            aad + b"|" + nonce + b"|" + ciphertext,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(auth_tag, expected_tag):
            raise AuditIntegrityError(
                f"Tier-2 encrypted payload authentication failed at sequence_id={entry.sequence_id}.",
                vector_id="A.3",
                component_id="audit_log",
            )

        plaintext = self._xor_keystream(ciphertext, enc_subkey, nonce)
        try:
            decoded_obj = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuditIntegrityError(
                f"Decrypted Tier-2 payload is not valid JSON at sequence_id={entry.sequence_id}.",
                vector_id="A.3",
                component_id="audit_log",
            ) from exc
        if not isinstance(decoded_obj, dict):
            raise AuditIntegrityError(
                f"Decrypted Tier-2 payload is not a key-value mapping at sequence_id={entry.sequence_id}.",
                vector_id="A.3",
                component_id="audit_log",
            )
        return {str(k): str(v) for k, v in decoded_obj.items()}

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
        """Sanitize, seal, and append a new cryptographically chained event to the audit log."""
        clean_event_type = self.sanitize_log_text(event_type).strip()
        clean_actor_id = self.sanitize_log_text(actor_id).strip()
        clean_vector_id = self.sanitize_log_text(vector_id).strip() or "NONE"

        if not clean_event_type or not clean_actor_id:
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

        sanitized_pairs: List[Tuple[str, str]] = []
        for raw_k, raw_v in (details or {}).items():
            clean_k = self.sanitize_log_text(str(raw_k))
            clean_v = self.sanitize_log_text(str(raw_v), key_hint=clean_k)
            sanitized_pairs.append((clean_k, clean_v))
        sorted_details: Tuple[Tuple[str, str], ...] = tuple(sorted(sanitized_pairs))

        encrypted_payload = self._seal_tier2_details(
            sequence_id=seq_id,
            event_type=clean_event_type,
            actor_id=clean_actor_id,
            ring_level=ring_level,
            vector_id=clean_vector_id,
            details=sorted_details,
        )

        provisional = AuditLogEntry(
            sequence_id=seq_id,
            timestamp_unix=ts,
            event_type=clean_event_type,
            actor_id=clean_actor_id,
            ring_level=ring_level,
            vector_id=clean_vector_id,
            details=sorted_details,
            prev_entry_hash=prev_hash,
            entry_hash="",
            hmac_signature="",
            encrypted_payload=encrypted_payload,
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
            event_type=clean_event_type,
            actor_id=clean_actor_id,
            ring_level=ring_level,
            vector_id=clean_vector_id,
            details=sorted_details,
            prev_entry_hash=prev_hash,
            entry_hash=entry_hash,
            hmac_signature=signature,
            encrypted_payload=encrypted_payload,
        )
        self._entries.append(final_entry)
        return final_entry

    def verify_chain(self, external_entries: Optional[Tuple[AuditLogEntry, ...]] = None) -> bool:
        """Verify cryptographic integrity, sequence continuity, HMAC signatures, and Tier-2 sealing."""
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

            if entry.encrypted_payload:
                decrypted = self.decrypt_entry_details(entry)
                if dict(entry.details) != decrypted:
                    raise AuditIntegrityError(
                        f"Tier-2 decrypted payload mismatch at sequence_id={entry.sequence_id}.",
                        vector_id="A.3",
                        component_id="audit_log",
                    )

            expected_prev_hash = entry.entry_hash

        return True

    def export_jsonl(self, *, include_cleartext_details: bool = False) -> str:
        """Export the verified chain as deterministic Split-Horizon JSON Lines.

        By default, cleartext `details` are omitted and only `encrypted_payload` is exported
        alongside Tier-1 structural headers.
        """
        self.verify_chain()
        lines: List[str] = []
        for e in self._entries:
            obj: Dict[str, object] = {
                "actor_id": e.actor_id,
                "encrypted_payload": e.encrypted_payload,
                "entry_hash": e.entry_hash,
                "event_type": e.event_type,
                "hmac_signature": e.hmac_signature,
                "prev_entry_hash": e.prev_entry_hash,
                "ring_level": e.ring_level,
                "sequence_id": e.sequence_id,
                "timestamp_unix": e.timestamp_unix,
                "vector_id": e.vector_id,
            }
            if include_cleartext_details:
                obj["details"] = dict(e.details)
            lines.append(json.dumps(obj, sort_keys=True))
        return "\n".join(lines)

    def write_vault_file(self, vault_path: str | os.PathLike[str]) -> Path:
        """Atomically write the sealed JSONL audit log with strict 0o600 permissions."""
        raw_target = Path(vault_path)
        if os.path.islink(raw_target):
            raise AuditIntegrityError(
                f"Audit vault path '{raw_target}' is a symbolic link; refusing to write.",
                vector_id="A.3",
                component_id="audit_log",
            )

        parent_dir = raw_target.parent
        if os.path.islink(parent_dir):
            raise AuditIntegrityError(
                f"Audit vault parent directory '{parent_dir}' is a symbolic link; refusing to write.",
                vector_id="A.3",
                component_id="audit_log",
            )

        os.makedirs(parent_dir, mode=0o700, exist_ok=True)
        os.chmod(parent_dir, 0o700)

        if raw_target.exists():
            st = os.lstat(raw_target)
            if not stat.S_ISREG(st.st_mode):
                raise AuditIntegrityError(
                    f"Audit vault target '{raw_target}' is not a regular file.",
                    vector_id="A.3",
                    component_id="audit_log",
                )

        sealed_jsonl = self.export_jsonl(include_cleartext_details=False)
        payload_bytes = (sealed_jsonl + "\n").encode("utf-8") if sealed_jsonl else b""

        tmp_name = f".{raw_target.name}.tmp.{secrets.token_hex(8)}"
        tmp_path = parent_dir / tmp_name
        open_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(tmp_path), open_flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, payload_bytes)
            os.fsync(fd)
        finally:
            os.close(fd)

        if os.path.islink(raw_target):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise AuditIntegrityError(
                f"Symlink race detected on audit vault path '{raw_target}'.",
                vector_id="A.3",
                component_id="audit_log",
            )

        os.replace(tmp_path, raw_target)
        os.chmod(raw_target, 0o600)
        return Path(os.path.realpath(raw_target))

    def load_vault_file(self, vault_path: str | os.PathLike[str]) -> Tuple[AuditLogEntry, ...]:
        """Load, permission-check (0o600), decrypt, and verify a sealed JSONL vault file."""
        raw_target = Path(vault_path)
        if os.path.islink(raw_target):
            raise AuditIntegrityError(
                f"Audit vault path '{raw_target}' is a symbolic link; refusing to load.",
                vector_id="A.3",
                component_id="audit_log",
            )
        if not raw_target.exists():
            raise AuditIntegrityError(
                f"Audit vault file '{raw_target}' does not exist.",
                vector_id="A.3",
                component_id="audit_log",
            )

        st = os.lstat(raw_target)
        if not stat.S_ISREG(st.st_mode):
            raise AuditIntegrityError(
                f"Audit vault path '{raw_target}' is not a regular file.",
                vector_id="A.3",
                component_id="audit_log",
            )
        if (st.st_mode & (stat.S_IRWXG | stat.S_IRWXO)) != 0:
            raise AuditIntegrityError(
                f"Audit vault file '{raw_target}' has insecure group/world permissions ({oct(st.st_mode & 0o777)}); expected 0o600.",
                vector_id="A.3",
                component_id="audit_log",
            )

        raw_content = raw_target.read_text(encoding="utf-8")
        loaded_entries: List[AuditLogEntry] = []

        for line_no, line in enumerate(raw_content.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise AuditIntegrityError(
                    f"Corrupted JSON in audit vault at line {line_no}.",
                    vector_id="A.3",
                    component_id="audit_log",
                ) from exc

            provisional = AuditLogEntry(
                sequence_id=int(obj["sequence_id"]),
                timestamp_unix=float(obj["timestamp_unix"]),
                event_type=str(obj["event_type"]),
                actor_id=str(obj["actor_id"]),
                ring_level=int(obj["ring_level"]),
                vector_id=str(obj["vector_id"]),
                details=(),
                prev_entry_hash=str(obj["prev_entry_hash"]),
                entry_hash=str(obj["entry_hash"]),
                hmac_signature=str(obj["hmac_signature"]),
                encrypted_payload=str(obj["encrypted_payload"]),
            )
            decrypted_map = self.decrypt_entry_details(provisional)
            sorted_details = tuple(sorted((str(k), str(v)) for k, v in decrypted_map.items()))

            full_entry = AuditLogEntry(
                sequence_id=provisional.sequence_id,
                timestamp_unix=provisional.timestamp_unix,
                event_type=provisional.event_type,
                actor_id=provisional.actor_id,
                ring_level=provisional.ring_level,
                vector_id=provisional.vector_id,
                details=sorted_details,
                prev_entry_hash=provisional.prev_entry_hash,
                entry_hash=provisional.entry_hash,
                hmac_signature=provisional.hmac_signature,
                encrypted_payload=provisional.encrypted_payload,
            )
            loaded_entries.append(full_entry)

        verified_tuple = tuple(loaded_entries)
        self.verify_chain(verified_tuple)
        self._entries = list(loaded_entries)
        return verified_tuple
