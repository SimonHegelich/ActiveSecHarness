# Component Security Assessment: `audit_log`

> **Auto-Generated & Verified by `WikiManager` (`tools/wiki_sync.py`)** — Do not edit manual status badges directly; update the `ComponentSecurityAssessment` contract in [`src/activesec/core/audit_log.py`](../../src/activesec/core/audit_log.py) or the security test suite in [`tests/security/test_sec_audit_log.py`](../../tests/security/test_sec_audit_log.py).

---

## 1. Security Posture Metadata

| Attribute | Value |
| :--- | :--- |
| **Component ID** | `audit_log` |
| **Title** | Ring-0 Hash-Chained, Split-Horizon Encrypted & Sanitized Security Audit Log |
| **Privilege Ring** | **Ring 0** |
| **Mitigated Threat Vectors** | `A.3`, `B.4`, `D.2`, `F.3` |
| **Source File** | [`src/activesec/core/audit_log.py`](../../src/activesec/core/audit_log.py) (`sha256:4bcaabbc5593`) |
| **Dedicated Security Test Suite** | [`tests/security/test_sec_audit_log.py`](../../tests/security/test_sec_audit_log.py) |
| **AST Static Safety Audit** | **CLEAN (Zero Forbidden Primitives)** |
| **Adversarial Security Verification** | **VERIFIED (PASS)** (7 test vectors) |

---

## 2. Architectural Summary

Maintains a tamper-evident, append-only cryptographic audit trail of all sudo grants, delegations, tool invocations, and security violations using SHA-256 hash chaining, Ring-0 HMAC-SHA256 signatures, deterministic salted HMAC secret scrubbing, anti-log-injection terminal/Unicode sanitization, split-horizon Tier-2 payload encryption (Encrypt-then-MAC), and strict 0o600 vault file protection.

---

## 3. Enforced Deterministic Security Invariants

- Every entry hashes its canonical payload together with prev_entry_hash (starting from a fixed 64-zero genesis hash).
- Every entry is authenticated with a >=256-bit Ring-0 HMAC-SHA256 signature over entry_hash.
- Two-stage pre-logging sanitization scrubs passwords, API keys, PEM keys, Bearer/Basic tokens, CLI secret flags, and high-entropy secrets into deterministic <REDACTED:TYPE:hmac_10chars> fingerprints before storage or hashing.
- All logged strings strip ANSI escape sequences, null bytes, C0/C1 control characters, and Trojan Source Unicode codepoints to prevent log injection and terminal hijacking.
- Tier-2 forensic details are sealed with per-entry HKDF-HMAC-SHA256 stream encryption and Encrypt-then-MAC authentication tags so exported JSONL and disk vaults never expose cleartext vulnerability or path blueprints.
- Physical vault writes enforce 0o700 directory and 0o600 file permissions atomically while rejecting symlinks and group/world-accessible files.

---

## 4. Dedicated Component Security Tests (`tests/security/test_sec_audit_log.py`)

| Test Function | Verified Adversarial Vector & Invariant | Status |
| :--- | :--- | :--- |
| `test_sec_audit_log_detects_payload_tampering` | [Vector A.3: Harness Tampering] Detects modification of any field in a historical audit entry. | **PASS** |
| `test_sec_audit_log_detects_entry_deletion_and_reordering` | [Vector A.3: Log Erasure] Detects deletion of middle/initial entries or sequence reordering. | **PASS** |
| `test_sec_audit_log_blocks_hash_recomputation_without_hmac_key` | [Vector A.3: Cryptographic Forgery] Recomputing SHA-256 chain without Ring-0 HMAC key is rejected. | **PASS** |
| `test_sec_audit_log_zero_secret_scrubbing_and_correlation_fingerprints` | [Vector D.2: Secret Leakage in Logs] Scrubs passwords, API keys, PEM keys, Bearer tokens, and CLI flags with deterministic salted HMAC correlation. | **PASS** |
| `test_sec_audit_log_neutralizes_ansi_escapes_and_trojan_unicode` | [Vector B.4 & A.3: Log Injection & Terminal Hijacking] Strips ANSI escape sequences, null bytes, C0 controls, and Trojan Source Bidi characters. | **PASS** |
| `test_sec_audit_log_split_horizon_encryption_hides_forensic_details` | [Vector A.3 & F.3: Reconnaissance & Exploit Blueprint Protection] Seals Tier-2 details in exported JSONL and recovers them only with Ring-0/1 decryption key. | **PASS** |
| `test_sec_audit_log_vault_0600_permissions_and_symlink_defense` | [Vector A.3 & A.4: Physical Vault Tampering & Symlink Attack] Enforces 0o600 vault permissions, rejects symlinks, and blocks agent capability/sandbox access. | **PASS** |

---

## 5. Known Residual Risks & Defense-in-Depth Pairing

- Total process termination before flushing in-memory entries to the 0o600 vault or remote append-only sink.
