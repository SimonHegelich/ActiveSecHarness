# Component Security Assessment: `canary_guard`

> **Auto-Generated & Verified by `tools/wiki_sync.py`** — Do not edit manual status badges directly; update the `ComponentSecurityAssessment` contract in [`src/activesec/guards/canary_guard.py`](../../src/activesec/guards/canary_guard.py) or the security test suite in [`tests/security/test_sec_canary_guard.py`](../../tests/security/test_sec_canary_guard.py).

---

## 1. Security Posture Metadata

| Attribute | Value |
| :--- | :--- |
| **Component ID** | `canary_guard` |
| **Title** | Ring-0 Honeypot Canary & Zero-False-Positive Intrusion Tripwire |
| **Privilege Ring** | **Ring 0** |
| **Mitigated Threat Vectors** | `F.2`, `C.3`, `D.2`, `A.1` |
| **Source File** | [`src/activesec/guards/canary_guard.py`](../../src/activesec/guards/canary_guard.py) (`sha256:099fee8359ce`) |
| **Dedicated Security Test Suite** | [`tests/security/test_sec_canary_guard.py`](../../tests/security/test_sec_canary_guard.py) |
| **AST Static Safety Audit** | **CLEAN (Zero Forbidden Primitives)** |
| **Adversarial Security Verification** | **VERIFIED (PASS)** (2 test vectors) |

---

## 2. Architectural Summary

Deploys synthetic honeypot credentials and decoy files (Canary Tokens) that no legitimate task ever touches. Detects indirect prompt injection, credential harvesting, and covert exfiltration (including Base64/Hex-encoded leaks) with zero false positives.

---

## 3. Enforced Deterministic Security Invariants

- Generates cryptographically unique decoy tokens (synthetic AWS AKIA, OpenAI sk-canary, SSH honeyfiles) via CSPRNG.
- Canonicalizes inspected file paths (os.path.realpath) so symlink or ../ access to a honeyfile immediately trips the alarm.
- Inspects outbound commands, tool outputs, and network bodies for both raw and Base64/Hex-encoded canary values.
- Invokes the registered emergency revocation callback prior to raising CanaryTripwireError.

---

## 4. Dedicated Component Security Tests (`tests/security/test_sec_canary_guard.py`)

| Test Function | Verified Adversarial Vector & Invariant | Status |
| :--- | :--- | :--- |
| `test_sec_honeyfile_access_and_symlink_trips_alarm_and_revokes` | [Vector F.2: Prompt Injection Credential Harvesting] Accessing a honeyfile directly or via symlink triggers revocation. | **PASS** |
| `test_sec_raw_and_encoded_canary_exfiltration_blocked` | [Vector C.3: Covert Exfiltration] Detects raw, Base64-encoded, and Hex-encoded canary leaks. | **PASS** |

---

## 5. Known Residual Risks & Defense-in-Depth Pairing

- Sophisticated attacker who selectively exfiltrates only application source code while avoiding credential files (mitigated by NetworkGuard offline default).
