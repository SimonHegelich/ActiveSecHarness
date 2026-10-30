# Component Security Assessment: `deobfuscator`

> **Auto-Generated & Verified by `tools/wiki_sync.py`** — Do not edit manual status badges directly; update the `ComponentSecurityAssessment` contract in [`src/activesec/sovereign/deobfuscator.py`](../../src/activesec/sovereign/deobfuscator.py) or the security test suite in [`tests/security/test_sec_deobfuscator.py`](../../tests/security/test_sec_deobfuscator.py).

---

## 1. Security Posture Metadata

| Attribute | Value |
| :--- | :--- |
| **Component ID** | `deobfuscator` |
| **Title** | Ring-1 Social-Engineering De-Obfuscator & Sudo Risk Explainer |
| **Privilege Ring** | **Ring 1** |
| **Mitigated Threat Vectors** | `B.4`, `F.1`, `A.1` |
| **Source File** | [`src/activesec/sovereign/deobfuscator.py`](../../src/activesec/sovereign/deobfuscator.py) (`sha256:16d147edb9a0`) |
| **Dedicated Security Test Suite** | [`tests/security/test_sec_deobfuscator.py`](../../tests/security/test_sec_deobfuscator.py) |
| **AST Static Safety Audit** | **CLEAN (Zero Forbidden Primitives)** |
| **Adversarial Security Verification** | **VERIFIED (PASS)** (3 test vectors) |

---

## 2. Architectural Summary

Protects the human operator during sudo ceremonies by detecting Trojan Source invisible Unicode characters, decoding inline Base64/Hex payloads, and flagging pipe-to-shell (curl | sh), insecure TLS flags, and sensitive host path access.

---

## 3. Enforced Deterministic Security Invariants

- Immediately blocks commands containing Trojan Source bidirectional or zero-width Unicode control characters (CVE-2021-42574).
- Automatically decodes Base64 and Hex encoded command pipelines so the operator sees the real payload before deciding.
- Classifies curl/wget-to-shell, obfuscated execution, and ~/.ssh or docker.sock access as CRITICAL risk requiring anti-reflex intervention.

---

## 4. Dedicated Component Security Tests (`tests/security/test_sec_deobfuscator.py`)

| Test Function | Verified Adversarial Vector & Invariant | Status |
| :--- | :--- | :--- |
| `test_sec_trojan_source_unicode_bidi_blocked` | [Vector B.4: Trojan Source CVE-2021-42574] Immediately blocks invisible Unicode Bidi overrides. | **PASS** |
| `test_sec_base64_obfuscated_reverse_shell_exposed_and_blocked` | [Vector F.1: Deceptive UI / Base64 Obfuscation] Decodes Base64 payload and triggers CRITICAL alert. | **PASS** |
| `test_sec_sensitive_ssh_and_docker_socket_flagged_critical` | [Vector A.4 & E.1: Host Persistence & Escape] Flags access to ~/.ssh and docker.sock as CRITICAL. | **PASS** |

---

## 5. Known Residual Risks & Defense-in-Depth Pairing

- External scripts whose logic resides on a remote server not yet downloaded (mitigated by MalwareGuard quarantine before execution).
