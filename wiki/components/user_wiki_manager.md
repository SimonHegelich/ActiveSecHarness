# Component Security Assessment: `user_wiki_manager`

> **Auto-Generated & Verified by `WikiManager` (`tools/wiki_sync.py`)** — Do not edit manual status badges directly; update the `ComponentSecurityAssessment` contract in [`src/activesec/core/user_wiki_manager.py`](../../src/activesec/core/user_wiki_manager.py) or the security test suite in [`tests/security/test_sec_user_wiki_manager.py`](../../tests/security/test_sec_user_wiki_manager.py).

---

## 1. Security Posture Metadata

| Attribute | Value |
| :--- | :--- |
| **Component ID** | `user_wiki_manager` |
| **Title** | Ring-1 Didactic User Security Academy Wiki Manager (`wiki_user/`) |
| **Privilege Ring** | **Ring 1** |
| **Mitigated Threat Vectors** | `F.1`, `D.2`, `B.4`, `A.3` |
| **Source File** | [`src/activesec/core/user_wiki_manager.py`](../../src/activesec/core/user_wiki_manager.py) (`sha256:0cfef121c6e2`) |
| **Dedicated Security Test Suite** | [`tests/security/test_sec_user_wiki_manager.py`](../../tests/security/test_sec_user_wiki_manager.py) |
| **AST Static Safety Audit** | **CLEAN (Zero Forbidden Primitives)** |
| **Adversarial Security Verification** | **VERIFIED (PASS)** (3 test vectors) |

---

## 2. Architectural Summary

Maintains a human-friendly, progressive cybersecurity learning wiki in `wiki_user/` that explains discovered code vulnerabilities, social-engineering patterns, and verified fixes in clear language. Starts at beginner-friendly Level 1 and unlocks Level 2 (Secure Engineering) and Level 3 (Adversarial Mastery) as the user resolves cases.

---

## 3. Enforced Deterministic Security Invariants

- Confines all writes strictly inside canonical `wiki_user/` under the repository root and rejects symlinks.
- Scrubs all code snippets and explanations through CredentialGuard.redact_secrets() and blocks Trojan Source Unicode characters.
- Adapts explanation depth automatically across Level 1 (1-2 cases), Level 2 (3-4 cases), and Level 3 (5+ cases).

---

## 4. Dedicated Component Security Tests (`tests/security/test_sec_user_wiki_manager.py`)

| Test Function | Verified Adversarial Vector & Invariant | Status |
| :--- | :--- | :--- |
| `test_sec_user_wiki_progressive_mastery_levels_and_lesson_generation` | [Vector F.1: Human Security Education] Scales explanation complexity from Level 1 (Beginner) to Level 3 (Expert). | **PASS** |
| `test_sec_user_wiki_redacts_secrets_and_strips_trojan_unicode` | [Vector D.2 & B.4: DLP & Trojan Source in User Wiki] Redacts leaked API keys and strips invisible Bidi characters. | **PASS** |
| `test_sec_user_wiki_blocks_outside_root_and_symlinks` | [Vector A.3: Path Containment] Rejects wiki_user directories outside repo_root or symlinked files. | **PASS** |

---

## 5. Known Residual Risks & Defense-in-Depth Pairing

- Educational examples must never be executed directly outside the sandbox (mitigated by storing them only as static markdown documentation).
