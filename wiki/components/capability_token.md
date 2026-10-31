# Component Security Assessment: `capability_token`

> **Auto-Generated & Verified by `WikiManager` (`tools/wiki_sync.py`)** — Do not edit manual status badges directly; update the `ComponentSecurityAssessment` contract in [`src/activesec/core/capability_token.py`](../../src/activesec/core/capability_token.py) or the security test suite in [`tests/security/test_sec_capability_token.py`](../../tests/security/test_sec_capability_token.py).

---

## 1. Security Posture Metadata

| Attribute | Value |
| :--- | :--- |
| **Component ID** | `capability_token` |
| **Title** | Ring-0 Sudo Capability Token, 5-Level IFC Lattice & Attenuation Engine |
| **Privilege Ring** | **Ring 0** |
| **Mitigated Threat Vectors** | `A.1`, `A.3`, `F.2`, `F.3` |
| **Source File** | [`src/activesec/core/capability_token.py`](../../src/activesec/core/capability_token.py) (`sha256:39fc1268d392`) |
| **Dedicated Security Test Suite** | [`tests/security/test_sec_capability_token.py`](../../tests/security/test_sec_capability_token.py) |
| **AST Static Safety Audit** | **CLEAN (Zero Forbidden Primitives)** |
| **Adversarial Security Verification** | **VERIFIED (PASS)** (6 test vectors) |

---

## 2. Architectural Summary

Enforces cryptographic sudo capability chains with Macaroon-style chained HMAC-SHA256 signatures, monotonic attenuation on sub-agent delegation, canonical path confinement, atomic call-quota/nonce tracking, parent-chain binding, and a 5-level Information-Flow Taint Lattice (TRUSTED, SANITIZED, DERIVED, UNTRUSTED, SENSITIVE) with fine-grained action-class permissions.

---

## 3. Enforced Deterministic Security Invariants

- All tokens are signed with a >=256-bit Ring-0 secret using constant-time hmac.compare_digest.
- Delegation strictly narrows authority: Child tools, binaries, network targets, paths, TTL, quotas, and max_information_class must be a mathematical subset of the parent token.
- Canonical path resolution (os.path.realpath) prevents ../ traversal and protects Ring-0 harness source and dotfiles.
- Enforces the 5-level InformationClass lattice: DERIVED taint permits workspace read/write and isolated pytest/unittest runs while blocking arbitrary shell escapes and network egress; UNTRUSTED and SENSITIVE contexts block privileged execution and exfiltration.
- Tracks per-call nonces and transitive parent-chain quotas atomically to defeat replay and sub-token quota amplification.

---

## 4. Dedicated Component Security Tests (`tests/security/test_sec_capability_token.py`)

| Test Function | Verified Adversarial Vector & Invariant | Status |
| :--- | :--- | :--- |
| `test_sec_forged_signature_rejected` | [Vector A.3: Harness Tampering] Rejects tokens with tampered caveats or forged HMAC signatures. | **PASS** |
| `test_sec_monotonic_attenuation_blocks_privilege_escalation` | [Vector F.3: Confused Deputy / Privilege Escalation] Child delegation cannot expand parent scope. | **PASS** |
| `test_sec_tainted_context_blocks_privileged_execution` | [Vector F.2: Indirect Prompt Injection] Blocks tool execution when agent context becomes tainted. | **PASS** |
| `test_sec_denied_paths_and_traversal_blocked` | [Vector A.4: Persistence Injection] Blocks writes to .git/hooks, .env, and ../ traversal. | **PASS** |
| `test_sec_revocation_and_quota_enforcement` | [Vector A.1: LotL Misuse] Enforces call quotas and immediate parent-chain revocation. | **PASS** |
| `test_sec_five_level_ifc_lattice_and_derived_test_usability` | [Vector F.2: 5-Level Information-Flow Taint Lattice] DERIVED taint permits workspace read/write and isolated pytest/unittest while blocking arbitrary shell and network egress. | **PASS** |

---

## 5. Known Residual Risks & Defense-in-Depth Pairing

- In-process memory disclosure if untrusted native C extensions run inside the Ring-0 Python interpreter process (mitigated by running tools in isolated bwrap subprocesses).
