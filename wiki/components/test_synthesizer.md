# Component Security Assessment: `test_synthesizer`

> **Auto-Generated & Verified by `WikiManager` (`tools/wiki_sync.py`)** — Do not edit manual status badges directly; update the `ComponentSecurityAssessment` contract in [`src/activesec/harness/test_synthesizer.py`](../../src/activesec/harness/test_synthesizer.py) or the security test suite in [`tests/security/test_sec_test_synthesizer.py`](../../tests/security/test_sec_test_synthesizer.py).

---

## 1. Security Posture Metadata

| Attribute | Value |
| :--- | :--- |
| **Component ID** | `test_synthesizer` |
| **Title** | Ring-2 Verified Security Test Synthesizer (Red-Green-Benign Triad) |
| **Privilege Ring** | **Ring 2** |
| **Mitigated Threat Vectors** | `A.1`, `B.2`, `F.1`, `F.3` |
| **Source File** | [`src/activesec/harness/test_synthesizer.py`](../../src/activesec/harness/test_synthesizer.py) (`sha256:0d6674a77498`) |
| **Dedicated Security Test Suite** | [`tests/security/test_sec_test_synthesizer.py`](../../tests/security/test_sec_test_synthesizer.py) |
| **AST Static Safety Audit** | **CLEAN (Zero Forbidden Primitives)** |
| **Adversarial Security Verification** | **VERIFIED (PASS)** (2 test vectors) |

---

## 2. Architectural Summary

Develops new deterministic security probe scripts whenever the Reviewer Model identifies a vulnerability not yet covered by existing deterministic probes. Enforces the Red-Green-Benign Verification Triad inside SandboxGuard so hallucinated or overly broad tests are rejected, and scopes verified tests task-locally until promoted by Ring 1.

---

## 3. Enforced Deterministic Security Invariants

- Audits every synthesized test script with audit_python_ast_source() before execution.
- Enforces Proof 1 (RED): The synthesized test must fail (exit non-zero) against the vulnerable code draft.
- Enforces Proof 2 (BENIGN-SAFE): The synthesized test must pass (exit zero) on normal benign inputs to prevent false-positive over-blocking.
- Enforces Proof 3 (GREEN): After code repair, verify_green_on_repaired() confirms the fixed code passes the adversarial probe.
- Scopes synthesized tests task-locally (TIER3_TASK_SCOPED) by default; promotion to the global catalog requires explicit Ring-1 authorization.

---

## 4. Dedicated Component Security Tests (`tests/security/test_sec_test_synthesizer.py`)

| Test Function | Verified Adversarial Vector & Invariant | Status |
| :--- | :--- | :--- |
| `test_sec_synthesizer_enforces_red_green_benign_triad_and_task_scope` | [Vector B.2 & F.3: Red-Green-Benign Test Synthesis] Synthesizes a deterministic probe, verifies Red+Benign+Green, and scopes it to the target file. | **PASS** |
| `test_sec_synthesizer_rejects_broken_or_always_failing_tests` | [Vector A.1: Anti-Hallucination Gate] Rejects synthesized tests that fail on benign inputs or use unsafe AST primitives. | **PASS** |

---

## 5. Known Residual Risks & Defense-in-Depth Pairing

- If a weak local model fails to synthesize a valid Red+Benign probe within max_attempts, the synthesizer safely discards the candidate test rather than registering a broken test.
