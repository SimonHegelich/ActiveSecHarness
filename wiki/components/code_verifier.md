# Component Security Assessment: `code_verifier`

> **Auto-Generated & Verified by `WikiManager` (`tools/wiki_sync.py`)** — Do not edit manual status badges directly; update the `ComponentSecurityAssessment` contract in [`src/activesec/guards/code_verifier.py`](../../src/activesec/guards/code_verifier.py) or the security test suite in [`tests/security/test_sec_code_verifier.py`](../../tests/security/test_sec_code_verifier.py).

---

## 1. Security Posture Metadata

| Attribute | Value |
| :--- | :--- |
| **Component ID** | `code_verifier` |
| **Title** | Ring-0 Deterministic Application Code Verifier & SoD Sandbox Test Runner |
| **Privilege Ring** | **Ring 0** |
| **Mitigated Threat Vectors** | `A.1`, `B.1`, `B.2`, `B.4`, `D.1`, `D.3`, `E.1`, `F.3` |
| **Source File** | [`src/activesec/guards/code_verifier.py`](../../src/activesec/guards/code_verifier.py) (`sha256:4aa68dae80ec`) |
| **Dedicated Security Test Suite** | [`tests/security/test_sec_code_verifier.py`](../../tests/security/test_sec_code_verifier.py) |
| **AST Static Safety Audit** | **CLEAN (Zero Forbidden Primitives)** |
| **Adversarial Security Verification** | **VERIFIED (PASS)** (3 test vectors) |

---

## 2. Architectural Summary

Provides LLM-independent deterministic security verification of agent-generated code before execution release. Combines static AST & contextual invariant analysis (blocking extractall, eval, shell=True, pickle, weak random secrets, and missing realpath/quota checks) with an isolated Separation-of-Duties (SoD) test-runner sub-agent that executes real adversarial attack payloads (Zip-Slip and ZipBomb probes) inside SandboxGuard.

---

## 3. Enforced Deterministic Security Invariants

- Deterministically rejects application code containing extractall(), eval(), exec(), os.system(), subprocess(..., shell=True), pickle, or Trojan Source Unicode.
- Enforces contextual archive safety invariants: modules importing zipfile or tarfile must include canonical path resolution (realpath/resolve) and size/ratio bounds.
- Uses CertifiedToolRegistry.partition_tool_plan_across_agents() to isolate test execution into a dedicated SoD sub-agent holding an attenuated shell:exec token with zero network access.
- Blocks execution approval whenever any static AST rule or dynamic sandbox attack probe fails.

---

## 4. Dedicated Component Security Tests (`tests/security/test_sec_code_verifier.py`)

| Test Function | Verified Adversarial Vector & Invariant | Status |
| :--- | :--- | :--- |
| `test_sec_code_verifier_blocks_unsafe_extractall_live_case` | [Vector B.1 & B.2: Unsafe Generated Zip Extractor] Blocks extractall() via AST rules and live Zip-Slip/ZipBomb sandbox probes. | **PASS** |
| `test_sec_code_verifier_approves_hardened_streaming_zip_extractor` | [Vector B.1 & B.2: Verified Safe Extractor] Approves streaming extractor that enforces realpath and ratio/byte quotas. | **PASS** |
| `test_sec_code_verifier_detects_eval_shell_true_pickle_and_weak_random` | [Vector A.1, B.3 & D.3: Unsafe Primitives] Detects eval, shell=True, pickle, and random password generation. | **PASS** |

---

## 5. Known Residual Risks & Defense-in-Depth Pairing

- Complex domain-specific business logic flaws that do not violate structural AST invariants or standard adversarial probes (mitigated by pairing with Stage-B DualModelReviewer).
