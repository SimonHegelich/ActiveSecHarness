# Component Security Assessment: `code_verifier`

> **Auto-Generated & Verified by `WikiManager` (`tools/wiki_sync.py`)** — Do not edit manual status badges directly; update the `ComponentSecurityAssessment` contract in [`src/activesec/guards/code_verifier.py`](../../src/activesec/guards/code_verifier.py) or the security test suite in [`tests/security/test_sec_code_verifier.py`](../../tests/security/test_sec_code_verifier.py).

---

## 1. Security Posture Metadata

| Attribute | Value |
| :--- | :--- |
| **Component ID** | `code_verifier` |
| **Title** | Ring-0 3-Tier Context-Sensitive Code Verifier & SoD Sandbox Test Runner |
| **Privilege Ring** | **Ring 0** |
| **Mitigated Threat Vectors** | `A.1`, `B.1`, `B.2`, `B.4`, `D.1`, `D.3`, `E.1`, `F.3` |
| **Source File** | [`src/activesec/guards/code_verifier.py`](../../src/activesec/guards/code_verifier.py) (`sha256:7d7f804964e7`) |
| **Dedicated Security Test Suite** | [`tests/security/test_sec_code_verifier.py`](../../tests/security/test_sec_code_verifier.py) |
| **AST Static Safety Audit** | **CLEAN (Zero Forbidden Primitives)** |
| **Adversarial Security Verification** | **VERIFIED (PASS)** (4 test vectors) |

---

## 2. Architectural Summary

Provides LLM-independent deterministic security verification across a 3-Tier scoping model (Tier 1 Universal Invariants, Tier 2 Context/Dataflow-Sensitive Rules such as permitting extractall() after pre-validated infolist checks or on self-created archives or Ring-1 ContextWaivers, and Tier 3 Task-Scoped Synthesized Probes) executed by an isolated Separation-of-Duties (SoD) test-runner sub-agent inside SandboxGuard.

---

## 3. Enforced Deterministic Security Invariants

- Tier 1 Universal: Always blocks eval(), exec(), os.system(), subprocess(..., shell=True), pickle/marshal, and Trojan Source Unicode.
- Tier 2 Contextual: Blocks unvalidated extractall(), but permits extractall() when AST dataflow proves prior infolist()/namelist() path+quota validation, self-created local archives, or a Ring-1 ContextWaiver.
- Tier 3 Task-Scoped: Executes synthesized regression tests strictly against their target file unless explicitly promoted to the domain catalog.
- Isolates all dynamic test execution into a dedicated SoD sub-agent holding an attenuated shell:exec token with zero network access.

---

## 4. Dedicated Component Security Tests (`tests/security/test_sec_code_verifier.py`)

| Test Function | Verified Adversarial Vector & Invariant | Status |
| :--- | :--- | :--- |
| `test_sec_code_verifier_blocks_unsafe_extractall_live_case` | [Vector B.1 & B.2: Unsafe Generated Zip Extractor] Blocks unvalidated extractall() via AST rules and live Zip-Slip/ZipBomb sandbox probes. | **PASS** |
| `test_sec_code_verifier_permits_contextually_safe_extractall_and_waivers` | [Vector B.1 & B.2: Contextual Tier-2 Scoping] Permits extractall() when pre-validated with infolist+realpath+quota or Ring-1 waiver. | **PASS** |
| `test_sec_code_verifier_approves_hardened_streaming_zip_extractor` | [Vector B.1 & B.2: Verified Safe Extractor] Approves streaming extractor that enforces realpath and ratio/byte quotas. | **PASS** |
| `test_sec_code_verifier_detects_eval_shell_true_pickle_and_weak_random` | [Vector A.1, B.3 & D.3: Unsafe Primitives] Detects eval, shell=True, pickle, and random password generation. | **PASS** |

---

## 5. Known Residual Risks & Defense-in-Depth Pairing

- Complex domain-specific business logic flaws not yet covered by a Tier-3 probe (mitigated by Stage-B DualModelReviewer + automatic SecurityTestSynthesizer).
