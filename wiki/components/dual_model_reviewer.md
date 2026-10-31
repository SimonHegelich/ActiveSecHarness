# Component Security Assessment: `dual_model_reviewer`

> **Auto-Generated & Verified by `WikiManager` (`tools/wiki_sync.py`)** — Do not edit manual status badges directly; update the `ComponentSecurityAssessment` contract in [`src/activesec/harness/dual_model_reviewer.py`](../../src/activesec/harness/dual_model_reviewer.py) or the security test suite in [`tests/security/test_sec_dual_model_reviewer.py`](../../tests/security/test_sec_dual_model_reviewer.py).

---

## 1. Security Posture Metadata

| Attribute | Value |
| :--- | :--- |
| **Component ID** | `dual_model_reviewer` |
| **Title** | Ring-2 Dual-Model Security Reviewer & Self-Healing Repair Orchestrator |
| **Privilege Ring** | **Ring 2** |
| **Mitigated Threat Vectors** | `A.1`, `B.1`, `B.2`, `D.1`, `F.1`, `F.3` |
| **Source File** | [`src/activesec/harness/dual_model_reviewer.py`](../../src/activesec/harness/dual_model_reviewer.py) (`sha256:9adcd9b6609b`) |
| **Dedicated Security Test Suite** | [`tests/security/test_sec_dual_model_reviewer.py`](../../tests/security/test_sec_dual_model_reviewer.py) |
| **AST Static Safety Audit** | **CLEAN (Zero Forbidden Primitives)** |
| **Adversarial Security Verification** | **VERIFIED (PASS)** (1 test vectors) |

---

## 2. Architectural Summary

Combines deterministic LLM-independent CodeVerifier checks (Stage A) with an independent second Reviewer Model (Stage B, defaulting to OpenRouter) in a clean context. Strictly blocks execution of any vulnerable program, explains risks and remediations in accessible plain language for non-experts, recommends stronger models when small local models fail, drives an automated Fix-Test-Verify repair loop, and records lessons into the User Security Academy Wiki (`wiki_user/`).

---

## 3. Enforced Deterministic Security Invariants

- Execution Gate: approved_for_execution is strictly False whenever Stage-A deterministic checks OR Stage-B reviewer model report a vulnerability.
- Context Isolation: The Stage-B reviewer model receives only the target source file and deterministic findings in a fresh context window.
- Model Escalation Recommendation: Automatically recommends a stronger model (e.g. openrouter/qwen/qwen3-coder) when a small local model produces vulnerable code.
- Updates UserWikiManager (`wiki_user/`) with plain-language explanations and before/after code comparisons.

---

## 4. Dedicated Component Security Tests (`tests/security/test_sec_dual_model_reviewer.py`)

| Test Function | Verified Adversarial Vector & Invariant | Status |
| :--- | :--- | :--- |
| `test_sec_dual_model_reviewer_blocks_unsafe_code_and_self_heals` | [Vector B.1, B.2 & F.1: Dual-Model Review & Self-Healing Loop] Blocks unsafe extractall(), explains in plain language, escalates to OpenRouter fixer, and updates wiki_user/. | **PASS** |

---

## 5. Known Residual Risks & Defense-in-Depth Pairing

- If OpenRouter is offline and no API key is configured, Stage B falls back to a local reviewer model while Stage-A deterministic AST and sandbox probes remain 100% enforced.
