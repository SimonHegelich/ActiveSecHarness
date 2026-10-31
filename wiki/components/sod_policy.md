# Component Security Assessment: `sod_policy`

> **Auto-Generated & Verified by `WikiManager` (`tools/wiki_sync.py`)** — Do not edit manual status badges directly; update the `ComponentSecurityAssessment` contract in [`src/activesec/core/sod_policy.py`](../../src/activesec/core/sod_policy.py) or the security test suite in [`tests/security/test_sec_sod_policy.py`](../../tests/security/test_sec_sod_policy.py).

---

## 1. Security Posture Metadata

| Attribute | Value |
| :--- | :--- |
| **Component ID** | `sod_policy` |
| **Title** | Ring-0 Workspace Provenance Ledger & Compositional Multi-Agent SoD Engine |
| **Privilege Ring** | **Ring 0** |
| **Mitigated Threat Vectors** | `C.2`, `D.2`, `F.2`, `F.3` |
| **Source File** | [`src/activesec/core/sod_policy.py`](../../src/activesec/core/sod_policy.py) (`sha256:2cb45aa56243`) |
| **Dedicated Security Test Suite** | [`tests/security/test_sec_sod_policy.py`](../../tests/security/test_sec_sod_policy.py) |
| **AST Static Safety Audit** | **CLEAN (Zero Forbidden Primitives)** |
| **Adversarial Security Verification** | **VERIFIED (PASS)** (3 test vectors) |

---

## 2. Architectural Summary

Enforces compositional Information-Flow Control (IFC) and Separation of Duties (SoD) across collaborating agents sharing a workspace filesystem. Tracks per-file provenance labels l(f) in the 5-level InformationClass lattice and propagates both taint and side-effect origins (READ_SENSITIVE, READ_EXTERNAL) whenever an agent writes to and another agent reads from shared workspace files, defeating multi-agent laundering of the Lethal Trifecta unless explicitly declassified to SANITIZED.

---

## 3. Enforced Deterministic Security Invariants

- Every workspace write by Agent A updates the canonical file's provenance record l(f) = l_prev(f) join tau(A) and unions Agent A's side-effect history Sigma(f) = Sigma_prev(f) U Sigma_A.
- Every workspace read of file f by Agent B updates Agent B's flow state tau(B) = tau(B) join l(f) and Sigma_B = Sigma_B U Sigma(f).
- Blocks any cross-agent Lethal Trifecta where Agent A reads sensitive or untrusted external data, writes it to a workspace staging file, and Agent B reads that file and attempts NETWORK_EGRESS or arbitrary EXEC_PROCESS.
- Permits DERIVED taint workflows (e.g., summarizing an issue into code edits and running isolated pytest/unittest) while blocking arbitrary shell escapes and network exfiltration.
- Requires explicit Ring-0/1 deterministic declassification (declassify_artifact -> SANITIZED) before sensitive or untrusted workspace artifacts can be transmitted externally.

---

## 4. Dedicated Component Security Tests (`tests/security/test_sec_sod_policy.py`)

| Test Function | Verified Adversarial Vector & Invariant | Status |
| :--- | :--- | :--- |
| `test_sec_compositional_sod_blocks_cross_agent_workspace_secret_laundering` | [Vector F.3: Cross-Agent Workspace Laundering Block] Agent A (READ_SENSITIVE -> fs:write) + Agent B (fs:read -> net:https) is deterministically blocked as a compositional Lethal Trifecta. | **PASS** |
| `test_sec_compositional_sod_blocks_cross_agent_untrusted_shell_laundering` | [Vector F.2 & F.3: Cross-Agent Untrusted Injection Laundering] Agent A reads untrusted external payload and writes to workspace; Agent B reads it and is blocked from arbitrary shell:exec. | **PASS** |
| `test_sec_derived_taint_and_explicit_declassification_preserve_swe_workflows` | [Vector F.2 & F.3: DERIVED Taint SWE Usability & Ring-1 Declassification] Verifies that DERIVED taint permits workspace code edits and isolated pytest runs, and Ring-1 declassification (SANITIZED) permits safe handoff. | **PASS** |

---

## 5. Known Residual Risks & Defense-in-Depth Pairing

- Covert timing channels across process scheduling (mitigated by sequential Ring-0 kernel mediation and deterministic timeout budgets).
