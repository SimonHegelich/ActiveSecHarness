# Component Security Assessment: `agent_loop`

> **Auto-Generated & Verified by `tools/wiki_sync.py`** — Do not edit manual status badges directly; update the `ComponentSecurityAssessment` contract in [`src/activesec/harness/agent_loop.py`](../../src/activesec/harness/agent_loop.py) or the security test suite in [`tests/security/test_sec_agent_loop.py`](../../tests/security/test_sec_agent_loop.py).

---

## 1. Security Posture Metadata

| Attribute | Value |
| :--- | :--- |
| **Component ID** | `agent_loop` |
| **Title** | Ring-2 Taint-Tracking Agent Loop & Kernel-Mediated Executor |
| **Privilege Ring** | **Ring 2** |
| **Mitigated Threat Vectors** | `A.1`, `E.2`, `F.2`, `F.3` |
| **Source File** | [`src/activesec/harness/agent_loop.py`](../../src/activesec/harness/agent_loop.py) (`sha256:bddf7ddacd69`) |
| **Dedicated Security Test Suite** | [`tests/security/test_sec_agent_loop.py`](../../tests/security/test_sec_agent_loop.py) |
| **AST Static Safety Audit** | **CLEAN (Zero Forbidden Primitives)** |
| **Adversarial Security Verification** | **VERIFIED (PASS)** (3 test vectors) |

---

## 2. Architectural Summary

Implements a minimal, inspectable Ring-2 agent execution loop inspired by mini-swe-agent. Tracks monotonic prompt-injection taint across untrusted data ingestion, enforces hard step budgets, delegates all LLM calls through ModelGateway, and executes every tool call exclusively via SecurityKernel.

---

## 3. Enforced Deterministic Security Invariants

- Has zero direct filesystem, subprocess, or socket execution primitives; all tool calls pass through SecurityKernel.execute_tool_call().
- Monotonically latches session.context_tainted = True whenever source_trust != 'TRUSTED' data is ingested.
- Propagates context_tainted and active_token to both ModelGateway.chat() and SecurityKernel.execute_tool_call().
- Enforces a hard per-session step limit (max_steps) and immediately halts on CanaryTripwireError.

---

## 4. Dedicated Component Security Tests (`tests/security/test_sec_agent_loop.py`)

| Test Function | Verified Adversarial Vector & Invariant | Status |
| :--- | :--- | :--- |
| `test_sec_agent_loop_taint_propagation_blocks_privileged_tool_call` | [Vector F.2: Prompt Injection Taint Locking] Ingesting UNTRUSTED data latches context_tainted=True and blocks privileged tool calls. | **PASS** |
| `test_sec_agent_loop_halts_immediately_on_canary_tripwire` | [Vector F.2 & C.3: Loop Canary Halt] Immediately halts execution even when halt_on_security_violation=False if a Canary tripwire fires. | **PASS** |
| `test_sec_agent_loop_enforces_max_steps_quota` | [Vector E.2: Agent Step Budget] Rejects execution once session.step_count reaches max_steps. | **PASS** |

---

## 5. Known Residual Risks & Defense-in-Depth Pairing

- An untainted agent may still make non-malicious mistakes within its explicitly permitted workspace subdirectory (mitigated by narrow CapabilityCaveat scoping).
