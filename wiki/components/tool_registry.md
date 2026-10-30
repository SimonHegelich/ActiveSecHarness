# Component Security Assessment: `tool_registry`

> **Auto-Generated & Verified by `WikiManager` (`tools/wiki_sync.py`)** — Do not edit manual status badges directly; update the `ComponentSecurityAssessment` contract in [`src/activesec/core/tool_registry.py`](../../src/activesec/core/tool_registry.py) or the security test suite in [`tests/security/test_sec_tool_registry.py`](../../tests/security/test_sec_tool_registry.py).

---

## 1. Security Posture Metadata

| Attribute | Value |
| :--- | :--- |
| **Component ID** | `tool_registry` |
| **Title** | Ring-0 Anti-MCP Tool Certification, Agent Qualification & Combinatorial SoD Engine |
| **Privilege Ring** | **Ring 0** |
| **Mitigated Threat Vectors** | `A.1`, `A.3`, `C.2`, `F.2`, `F.3` |
| **Source File** | [`src/activesec/core/tool_registry.py`](../../src/activesec/core/tool_registry.py) (`sha256:4323ee8c75e6`) |
| **Dedicated Security Test Suite** | [`tests/security/test_sec_tool_registry.py`](../../tests/security/test_sec_tool_registry.py) |
| **AST Static Safety Audit** | **CLEAN (Zero Forbidden Primitives)** |
| **Adversarial Security Verification** | **VERIFIED (PASS)** (5 test vectors) |

---

## 2. Architectural Summary

Replaces dynamic, unverified MCP tool loading with a zero-trust Ring-0 certification and Separation-of-Duties (SoD) engine. Enforces cryptographic ToolCertificates bound to static AST scans and handler bytecode/source SHA-256 hashes (blocking rug-pull and tool-poisoning attacks), requires per-agent AgentToolCertificates covering both individual tools and tested tool combinations, blocks Lethal Trifecta toxic tool combinations at runtime, and deterministically partitions multi-tool workflows across isolated sub-agents with attenuated capability tokens.

---

## 3. Enforced Deterministic Security Invariants

- Every registered tool must carry a Ring-0 HMAC-SHA256 ToolCertificate after passing AST safety inspection and adversarial probes.
- Re-verifies live handler SHA-256 and schema SHA-256 on every invocation to defeat post-certification MCP-style rug-pull mutations.
- Requires a valid, non-expired AgentToolCertificate for the calling agent covering both the individual tool and every pairwise combination with tools previously used in the session.
- Enforces ToxicToolPolicy Separation of Duties (SoD), raising ToxicCombinationError (vector_id='F.3') if an agent combines mutually exclusive tools or side-effect classes (e.g., READ_SENSITIVE + NETWORK_EGRESS).
- Provides deterministic multi-agent workflow partitioning (partition_tool_plan_across_agents) that splits incompatible tool sequences into isolated sub-agents with attenuated CapabilityTokens.

---

## 4. Dedicated Component Security Tests (`tests/security/test_sec_tool_registry.py`)

| Test Function | Verified Adversarial Vector & Invariant | Status |
| :--- | :--- | :--- |
| `test_sec_tool_registry_rejects_uncertified_and_rugpull_tampered_tools` | [Vector A.1: Zero-Trust Tool Certification & Anti-Rug-Pull Defense] Rejects uncertified tools, unsafe AST handlers, and post-certification bytecode/schema tampering. | **PASS** |
| `test_sec_tool_registry_rejects_uncertified_agent_access` | [Vector F.3: Mandatory Agent-Tool Qualification] Blocks an agent lacking a signed AgentToolCertificate even when the tool itself is certified. | **PASS** |
| `test_sec_tool_registry_rejects_uncertified_tool_combinations` | [Vector F.3: Combinatorial Qualification Enforcement] Blocks an agent certified for Tool A and Tool B individually when {Tool A, Tool B} was not combinatorially certified. | **PASS** |
| `test_sec_tool_registry_blocks_lethal_trifecta_toxic_combinations` | [Vector F.3: Separation of Duties / Lethal Trifecta Block] Deterministically blocks an agent attempting to combine fs:read (READ_SENSITIVE) with net:https (NETWORK_EGRESS) in one session. | **PASS** |
| `test_sec_tool_registry_partitions_toxic_plan_across_isolated_sub_agents` | [Vector F.3 & C.2: Deterministic Multi-Agent SoD Partitioning] Splits a workflow containing fs:read + net:https across isolated sub-agents with attenuated capability tokens. | **PASS** |

---

## 5. Known Residual Risks & Defense-in-Depth Pairing

- A single read-only or egress-only sub-agent still operates within its narrow equivalence class (mitigated by CredentialGuard DLP redaction on inter-agent handoffs and NetworkGuard allowlisting).
