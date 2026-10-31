# Component Security Assessment: `wiki_manager`

> **Auto-Generated & Verified by `WikiManager` (`tools/wiki_sync.py`)** — Do not edit manual status badges directly; update the `ComponentSecurityAssessment` contract in [`src/activesec/core/wiki_manager.py`](../../src/activesec/core/wiki_manager.py) or the security test suite in [`tests/security/test_sec_wiki_manager.py`](../../tests/security/test_sec_wiki_manager.py).

---

## 1. Security Posture Metadata

| Attribute | Value |
| :--- | :--- |
| **Component ID** | `wiki_manager` |
| **Title** | Ring-0 Karpathy Security Wiki Compiler & Runtime Telemetry Synchronizer |
| **Privilege Ring** | **Ring 0** |
| **Mitigated Threat Vectors** | `A.1`, `A.3`, `B.4`, `F.3` |
| **Source File** | [`src/activesec/core/wiki_manager.py`](../../src/activesec/core/wiki_manager.py) (`sha256:493fb7f3ff96`) |
| **Dedicated Security Test Suite** | [`tests/security/test_sec_wiki_manager.py`](../../tests/security/test_sec_wiki_manager.py) |
| **AST Static Safety Audit** | **CLEAN (Zero Forbidden Primitives)** |
| **Adversarial Security Verification** | **VERIFIED (PASS)** (3 test vectors) |

---

## 2. Architectural Summary

Natively embeds Andrej Karpathy's Living Security Wiki into Ring 0 of the ActiveSecHarness runtime. Performs static Python AST safety and Trojan Source auditing across all registered SecureComponent modules, verifies source SHA-256 hashes against the ledger to detect post-verification tampering, executes component security test suites, and streams verified runtime telemetry from HashChainedAuditLog directly into wiki/SECURITY_LEDGER.md, wiki/components/*.md, and wiki/log.md.

---

## 3. Enforced Deterministic Security Invariants

- Statically scans every component AST for forbidden unsafe calls (eval, exec, extractall, system, popen, shell=True, pickle, marshal) and Trojan Source Unicode characters.
- Confines all wiki file writes strictly within the canonical repository root (os.path.realpath) and rejects symlinked wiki targets.
- Verifies HashChainedAuditLog cryptographic chain integrity before recording any runtime security telemetry snapshot into the Wiki.
- Detects unauthorized component source modifications by comparing live SHA-256 digests against pinned ledger fingerprints.

---

## 4. Dedicated Component Security Tests (`tests/security/test_sec_wiki_manager.py`)

| Test Function | Verified Adversarial Vector & Invariant | Status |
| :--- | :--- | :--- |
| `test_sec_wiki_manager_detects_forbidden_ast_primitives_and_trojan_unicode` | [Vector A.1 & B.4: AST Safety & Trojan Source Audit] Rejects eval, exec, pickle, shell=True, and Trojan Unicode in Python ASTs. | **PASS** |
| `test_sec_wiki_manager_detects_component_sha256_tampering_and_outside_root` | [Vector A.3: Component Source Tampering & Path Confinement] Detects SHA-256 digest drift against pinned hashes and blocks out-of-repo wiki paths. | **PASS** |
| `test_sec_wiki_manager_rejects_tampered_audit_log_and_syncs_runtime_telemetry` | [Vector A.3 & F.3: Runtime Telemetry & Audit Verification] Rejects tampered audit chains and automatically syncs AgentLoop runtime telemetry. | **PASS** |

---

## 5. Known Residual Risks & Defense-in-Depth Pairing

- Static AST analysis inspects syntactic call nodes within registered Python files; dynamic runtime enforcement is paired with SandboxGuard and CertifiedToolRegistry.
