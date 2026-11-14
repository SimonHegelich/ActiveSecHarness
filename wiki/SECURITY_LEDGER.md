# ActiveSecHarness – Automated Component Security Ledger (`wiki/SECURITY_LEDGER.md`)

This ledger is automatically compiled and verified by `WikiManager` ([`src/activesec/core/wiki_manager.py`](../src/activesec/core/wiki_manager.py) & [`tools/wiki_sync.py`](../tools/wiki_sync.py)). Every component in `ActiveSecHarness` must declare a `ComponentSecurityAssessment`, pass static AST safety auditing, and pass its dedicated adversarial security test suite (`tests/security/test_sec_*.py`).

---

## Live Component Verification Matrix

| Component | Privilege Ring | Mitigated Threat Vectors | AST Safety Audit | Security Test Status | Source SHA-256 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **[`agent_loop`](components/agent_loop.md)** | Ring 2 | `A.1`, `E.2`, `F.2`, `F.3` | `CLEAN` | **VERIFIED** (3/3 passed) | `b424df040e` |
| **[`archive_guard`](components/archive_guard.md)** | Ring 0 | `B.1`, `B.2` | `CLEAN` | **VERIFIED** (6/6 passed) | `bcabc5927a` |
| **[`audit_log`](components/audit_log.md)** | Ring 0 | `A.3`, `B.4`, `D.2`, `F.3` | `CLEAN` | **VERIFIED** (7/7 passed) | `2faea491ef` |
| **[`canary_guard`](components/canary_guard.md)** | Ring 0 | `F.2`, `C.3`, `D.2`, `A.1` | `CLEAN` | **VERIFIED** (2/2 passed) | `099fee8359` |
| **[`capability_token`](components/capability_token.md)** | Ring 0 | `A.1`, `A.3`, `F.2`, `F.3` | `CLEAN` | **VERIFIED** (7/7 passed) | `2534b54386` |
| **[`code_verifier`](components/code_verifier.md)** | Ring 0 | `A.1`, `B.1`, `B.2`, `B.4`, `D.1`, `D.3`, `E.1`, `F.3` | `CLEAN` | **VERIFIED** (5/5 passed) | `ed244a7426` |
| **[`credential_guard`](components/credential_guard.md)** | Ring 0 | `D.1`, `D.2`, `D.3` | `CLEAN` | **VERIFIED** (4/4 passed) | `6cb410bdfe` |
| **[`deobfuscator`](components/deobfuscator.md)** | Ring 1 | `B.4`, `F.1`, `A.1` | `CLEAN` | **VERIFIED** (4/4 passed) | `49f4506b0a` |
| **[`dual_model_reviewer`](components/dual_model_reviewer.md)** | Ring 2 | `A.1`, `B.1`, `B.2`, `D.1`, `F.1`, `F.3` | `CLEAN` | **VERIFIED** (4/4 passed) | `559703ca90` |
| **[`malware_guard`](components/malware_guard.md)** | Ring 0 | `B.3`, `B.4`, `F.2` | `CLEAN` | **VERIFIED** (5/5 passed) | `80a549c454` |
| **[`model_gateway`](components/model_gateway.md)** | Ring 0 | `A.1`, `A.2`, `B.4`, `C.1`, `C.2`, `C.3`, `D.2`, `E.2`, `F.2` | `CLEAN` | **VERIFIED** (8/8 passed) | `33a8733c25` |
| **[`network_guard`](components/network_guard.md)** | Ring 0 | `C.1`, `C.2`, `C.3` | `CLEAN` | **VERIFIED** (6/6 passed) | `06121f27f2` |
| **[`sandbox_guard`](components/sandbox_guard.md)** | Ring 0 | `A.1`, `A.2`, `E.1`, `E.2`, `E.3` | `CLEAN` | **VERIFIED** (5/5 passed) | `4a6f849343` |
| **[`security_kernel`](components/security_kernel.md)** | Ring 0 | `A.1`, `A.3`, `A.4`, `B.1`, `B.2`, `B.3`, `B.4`, `C.1`, `C.2`, `C.3`, `D.2`, `E.1`, `F.1`, `F.2`, `F.3` | `CLEAN` | **VERIFIED** (7/7 passed) | `d4ef863ac3` |
| **[`sod_policy`](components/sod_policy.md)** | Ring 0 | `C.2`, `D.2`, `F.2`, `F.3` | `CLEAN` | **VERIFIED** (6/6 passed) | `9660add33a` |
| **[`test_synthesizer`](components/test_synthesizer.md)** | Ring 2 | `A.1`, `B.2`, `F.1`, `F.3` | `CLEAN` | **VERIFIED** (2/2 passed) | `0d6674a774` |
| **[`tool_registry`](components/tool_registry.md)** | Ring 0 | `A.1`, `A.3`, `C.2`, `F.2`, `F.3` | `CLEAN` | **VERIFIED** (5/5 passed) | `ecc138758d` |
| **[`user_wiki_manager`](components/user_wiki_manager.md)** | Ring 1 | `F.1`, `D.2`, `B.4`, `A.3` | `CLEAN` | **VERIFIED** (3/3 passed) | `0cfef121c6` |
| **[`wiki_manager`](components/wiki_manager.md)** | Ring 0 | `A.1`, `A.3`, `B.4`, `F.3` | `CLEAN` | **VERIFIED** (4/4 passed) | `3500a87801` |

---

## Summary Metrics

- **Registered Security Components:** 19
- **Dedicated Adversarial Test Vectors Executed:** 93 (of 93 discovered)
- **Overall Posture:** ALL COMPONENTS VERIFIED
