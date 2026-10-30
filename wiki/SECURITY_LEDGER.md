# ActiveSecHarness – Automated Component Security Ledger (`wiki/SECURITY_LEDGER.md`)

This ledger is automatically compiled and verified by [`tools/wiki_sync.py`](../tools/wiki_sync.py). Every component in `ActiveSecHarness` must declare a `ComponentSecurityAssessment`, pass static AST safety auditing, and pass its dedicated adversarial security test suite (`tests/security/test_sec_*.py`).

---

## Live Component Verification Matrix

| Component | Privilege Ring | Mitigated Threat Vectors | AST Safety Audit | Security Test Status | Source SHA-256 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **[`agent_loop`](components/agent_loop.md)** | Ring 2 | `A.1`, `E.2`, `F.2`, `F.3` | `CLEAN` | **VERIFIED** (3/3 passed) | `bddf7ddacd` |
| **[`archive_guard`](components/archive_guard.md)** | Ring 0 | `B.1`, `B.2` | `CLEAN` | **VERIFIED** (4/4 passed) | `31fe4b95ec` |
| **[`audit_log`](components/audit_log.md)** | Ring 0 | `A.3`, `B.4`, `D.2`, `F.3` | `CLEAN` | **VERIFIED** (7/7 passed) | `4bcaabbc55` |
| **[`canary_guard`](components/canary_guard.md)** | Ring 0 | `F.2`, `C.3`, `D.2`, `A.1` | `CLEAN` | **VERIFIED** (2/2 passed) | `099fee8359` |
| **[`capability_token`](components/capability_token.md)** | Ring 0 | `A.1`, `A.3`, `F.2`, `F.3` | `CLEAN` | **VERIFIED** (5/5 passed) | `1c68f7c29f` |
| **[`credential_guard`](components/credential_guard.md)** | Ring 0 | `D.1`, `D.2`, `D.3` | `CLEAN` | **VERIFIED** (3/3 passed) | `551bc705ce` |
| **[`deobfuscator`](components/deobfuscator.md)** | Ring 1 | `B.4`, `F.1`, `A.1` | `CLEAN` | **VERIFIED** (3/3 passed) | `16d147edb9` |
| **[`malware_guard`](components/malware_guard.md)** | Ring 0 | `B.3`, `B.4`, `F.2` | `CLEAN` | **VERIFIED** (4/4 passed) | `d8ab2f93f3` |
| **[`model_gateway`](components/model_gateway.md)** | Ring 0 | `A.1`, `A.2`, `B.4`, `C.1`, `C.2`, `C.3`, `D.2`, `E.2`, `F.2` | `CLEAN` | **VERIFIED** (8/8 passed) | `905e358ca1` |
| **[`network_guard`](components/network_guard.md)** | Ring 0 | `C.1`, `C.2`, `C.3` | `CLEAN` | **VERIFIED** (4/4 passed) | `12291c0db4` |
| **[`sandbox_guard`](components/sandbox_guard.md)** | Ring 0 | `A.1`, `A.2`, `E.1`, `E.2`, `E.3` | `CLEAN` | **VERIFIED** (3/3 passed) | `dc16771e6e` |
| **[`security_kernel`](components/security_kernel.md)** | Ring 0 | `A.1`, `A.3`, `A.4`, `B.1`, `B.2`, `B.3`, `B.4`, `C.1`, `C.2`, `C.3`, `D.2`, `E.1`, `F.1`, `F.2`, `F.3` | `CLEAN` | **VERIFIED** (3/3 passed) | `ef0d9a1944` |

---

## Summary Metrics

- **Registered Security Components:** 12
- **Dedicated Adversarial Test Vectors Executed:** 49
- **Overall Posture:** ALL COMPONENTS VERIFIED
