# ActiveSecHarness – Automated Component Security Ledger (`wiki/SECURITY_LEDGER.md`)

This ledger is automatically compiled and verified by [`tools/wiki_sync.py`](../tools/wiki_sync.py). Every component in `ActiveSecHarness` must declare a `ComponentSecurityAssessment`, pass static AST safety auditing, and pass its dedicated adversarial security test suite (`tests/security/test_sec_*.py`).

---

## Live Component Verification Matrix

| Component | Privilege Ring | Mitigated Threat Vectors | AST Safety Audit | Security Test Status | Source SHA-256 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **[`archive_guard`](components/archive_guard.md)** | Ring 0 | `B.1`, `B.2` | `CLEAN` | **VERIFIED** (4/4 passed) | `31fe4b95ec` |
| **[`capability_token`](components/capability_token.md)** | Ring 0 | `A.1`, `A.3`, `F.2`, `F.3` | `CLEAN` | **VERIFIED** (5/5 passed) | `18f19dda40` |
| **[`credential_guard`](components/credential_guard.md)** | Ring 0 | `D.1`, `D.2`, `D.3` | `CLEAN` | **VERIFIED** (3/3 passed) | `551bc705ce` |
| **[`deobfuscator`](components/deobfuscator.md)** | Ring 1 | `B.4`, `F.1`, `A.1` | `CLEAN` | **VERIFIED** (3/3 passed) | `16d147edb9` |
| **[`network_guard`](components/network_guard.md)** | Ring 0 | `C.1`, `C.2`, `C.3` | `CLEAN` | **VERIFIED** (4/4 passed) | `12291c0db4` |

---

## Summary Metrics

- **Registered Security Components:** 5
- **Dedicated Adversarial Test Vectors Executed:** 19
- **Overall Posture:** ALL COMPONENTS VERIFIED
