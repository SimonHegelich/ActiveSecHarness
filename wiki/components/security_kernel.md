# Component Security Assessment: `security_kernel`

> **Auto-Generated & Verified by `WikiManager` (`tools/wiki_sync.py`)** — Do not edit manual status badges directly; update the `ComponentSecurityAssessment` contract in [`src/activesec/core/security_kernel.py`](../../src/activesec/core/security_kernel.py) or the security test suite in [`tests/security/test_sec_security_kernel.py`](../../tests/security/test_sec_security_kernel.py).

---

## 1. Security Posture Metadata

| Attribute | Value |
| :--- | :--- |
| **Component ID** | `security_kernel` |
| **Title** | Ring-0 Security Kernel & Complete Mediation Reference Monitor |
| **Privilege Ring** | **Ring 0** |
| **Mitigated Threat Vectors** | `A.1`, `A.3`, `A.4`, `B.1`, `B.2`, `B.3`, `B.4`, `C.1`, `C.2`, `C.3`, `D.2`, `E.1`, `F.1`, `F.2`, `F.3` |
| **Source File** | [`src/activesec/core/security_kernel.py`](../../src/activesec/core/security_kernel.py) (`sha256:3fd195d346ed`) |
| **Dedicated Security Test Suite** | [`tests/security/test_sec_security_kernel.py`](../../tests/security/test_sec_security_kernel.py) |
| **AST Static Safety Audit** | **CLEAN (Zero Forbidden Primitives)** |
| **Adversarial Security Verification** | **VERIFIED (PASS)** (3 test vectors) |

---

## 2. Architectural Summary

Acts as the non-bypassable Ring-0 reference monitor between the agent loop and host resources. Enforces CanaryGuard tripwire checks, CapabilityToken verification, CommandDeobfuscator inspection, deterministic guard dispatch (CredentialGuard, MalwareGuard, ArchiveGuard, NetworkGuard, SandboxGuard), and tamper-evident HashChainedAuditLog recording on every single tool request.

---

## 3. Enforced Deterministic Security Invariants

- Evaluates CanaryGuard tripwires on target paths, raw commands, and arguments before touching any resource, revoking the active token on violation.
- Verifies CapabilityToken signatures, revocation state, TTL, call quota, path confinement, allowed binaries, and 5-level InformationClass taint lattice via CapabilityEngine.
- Enforces Compositional Cross-Agent Separation of Duties via WorkspaceProvenanceLedger, tracking per-file provenance labels l(f) on workspace writes and propagating taint/sensitivity across collaborating agents.
- Runs CommandDeobfuscator.inspect_command(..., fail_on_critical=True) on all shell:exec requests and rejects shell=True.
- Scans files with MalwareGuard before fs:read or after fs:write/archive:extract, and enforces CredentialGuard DLP on both read (redaction) and write (blocking).
- Appends an immutable, cryptographically signed AuditLogEntry for every allowed or blocked tool invocation.

---

## 4. Dedicated Component Security Tests (`tests/security/test_sec_security_kernel.py`)

| Test Function | Verified Adversarial Vector & Invariant | Status |
| :--- | :--- | :--- |
| `test_sec_kernel_canary_tripwire_revokes_token_and_logs_alert` | [Vector F.2 & A.1: Canary Tripwire Revocation] Accessing a honeyfile via SecurityKernel revokes the token and logs CANARY_TRIPWIRE_ALERT. | **PASS** |
| `test_sec_kernel_blocks_obfuscated_and_lotl_shell_commands` | [Vector F.1 & B.4: Deobfuscator Mediation] Blocks Base64-obfuscated and curl|sh commands before SandboxGuard execution. | **PASS** |
| `test_sec_kernel_enforces_dlp_and_malware_guards_on_fs_read_write` | [Vector D.2 & B.3: File DLP & Malware Mediation] Redacts secrets on fs:read, blocks cleartext secrets on fs:write, and blocks EICAR malware. | **PASS** |

---

## 5. Known Residual Risks & Defense-in-Depth Pairing

- Logic bugs within an explicitly authorized workspace script executed inside the sandbox (mitigated by bubblewrap namespace isolation and offline network default).
