# Component Security Assessment: `sandbox_guard`

> **Auto-Generated & Verified by `WikiManager` (`tools/wiki_sync.py`)** — Do not edit manual status badges directly; update the `ComponentSecurityAssessment` contract in [`src/activesec/guards/sandbox_guard.py`](../../src/activesec/guards/sandbox_guard.py) or the security test suite in [`tests/security/test_sec_sandbox_guard.py`](../../tests/security/test_sec_sandbox_guard.py).

---

## 1. Security Posture Metadata

| Attribute | Value |
| :--- | :--- |
| **Component ID** | `sandbox_guard` |
| **Title** | Ring-0 Namespace Sandbox, Clean-Room Environment & Resource Quota Guard |
| **Privilege Ring** | **Ring 0** |
| **Mitigated Threat Vectors** | `A.1`, `A.2`, `E.1`, `E.2`, `E.3` |
| **Source File** | [`src/activesec/guards/sandbox_guard.py`](../../src/activesec/guards/sandbox_guard.py) (`sha256:3a282d50ee0b`) |
| **Dedicated Security Test Suite** | [`tests/security/test_sec_sandbox_guard.py`](../../tests/security/test_sec_sandbox_guard.py) |
| **AST Static Safety Audit** | **CLEAN (Zero Forbidden Primitives)** |
| **Adversarial Security Verification** | **VERIFIED (PASS)** (4 test vectors) |

---

## 2. Architectural Summary

Isolates all agent subprocess executions using clean-room environment scrubbing, binary allowlisting, bubblewrap (bwrap) Linux namespaces (--unshare-all, --die-with-parent), unmounted host home directories, and OS resource limits (RLIMIT_NPROC, RLIMIT_FSIZE) against fork bombs and container escapes.

---

## 3. Enforced Deterministic Security Invariants

- Never executes commands with shell=True; requires an explicit sequence of arguments.
- Scrubs os.environ completely: API keys, tokens, DISPLAY, WAYLAND_DISPLAY, DBUS, and SSH_AUTH_SOCK are stripped before spawning.
- Blocks mounting of sensitive host paths (/var/run/docker.sock, /etc/shadow, ~/.ssh) into the sandbox.
- Builds bubblewrap command lines with --unshare-all, --die-with-parent, --new-session, read-only /usr /bin /lib, and isolated --tmpfs /tmp.
- Enforces close_fds=True and hard wall-clock timeouts on every subprocess.

---

## 4. Dedicated Component Security Tests (`tests/security/test_sec_sandbox_guard.py`)

| Test Function | Verified Adversarial Vector & Invariant | Status |
| :--- | :--- | :--- |
| `test_sec_clean_room_environment_strips_host_secrets` | [Vector A.2: Subprocess Environment Leak] Scrubs OPENAI_API_KEY, SSH_AUTH_SOCK, and DISPLAY from subprocesses. | **PASS** |
| `test_sec_forbidden_docker_socket_and_ssh_mounts_blocked` | [Vector E.1: Container/Sandbox Escape] Blocks mounting /var/run/docker.sock, /etc/shadow, or ~/.ssh. | **PASS** |
| `test_sec_unauthorized_lotl_binary_and_timeout_enforced` | [Vector A.1 & E.2: LotL Binary & Resource Exhaustion] Blocks unapproved binaries and terminates hung processes. | **PASS** |
| `test_sec_gtfobins_disallowed_binary_flags_blocked` | [Vector E.3: Disallowed Binary Flags] Blocks GTFOBins flag escapes on allowlisted binaries. | **PASS** |

---

## 5. Known Residual Risks & Defense-in-Depth Pairing

- Unprivileged user namespaces may be restricted by host sysctl (kernel.unprivileged_userns_clone=0); when require_bwrap=True is set, SandboxGuard fails closed rather than falling back.
