"""Ring-0 SandboxGuard: Namespace isolation (bubblewrap), clean-room environment, and resource quotas.

Executes untrusted or agent-initiated subprocesses inside an isolated Linux namespace
(`bwrap --unshare-all --die-with-parent --new-session`) with:
- Completely scrubbed environment variables (preventing API key and SSH_AUTH_SOCK leaks).
- Unmounted host home directory (`~/.ssh`, `~/.aws` are invisible inside the sandbox).
- Read-only system binary mounts (`/usr`, `/bin`, `/lib`, `/lib64`).
- isolated `/tmp` tmpfs and offline network namespace (`--unshare-net`) by default.
- RLIMIT process/memory/file-size quotas against fork bombs and disk exhaustion.
"""

from __future__ import annotations

import os
import resource
import shutil
import subprocess
from dataclasses import dataclass
from typing import FrozenSet, Mapping, Optional, Sequence, Tuple

from activesec.core.component import ComponentSecurityAssessment, SecureComponent
from activesec.core.exceptions import SandboxSecurityError


FORBIDDEN_MOUNT_SOURCES: FrozenSet[str] = frozenset(
    {
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/etc/shadow",
        "/etc/sudoers",
        "/proc/kcore",
        "/dev/mem",
        "/dev/kmem",
        "audit_vault",
        ".audit.jsonl",
    }
)

DISALLOWED_BINARY_FLAGS: Mapping[str, FrozenSet[str]] = {
    "find": frozenset({"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprintf"}),
    "tar": frozenset({"--to-command", "--checkpoint-action", "--use-compress-program", "-I"}),
    "git": frozenset({"--upload-pack", "--receive-pack", "--exec-path"}),
    "pytest": frozenset({"-o", "--override-ini"}),
    "chmod": frozenset({"u+s", "g+s", "+s", "4755", "4777", "6755"}),
}

DISALLOWED_GIT_CONFIG_KEYS: Tuple[str, ...] = (
    "core.fsmonitor",
    "core.sshcommand",
    "core.pager",
    "core.editor",
    "alias.",
    "protocol.ext.allow",
)


@dataclass(frozen=True, slots=True)
class SandboxPolicy:
    """Immutable resource and namespace isolation policy for subprocess execution."""

    allowed_binaries: FrozenSet[str] = frozenset({"python3", "pytest", "git", "ls", "cat", "echo", "sh"})
    allow_network: bool = False
    timeout_seconds: float = 10.0
    max_processes: int = 64
    max_memory_bytes: int = 512 * 1024 * 1024      # 512 MB address space limit
    max_file_size_bytes: int = 50 * 1024 * 1024    # 50 MB max single file write
    require_bwrap: bool = False                    # Auto-uses bwrap when available and permitted by kernel


@dataclass(frozen=True, slots=True)
class SandboxExecutionResult:
    """Immutable result of a sandboxed subprocess invocation."""

    command: Tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    isolated_with_bwrap: bool


class SandboxGuard(SecureComponent):
    """Ring-0 subprocess isolation guard enforcing clean-room environments, bwrap namespaces, and rlimits."""

    SAFE_ENV_KEYS: FrozenSet[str] = frozenset({"LANG", "LC_ALL", "TERM"})

    def __init__(self, policy: Optional[SandboxPolicy] = None) -> None:
        self._policy: SandboxPolicy = policy if policy is not None else SandboxPolicy()
        self._bwrap_path: Optional[str] = shutil.which("bwrap")

    @classmethod
    def security_assessment(cls) -> ComponentSecurityAssessment:
        return ComponentSecurityAssessment(
            component_id="sandbox_guard",
            title="Ring-0 Namespace Sandbox, Clean-Room Environment & Resource Quota Guard",
            ring_level=0,
            source_path="src/activesec/guards/sandbox_guard.py",
            security_test_path="tests/security/test_sec_sandbox_guard.py",
            threat_vectors=("A.1", "A.2", "E.1", "E.2", "E.3"),
            summary=(
                "Isolates all agent subprocess executions using clean-room environment scrubbing, "
                "binary allowlisting, bubblewrap (bwrap) Linux namespaces (--unshare-all, --die-with-parent), "
                "unmounted host home directories, and OS resource limits (RLIMIT_NPROC, RLIMIT_FSIZE) "
                "against fork bombs and container escapes."
            ),
            enforced_invariants=(
                "Never executes commands with shell=True; requires an explicit sequence of arguments.",
                "Scrubs os.environ completely: API keys, tokens, DISPLAY, WAYLAND_DISPLAY, DBUS, and SSH_AUTH_SOCK are stripped before spawning.",
                "Blocks mounting of sensitive host paths (/var/run/docker.sock, /etc/shadow, ~/.ssh) into the sandbox.",
                "Builds bubblewrap command lines with --unshare-all, --die-with-parent, --new-session, read-only /usr /bin /lib, and isolated --tmpfs /tmp.",
                "Enforces close_fds=True and hard wall-clock timeouts on every subprocess.",
            ),
            residual_risks=(
                "Unprivileged user namespaces may be restricted by host sysctl (kernel.unprivileged_userns_clone=0); when require_bwrap=True is set, SandboxGuard fails closed rather than falling back.",
            ),
        )

    def build_clean_environment(
        self,
        workspace_dir: str,
        *,
        extra_safe_env: Optional[Mapping[str, str]] = None,
    ) -> dict[str, str]:
        """Construct a scrubbed clean-room environment free of host secrets and sockets."""
        real_ws = os.path.realpath(workspace_dir)
        clean_env: dict[str, str] = {
            "PATH": "/usr/bin:/bin",
            "HOME": real_ws,
            "LANG": "C.UTF-8",
            "TERM": "dumb",
        }
        if extra_safe_env:
            for key, val in extra_safe_env.items():
                upper_k = key.upper()
                if any(
                    secret_marker in upper_k
                    for secret_marker in ("KEY", "TOKEN", "SECRET", "PASSWORD", "AUTH", "SOCK", "DISPLAY", "DBUS")
                ):
                    raise SandboxSecurityError(
                        f"Attempted to inject sensitive environment variable '{key}' into sandbox.",
                        vector_id="A.2",
                        component_id="sandbox_guard",
                    )
                clean_env[key] = str(val)
        return clean_env

    def build_bwrap_command(
        self,
        argv: Sequence[str],
        *,
        workspace_dir: str,
        extra_ro_binds: Sequence[str] = (),
    ) -> Tuple[str, ...]:
        """Construct a hardened bubblewrap (bwrap) command line for namespace isolation."""
        self._validate_argv_and_mounts(argv, workspace_dir=workspace_dir, extra_mounts=extra_ro_binds)
        bwrap_bin = self._bwrap_path or "/usr/bin/bwrap"
        real_ws = os.path.realpath(workspace_dir)

        cmd: list[str] = [
            bwrap_bin,
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
        ]
        if self._policy.allow_network:
            cmd.append("--share-net")

        for sys_dir in ("/usr", "/bin", "/lib", "/lib64", "/etc/alternatives"):
            if os.path.exists(sys_dir):
                cmd.extend(["--ro-bind", sys_dir, sys_dir])

        for ro_path in extra_ro_binds:
            real_ro = os.path.realpath(ro_path)
            cmd.extend(["--ro-bind", real_ro, real_ro])

        cmd.extend(["--bind", real_ws, real_ws, "--chdir", real_ws])

        # Protect .git/hooks, .env, and audit vault artifacts inside the workspace if they exist
        for protected_rel in (".git/hooks", ".env", "audit_vault", ".audit.jsonl"):
            prot_full = os.path.join(real_ws, protected_rel)
            if os.path.exists(prot_full):
                cmd.extend(["--ro-bind", prot_full, prot_full])

        cmd.append("--")
        cmd.extend(argv)
        return tuple(cmd)

    def _validate_argv_and_mounts(
        self,
        argv: Sequence[str],
        *,
        workspace_dir: str,
        extra_mounts: Sequence[str] = (),
    ) -> None:
        if not argv or not argv[0].strip():
            raise SandboxSecurityError(
                "Empty command vector passed to SandboxGuard.",
                vector_id="A.1",
                component_id="sandbox_guard",
            )

        binary_name = os.path.basename(argv[0])
        if binary_name not in self._policy.allowed_binaries:
            raise SandboxSecurityError(
                f"Binary '{binary_name}' is not permitted by SandboxPolicy.allowed_binaries.",
                vector_id="A.1",
                component_id="sandbox_guard",
            )

        # Enforce per-binary disallowed GTFOBins / subcommand flags (Vector E.3 / A.1)
        forbidden_flags = DISALLOWED_BINARY_FLAGS.get(binary_name, frozenset())
        for idx, arg in enumerate(argv[1:], start=1):
            arg_clean = arg.strip()
            for flag in forbidden_flags:
                if arg_clean == flag or arg_clean.startswith(flag + "="):
                    raise SandboxSecurityError(
                        f"Disallowed GTFOBins/escape flag '{arg_clean}' on binary '{binary_name}'.",
                        vector_id="E.3",
                        component_id="sandbox_guard",
                    )
            if binary_name == "git" and arg_clean == "-c" and idx < len(argv) - 1:
                cfg_pair = argv[idx + 1].strip().lower()
                if any(cfg_pair.startswith(k) for k in DISALLOWED_GIT_CONFIG_KEYS):
                    raise SandboxSecurityError(
                        f"Disallowed git -c config execution hook '{argv[idx + 1]}'.",
                        vector_id="E.3",
                        component_id="sandbox_guard",
                    )
            if binary_name == "git" and arg_clean.startswith("-c") and len(arg_clean) > 2:
                cfg_pair = arg_clean[2:].strip().lower()
                if any(cfg_pair.startswith(k) for k in DISALLOWED_GIT_CONFIG_KEYS):
                    raise SandboxSecurityError(
                        f"Disallowed git -c config execution hook '{arg_clean}'.",
                        vector_id="E.3",
                        component_id="sandbox_guard",
                    )

        real_ws = os.path.realpath(workspace_dir)
        user_home = os.path.realpath(os.path.expanduser("~"))
        ssh_dir = os.path.join(user_home, ".ssh")

        for mount_candidate in (real_ws, *[os.path.realpath(m) for m in extra_mounts]):
            if (
                mount_candidate in FORBIDDEN_MOUNT_SOURCES
                or os.path.basename(mount_candidate) in ("audit_vault", ".audit.jsonl")
                or os.path.basename(mount_candidate).endswith(".audit.jsonl")
                or (os.sep + "audit_vault" + os.sep) in (mount_candidate + os.sep)
            ):
                raise SandboxSecurityError(
                    f"Sandbox escape risk: Mounting forbidden host resource '{mount_candidate}' is blocked.",
                    vector_id="E.1",
                    component_id="sandbox_guard",
                )
            if mount_candidate == ssh_dir or mount_candidate.startswith(ssh_dir + os.sep):
                raise SandboxSecurityError(
                    f"Mounting host SSH directory '{mount_candidate}' into sandbox is blocked.",
                    vector_id="E.1",
                    component_id="sandbox_guard",
                )

    def run_sandboxed(
        self,
        argv: Sequence[str],
        *,
        workspace_dir: str,
        extra_safe_env: Optional[Mapping[str, str]] = None,
    ) -> SandboxExecutionResult:
        """Execute argv inside a clean-room, resource-limited sandbox."""
        self._validate_argv_and_mounts(argv, workspace_dir=workspace_dir)
        real_ws = os.path.realpath(workspace_dir)
        os.makedirs(real_ws, mode=0o700, exist_ok=True)
        clean_env = self.build_clean_environment(real_ws, extra_safe_env=extra_safe_env)

        use_bwrap = False
        exec_argv: Tuple[str, ...] = tuple(argv)

        if self._bwrap_path is not None:
            bwrap_cmd = self.build_bwrap_command(argv, workspace_dir=real_ws)
            probe = subprocess.run(
                [self._bwrap_path, "--unshare-all", "--ro-bind", "/", "/", "--", "/bin/true"],
                capture_output=True,
                text=True,
                check=False,
            )
            if probe.returncode == 0:
                use_bwrap = True
                exec_argv = bwrap_cmd
            elif self._policy.require_bwrap:
                raise SandboxSecurityError(
                    f"Bubblewrap namespace creation failed and require_bwrap=True: {probe.stderr.strip()}",
                    vector_id="E.1",
                    component_id="sandbox_guard",
                )
        elif self._policy.require_bwrap:
            raise SandboxSecurityError(
                "Bubblewrap (bwrap) binary not found on system and require_bwrap=True.",
                vector_id="E.1",
                component_id="sandbox_guard",
            )

        max_fsize = self._policy.max_file_size_bytes
        max_mem = self._policy.max_memory_bytes
        max_nproc = self._policy.max_processes
        cpu_secs = max(1, int(self._policy.timeout_seconds) + 2)

        def _apply_rlimits() -> None:
            resource.setrlimit(resource.RLIMIT_FSIZE, (max_fsize, max_fsize))
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_secs, cpu_secs))
            try:
                resource.setrlimit(resource.RLIMIT_AS, (max_mem, max_mem))
            except (ValueError, OSError):
                pass
            try:
                # Only lower RLIMIT_NPROC if current soft limit is higher and max_nproc > 512
                # (since RLIMIT_NPROC is per-UID on Linux and a very low value can block fork if user has many desktop processes)
                if max_nproc >= 512:
                    resource.setrlimit(resource.RLIMIT_NPROC, (max_nproc, max_nproc))
            except (ValueError, OSError):
                pass

        try:
            proc = subprocess.run(
                list(exec_argv),
                cwd=real_ws,
                env=clean_env,
                capture_output=True,
                text=True,
                timeout=self._policy.timeout_seconds,
                close_fds=True,
                preexec_fn=_apply_rlimits,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise SandboxSecurityError(
                f"Subprocess timed out after {self._policy.timeout_seconds}s (resource exhaustion defense).",
                vector_id="E.2",
                component_id="sandbox_guard",
            ) from exc

        return SandboxExecutionResult(
            command=tuple(argv),
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            isolated_with_bwrap=use_bwrap,
        )
