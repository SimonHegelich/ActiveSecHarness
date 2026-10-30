"""Adversarial security tests for SandboxGuard (src/activesec/guards/sandbox_guard.py).

Verifies environment variable secret scrubbing, docker.sock and ~/.ssh mount blocking,
binary allowlist enforcement, bubblewrap command construction, and timeout protection.
"""

from __future__ import annotations

import os

import pytest

from activesec.core.exceptions import SandboxSecurityError
from activesec.guards.sandbox_guard import SandboxGuard, SandboxPolicy


@pytest.mark.security
def test_sec_clean_room_environment_strips_host_secrets(
    tmp_path: os.PathLike[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """[Vector A.2: Subprocess Environment Leak] Scrubs OPENAI_API_KEY, SSH_AUTH_SOCK, and DISPLAY from subprocesses."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-super-secret-host-key")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/ssh-agent.sock")
    monkeypatch.setenv("DISPLAY", ":0")

    guard = SandboxGuard()
    res = guard.run_sandboxed(
        ["python3", "-c", "import os; print(list(os.environ.keys()))"],
        workspace_dir=str(tmp_path),
    )
    assert res.returncode == 0
    assert "OPENAI_API_KEY" not in res.stdout
    assert "SSH_AUTH_SOCK" not in res.stdout
    assert "DISPLAY" not in res.stdout

    # Attempting to explicitly pass a secret env var via extra_safe_env is also blocked
    with pytest.raises(SandboxSecurityError) as exc_info:
        guard.build_clean_environment(str(tmp_path), extra_safe_env={"GITHUB_TOKEN": "ghp_xxx"})
    assert exc_info.value.vector_id == "A.2"


@pytest.mark.security
def test_sec_forbidden_docker_socket_and_ssh_mounts_blocked(tmp_path: os.PathLike[str]) -> None:
    """[Vector E.1: Container/Sandbox Escape] Blocks mounting /var/run/docker.sock, /etc/shadow, or ~/.ssh."""
    guard = SandboxGuard()

    with pytest.raises(SandboxSecurityError) as exc_info:
        guard.build_bwrap_command(
            ["python3", "-V"],
            workspace_dir=str(tmp_path),
            extra_ro_binds=["/var/run/docker.sock"],
        )
    assert exc_info.value.vector_id == "E.1"

    ssh_dir = os.path.expanduser("~/.ssh")
    with pytest.raises(SandboxSecurityError) as exc_info2:
        guard.build_bwrap_command(
            ["python3", "-V"],
            workspace_dir=str(tmp_path),
            extra_ro_binds=[ssh_dir],
        )
    assert exc_info2.value.vector_id == "E.1"


@pytest.mark.security
def test_sec_unauthorized_lotl_binary_and_timeout_enforced(tmp_path: os.PathLike[str]) -> None:
    """[Vector A.1 & E.2: LotL Binary & Resource Exhaustion] Blocks unapproved binaries and terminates hung processes."""
    guard = SandboxGuard(SandboxPolicy(allowed_binaries=frozenset({"python3"}), timeout_seconds=0.3))

    # Unauthorized binary (e.g., nc / curl) must be blocked before spawn
    with pytest.raises(SandboxSecurityError) as exc_info:
        guard.run_sandboxed(["curl", "https://example.com"], workspace_dir=str(tmp_path))
    assert exc_info.value.vector_id == "A.1"

    # Infinite loop must be killed by timeout
    with pytest.raises(SandboxSecurityError) as exc_info2:
        guard.run_sandboxed(["python3", "-c", "while True: pass"], workspace_dir=str(tmp_path))
    assert exc_info2.value.vector_id == "E.2"
