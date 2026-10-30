"""Adversarial security tests for CapabilityEngine (src/activesec/core/capability_token.py).

Verifies cryptographic chain integrity, monotonic attenuation, canonical path confinement,
TTL/quota limits, and prompt-injection taint locking.
"""

from __future__ import annotations

import os
import time
from dataclasses import replace

import pytest

from activesec.core.capability_token import CapabilityCaveat, CapabilityEngine
from activesec.core.exceptions import CapabilityViolationError


@pytest.mark.security
def test_sec_forged_signature_rejected(tmp_path: os.PathLike[str]) -> None:
    """[Vector A.3: Harness Tampering] Rejects tokens with tampered caveats or forged HMAC signatures."""
    engine = CapabilityEngine()
    caveat = CapabilityCaveat(
        allowed_tools=frozenset({"fs:read"}),
        path_prefixes=(str(tmp_path),),
        expires_at_unix=time.time() + 300,
    )
    token = engine.issue_root_token(
        subject_agent_id="agent-1",
        task_purpose="Read project files",
        caveat=caveat,
    )

    # Attempt to tamper with the token to add shell:exec without re-signing with master key
    tampered_caveat = replace(caveat, allowed_tools=frozenset({"fs:read", "shell:exec"}))
    tampered_token = replace(token, caveats=(tampered_caveat,))

    with pytest.raises(CapabilityViolationError) as exc_info:
        engine.verify_tool_call(
            token=tampered_token,
            agent_id="agent-1",
            tool_name="shell:exec",
        )
    assert exc_info.value.vector_id == "A.3"


@pytest.mark.security
def test_sec_monotonic_attenuation_blocks_privilege_escalation(tmp_path: os.PathLike[str]) -> None:
    """[Vector F.3: Confused Deputy / Privilege Escalation] Child delegation cannot expand parent scope."""
    engine = CapabilityEngine()
    sub_dir = os.path.join(str(tmp_path), "sub")
    os.makedirs(sub_dir, exist_ok=True)
    now = time.time()

    parent_caveat = CapabilityCaveat(
        allowed_tools=frozenset({"fs:read", "fs:write"}),
        path_prefixes=(sub_dir,),
        allowed_binaries=frozenset({"pytest"}),
        max_calls=5,
        expires_at_unix=now + 120,
    )
    parent_token = engine.issue_root_token(
        subject_agent_id="orchestrator",
        task_purpose="Manage sub_dir tests",
        caveat=parent_caveat,
    )

    # 1. Escalating tools (adding shell:exec) must fail
    with pytest.raises(CapabilityViolationError):
        engine.delegate_attenuated_token(
            parent_token=parent_token,
            child_agent_id="worker",
            child_purpose="Escalate tool",
            narrowed_caveat=replace(
                parent_caveat,
                allowed_tools=frozenset({"fs:read", "shell:exec"}),
            ),
        )

    # 2. Escalating path outside sub_dir (to parent tmp_path) must fail
    with pytest.raises(CapabilityViolationError):
        engine.delegate_attenuated_token(
            parent_token=parent_token,
            child_agent_id="worker",
            child_purpose="Escalate path",
            narrowed_caveat=replace(parent_caveat, path_prefixes=(str(tmp_path),)),
        )

    # 3. Escalating TTL or max_calls must fail
    with pytest.raises(CapabilityViolationError):
        engine.delegate_attenuated_token(
            parent_token=parent_token,
            child_agent_id="worker",
            child_purpose="Escalate TTL",
            narrowed_caveat=replace(parent_caveat, expires_at_unix=now + 600),
        )


@pytest.mark.security
def test_sec_tainted_context_blocks_privileged_execution(tmp_path: os.PathLike[str]) -> None:
    """[Vector F.2: Indirect Prompt Injection] Blocks tool execution when agent context becomes tainted."""
    engine = CapabilityEngine()
    caveat = CapabilityCaveat(
        allowed_tools=frozenset({"fs:write"}),
        path_prefixes=(str(tmp_path),),
        expires_at_unix=time.time() + 300,
        require_untainted_context=True,
    )
    token = engine.issue_root_token(
        subject_agent_id="coder",
        task_purpose="Write module",
        caveat=caveat,
    )

    target_file = os.path.join(str(tmp_path), "app.py")
    # Untainted call succeeds
    engine.verify_tool_call(
        token=token,
        agent_id="coder",
        tool_name="fs:write",
        target_path=target_file,
        context_tainted=False,
    )

    # Once untrusted external data taints the agent context, the call is blocked
    with pytest.raises(CapabilityViolationError) as exc_info:
        engine.verify_tool_call(
            token=token,
            agent_id="coder",
            tool_name="fs:write",
            target_path=target_file,
            context_tainted=True,
        )
    assert exc_info.value.vector_id == "F.2"


@pytest.mark.security
def test_sec_denied_paths_and_traversal_blocked(tmp_path: os.PathLike[str]) -> None:
    """[Vector A.4: Persistence Injection] Blocks writes to .git/hooks, .env, and ../ traversal."""
    engine = CapabilityEngine()
    caveat = CapabilityCaveat(
        allowed_tools=frozenset({"fs:write"}),
        path_prefixes=(str(tmp_path),),
        expires_at_unix=time.time() + 300,
    )
    token = engine.issue_root_token(
        subject_agent_id="coder",
        task_purpose="Edit workspace",
        caveat=caveat,
    )

    # Attempt to write to .git/hooks/pre-commit inside workspace
    hook_path = os.path.join(str(tmp_path), ".git/hooks/pre-commit")
    with pytest.raises(CapabilityViolationError) as exc_info:
        engine.verify_tool_call(
            token=token,
            agent_id="coder",
            tool_name="fs:write",
            target_path=hook_path,
        )
    assert exc_info.value.vector_id == "A.4"

    # Attempt ../ path traversal outside workspace
    traversal_path = os.path.join(str(tmp_path), "..", "outside.txt")
    with pytest.raises(CapabilityViolationError) as exc_info:
        engine.verify_tool_call(
            token=token,
            agent_id="coder",
            tool_name="fs:write",
            target_path=traversal_path,
        )
    assert exc_info.value.vector_id == "A.3"


@pytest.mark.security
def test_sec_revocation_and_quota_enforcement(tmp_path: os.PathLike[str]) -> None:
    """[Vector A.1: LotL Misuse] Enforces call quotas and immediate parent-chain revocation."""
    engine = CapabilityEngine()
    caveat = CapabilityCaveat(
        allowed_tools=frozenset({"fs:read"}),
        path_prefixes=(str(tmp_path),),
        max_calls=1,
        expires_at_unix=time.time() + 300,
    )
    token = engine.issue_root_token(
        subject_agent_id="reader",
        task_purpose="Single read",
        caveat=caveat,
    )

    engine.verify_tool_call(token=token, agent_id="reader", tool_name="fs:read")

    # Second call exceeds max_calls=1
    with pytest.raises(CapabilityViolationError):
        engine.verify_tool_call(token=token, agent_id="reader", tool_name="fs:read")
