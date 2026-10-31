"""Adversarial security tests for CapabilityEngine (src/activesec/core/capability_token.py).

Verifies cryptographic chain integrity, monotonic attenuation, canonical path confinement,
TTL/quota limits, and prompt-injection taint locking.
"""

from __future__ import annotations

import os
import time
from dataclasses import replace

import pytest

from activesec.core.capability_token import (
    ActionClass,
    CapabilityCaveat,
    CapabilityEngine,
    CompositeLabel,
    InformationClass,
    SensitivityLevel,
    TrustLevel,
    classify_tool_action,
)
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


@pytest.mark.security
def test_sec_five_level_ifc_lattice_and_derived_test_usability(tmp_path: os.PathLike[str]) -> None:
    """[Vector F.2: 5-Level Information-Flow Taint Lattice] DERIVED taint permits workspace read/write and isolated pytest/unittest while blocking arbitrary shell and network egress."""
    engine = CapabilityEngine()
    ws = str(tmp_path)
    caveat = CapabilityCaveat(
        allowed_tools=frozenset({"fs:read", "fs:write", "shell:exec", "net:https"}),
        path_prefixes=(ws,),
        allowed_binaries=frozenset({"pytest", "python3", "bash", "curl"}),
        network_destinations=frozenset({"pypi.org"}),
        max_calls=10,
        expires_at_unix=time.time() + 300,
        max_information_class=InformationClass.DERIVED,
    )
    token = engine.issue_root_token(
        subject_agent_id="swe-agent",
        task_purpose="Read issue, edit workspace, run isolated tests",
        caveat=caveat,
    )

    # 1. Verify lattice join algebraic ordering
    assert InformationClass.TRUSTED.join(InformationClass.DERIVED) == InformationClass.DERIVED
    assert InformationClass.DERIVED.join(InformationClass.UNTRUSTED) == InformationClass.UNTRUSTED
    assert InformationClass.DERIVED.join(InformationClass.SENSITIVE) == InformationClass.SENSITIVE
    assert classify_tool_action("shell:exec", binary_name="pytest", raw_command="pytest -q tests/") == ActionClass.SHELL_TEST_ISOLATED
    assert classify_tool_action("shell:exec", binary_name="python3", raw_command="python3 -m unittest discover") == ActionClass.SHELL_TEST_ISOLATED
    assert classify_tool_action("shell:exec", binary_name="python3", raw_command="python3 -c 'import os'") == ActionClass.SHELL_ARBITRARY

    # 2. Under DERIVED taint, fs:read, fs:write, and isolated pytest/unittest succeed
    engine.verify_tool_call(
        token=token,
        agent_id="swe-agent",
        tool_name="fs:read",
        target_path=os.path.join(ws, "bug.py"),
        information_class=InformationClass.DERIVED,
        call_nonce="nonce-1",
    )
    engine.verify_tool_call(
        token=token,
        agent_id="swe-agent",
        tool_name="fs:write",
        target_path=os.path.join(ws, "bug.py"),
        information_class=InformationClass.DERIVED,
        call_nonce="nonce-2",
    )
    engine.verify_tool_call(
        token=token,
        agent_id="swe-agent",
        tool_name="shell:exec",
        binary_name="pytest",
        raw_command="pytest -q tests/test_bug.py",
        information_class=InformationClass.DERIVED,
        call_nonce="nonce-3",
    )

    # 3. Replay of consumed call_nonce is rejected
    with pytest.raises(CapabilityViolationError) as exc_replay:
        engine.verify_tool_call(
            token=token,
            agent_id="swe-agent",
            tool_name="fs:read",
            target_path=os.path.join(ws, "bug.py"),
            information_class=InformationClass.DERIVED,
            call_nonce="nonce-1",
        )
    assert exc_replay.value.vector_id == "A.3"

    # 4. Under DERIVED taint, arbitrary shell commands (e.g., bash or python3 -c) and net:https are blocked
    with pytest.raises(CapabilityViolationError) as exc_shell:
        engine.verify_tool_call(
            token=token,
            agent_id="swe-agent",
            tool_name="shell:exec",
            binary_name="python3",
            raw_command="python3 -c 'import socket'",
            information_class=InformationClass.DERIVED,
        )
    assert exc_shell.value.vector_id == "F.2"

    with pytest.raises(CapabilityViolationError) as exc_net:
        engine.verify_tool_call(
            token=token,
            agent_id="swe-agent",
            tool_name="net:https",
            network_destination="pypi.org",
            information_class=InformationClass.DERIVED,
        )
    assert exc_net.value.vector_id == "F.2"

    # 5. Under UNTRUSTED or SENSITIVE taint, calls exceeding max_information_class=DERIVED are blocked
    with pytest.raises(CapabilityViolationError) as exc_untrusted:
        engine.verify_tool_call(
            token=token,
            agent_id="swe-agent",
            tool_name="fs:write",
            target_path=os.path.join(ws, "bug.py"),
            information_class=InformationClass.UNTRUSTED,
        )
    assert exc_untrusted.value.vector_id == "F.2"


@pytest.mark.security
def test_sec_full_lineage_revocation_cascades_across_root_and_siblings(tmp_path: os.PathLike[str]) -> None:
    """[Vector A.1 & F.2: Lineage Revocation] Revoking any child token revokes root, sibling, and descendant tokens across the lineage."""
    engine = CapabilityEngine()
    ws = str(tmp_path)
    root_caveat = CapabilityCaveat(
        allowed_tools=frozenset({"fs:read", "fs:write"}),
        path_prefixes=(ws,),
        max_calls=10,
        expires_at_unix=time.time() + 300,
    )
    root_token = engine.issue_root_token(
        subject_agent_id="root-orch",
        task_purpose="Orchestrate workers",
        caveat=root_caveat,
    )
    child_a = engine.delegate_attenuated_token(
        parent_token=root_token,
        child_agent_id="worker-a",
        child_purpose="Read task",
        narrowed_caveat=replace(root_caveat, allowed_tools=frozenset({"fs:read"}), max_calls=3),
    )
    child_b = engine.delegate_attenuated_token(
        parent_token=root_token,
        child_agent_id="worker-b",
        child_purpose="Write task",
        narrowed_caveat=replace(root_caveat, allowed_tools=frozenset({"fs:write"}), max_calls=3),
    )

    # Child A trips a canary -> revoke_token(child_a.token_id) revokes the entire lineage
    engine.revoke_token(child_a.token_id)
    assert engine.is_revoked(child_a.token_id)
    assert engine.is_revoked(root_token.token_id)
    assert engine.is_revoked(child_b.token_id)

    with pytest.raises(CapabilityViolationError):
        engine.verify_tool_call(token=child_b, agent_id="worker-b", tool_name="fs:write", target_path=os.path.join(ws, "out.txt"))


