"""Adversarial security tests for WikiManager (src/activesec/core/wiki_manager.py).

Verifies AST safety violation detection (eval, exec, pickle, shell=True, Trojan Source),
component SHA-256 tampering detection, symlink/traversal confinement, and runtime
telemetry synchronization from HashChainedAuditLog and AgentLoop.
"""

from __future__ import annotations

import os
import ssl
import time
from pathlib import Path
from typing import Mapping, Optional

import pytest

from activesec.core.audit_log import AuditLogEntry, HashChainedAuditLog
from activesec.core.capability_token import CapabilityCaveat, CapabilityEngine
from activesec.core.exceptions import WikiSecurityError
from activesec.core.security_kernel import SecurityKernel
from activesec.core.wiki_manager import WikiManager, audit_python_ast_source
from activesec.harness.agent_loop import AgentLoop, AgentSession
from activesec.harness.model_gateway import (
    ModelGateway,
    OllamaLocalConfig,
    OpenRouterConfig,
)


@pytest.mark.security
def test_sec_wiki_manager_detects_forbidden_ast_primitives_and_trojan_unicode(tmp_path: Path) -> None:
    """[Vector A.1 & B.4: AST Safety & Trojan Source Audit] Rejects eval, exec, pickle, shell=True, and Trojan Unicode in Python ASTs."""
    unsafe_source = (
        "import pickle\n"
        "import subprocess\n"
        "def bad_handler(cmd: str) -> None:\n"
        "    eval(cmd)\n"
        "    subprocess.run(cmd, shell=True)\n"
    )
    safe, findings = audit_python_ast_source(unsafe_source, filename="bad_tool.py")
    assert safe is False
    assert any("Forbidden import 'pickle'" in f for f in findings)
    assert any("Forbidden call 'eval()'" in f for f in findings)
    assert any("Forbidden subprocess 'shell=True'" in f for f in findings)

    # Also test Trojan Source RLO character U+202E
    trojan_file = tmp_path / "trojan.py"
    trojan_file.write_text("x = 1 # \u202e evil comment\n", encoding="utf-8")

    manager = WikiManager()
    with pytest.raises(WikiSecurityError) as exc_info:
        manager.inspect_source_ast(trojan_file, strict=True)
    assert exc_info.value.vector_id == "A.1"
    assert "U+202E" in exc_info.value.message


@pytest.mark.security
def test_sec_wiki_manager_detects_component_sha256_tampering_and_outside_root(tmp_path: Path) -> None:
    """[Vector A.3: Component Source Tampering & Path Confinement] Detects SHA-256 digest drift against pinned hashes and blocks out-of-repo wiki paths."""
    manager = WikiManager()
    live_hashes = manager.verify_component_integrity()
    assert "wiki_manager" in live_hashes
    assert "security_kernel" in live_hashes

    # Tamper with an expected hash prefix
    forged_hashes = dict(live_hashes)
    forged_hashes["security_kernel"] = "deadbeef0000"

    with pytest.raises(WikiSecurityError) as exc_info:
        manager.verify_component_integrity(expected_hashes=forged_hashes)
    assert exc_info.value.vector_id == "A.3"
    assert "tampering detected" in exc_info.value.message.lower()

    # Attempting to point wiki_dir outside repo_root fails closed
    with pytest.raises(WikiSecurityError) as path_exc:
        WikiManager(wiki_dir=tmp_path / "outside_wiki")
    assert path_exc.value.vector_id == "A.3"


@pytest.mark.security
def test_sec_wiki_manager_rejects_tampered_audit_log_and_syncs_runtime_telemetry(tmp_path: Path) -> None:
    """[Vector A.3 & F.3: Runtime Telemetry & Audit Verification] Rejects tampered audit chains and automatically syncs AgentLoop runtime telemetry."""
    repo_root = Path(__file__).resolve().parents[2]
    test_wiki_dir = repo_root / "wiki"
    manager = WikiManager(repo_root=repo_root, wiki_dir=test_wiki_dir)

    # 1. Tampered audit log must be rejected by collect_runtime_telemetry
    bad_log = HashChainedAuditLog()
    e0 = bad_log.append_event(event_type="TOOL_CALL_ALLOWED", actor_id="agent-1", ring_level=2)
    tampered_entry = AuditLogEntry(
        sequence_id=e0.sequence_id,
        timestamp_unix=e0.timestamp_unix,
        event_type="TOOL_CALL_ALLOWED",
        actor_id="forged-actor",
        ring_level=e0.ring_level,
        vector_id=e0.vector_id,
        details=e0.details,
        prev_entry_hash=e0.prev_entry_hash,
        entry_hash=e0.entry_hash,
        hmac_signature=e0.hmac_signature,
        encrypted_payload=e0.encrypted_payload,
    )
    bad_log._entries[0] = tampered_entry

    with pytest.raises(WikiSecurityError) as exc_info:
        manager.collect_runtime_telemetry(bad_log, session_label="tampered_session")
    assert exc_info.value.vector_id == "A.3"

    # 2. Valid AgentLoop run with auto_sync_wiki=True records telemetry in WikiManager
    ws = tmp_path / "ws"
    ws.mkdir()
    sample_file = ws / "readme.txt"
    sample_file.write_text("Telemetry verification artifact.\n", encoding="utf-8")

    engine = CapabilityEngine()
    audit_log = HashChainedAuditLog()
    kernel = SecurityKernel(
        workspace_dir=str(ws),
        capability_engine=engine,
        audit_log=audit_log,
        wiki_manager=manager,
    )

    step_state = {"n": 0}

    def _mock_transport(
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        tls_context: Optional[ssl.SSLContext],
        timeout: float,
        max_response_bytes: int,
    ) -> bytes:
        step_state["n"] += 1
        if step_state["n"] == 1:
            return (
                b'{"model":"qwen/qwen3-coder","choices":[{"message":{"content":"Reading",'
                b'"tool_call":{"tool_name":"fs:read","target_path":"'
                + str(sample_file).encode("utf-8")
                + b'"}}}]}'
            )
        return b'{"model":"qwen/qwen3-coder","choices":[{"message":{"content":"Done"}}]}'

    gateway = ModelGateway(
        openrouter_config=OpenRouterConfig(),
        ollama_config=OllamaLocalConfig(),
        capability_engine=engine,
        transport_func=_mock_transport,
        api_key="test-key",
    )
    token = engine.issue_root_token(
        subject_agent_id="telemetry-agent",
        task_purpose="Read sample",
        caveat=CapabilityCaveat(
            allowed_tools=frozenset({"fs:read"}),
            path_prefixes=(str(ws),),
            max_calls=5,
            expires_at_unix=time.time() + 300.0,
        ),
    )
    session = AgentSession(agent_id="telemetry-agent", active_token=token, max_steps=4)
    loop = AgentLoop(kernel=kernel, gateway=gateway, wiki_manager=manager)
    summary = loop.run(session, "Read readme.txt", auto_sync_wiki=True)

    assert summary.steps_executed == 2
    assert len(manager.telemetry_history) >= 1
    latest = manager.telemetry_history[-1]
    assert latest.session_label == "agent_loop:telemetry-agent"
    assert latest.allowed_tool_calls == 1
    assert latest.audit_chain_verified is True
