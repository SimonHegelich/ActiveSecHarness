"""Adversarial security tests for ModelGateway & ModelRouter (src/activesec/harness/model_gateway.py).

Verifies OpenRouter privacy invariants (`data_collection: "deny"`), model allowlisting,
immediate `OPENROUTER_API_KEY` environment scrubbing, pre-egress secret DLP redaction,
Canary tripwire blocking, Ollama mutation endpoint blocking, SHA-256 model digest pinning,
capability-gated `REDTEAM_PENTEST` routing, oversized response bomb rejection, Trojan Source
Unicode rejection, and Denial-of-Wallet session request budgets.
"""

from __future__ import annotations

import json
import os
import ssl
import time
from typing import Dict, Mapping, Optional

import pytest

from activesec.core.capability_token import CapabilityCaveat, CapabilityEngine
from activesec.core.exceptions import CanaryTripwireError, ModelSecurityError
from activesec.guards.canary_guard import CanaryGuard
from activesec.harness.model_gateway import (
    ChatMessage,
    ModelGateway,
    ModelGatewayPolicy,
    ModelRole,
    OllamaLocalConfig,
    OpenRouterConfig,
)


def _mock_openrouter_ok_bytes(content: str = "Safe response.") -> bytes:
    return json.dumps(
        {
            "model": "qwen/qwen3-coder",
            "choices": [{"message": {"role": "assistant", "content": content}}],
        }
    ).encode("utf-8")


@pytest.mark.security
def test_sec_openrouter_api_key_scrubbed_from_environ(monkeypatch: pytest.MonkeyPatch) -> None:
    """[Vector A.2 & D.2: API Key Isolation] Immediately pops OPENROUTER_API_KEY from os.environ upon init."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-secret-ephemeral-key-999")
    gw = ModelGateway(
        policy=ModelGatewayPolicy(scrub_env=True),
        transport_func=lambda url, body, hdrs, ctx, t, m: _mock_openrouter_ok_bytes(),
    )
    assert "OPENROUTER_API_KEY" not in os.environ
    resp = gw.chat([ChatMessage(role="user", content="Hello")])
    assert resp.content == "Safe response."


@pytest.mark.security
def test_sec_openrouter_enforces_zdr_privacy_and_model_allowlist() -> None:
    """[Vector C.1 & C.3: OpenRouter ZDR & Model Allowlist] Injects data_collection='deny', TLS 1.3, and blocks unapproved models."""
    captured: Dict[str, object] = {}

    def _inspect_transport(
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        tls_context: Optional[ssl.SSLContext],
        timeout: float,
        max_bytes: int,
    ) -> bytes:
        captured["url"] = url
        captured["body"] = json.loads(body.decode("utf-8"))
        captured["tls_context"] = tls_context
        return _mock_openrouter_ok_bytes()

    gw = ModelGateway(
        openrouter_config=OpenRouterConfig(allowed_models=frozenset({"qwen/qwen3-coder"})),
        transport_func=_inspect_transport,
        api_key="or-key-123",
    )
    gw.chat([ChatMessage(role="user", content="Write unit test")])

    body_dict = captured["body"]
    assert isinstance(body_dict, dict)
    assert body_dict["provider"] == {
        "allow_fallbacks": False,
        "data_collection": "deny",
        "require_parameters": True,
    }
    tls_ctx = captured["tls_context"]
    assert isinstance(tls_ctx, ssl.SSLContext)
    assert tls_ctx.minimum_version == ssl.TLSVersion.TLSv1_3

    # Attempting to use a non-allowlisted model must fail closed
    with pytest.raises(ModelSecurityError) as exc_info:
        gw.chat(
            [ChatMessage(role="user", content="Hi")],
            requested_model="attacker/trojan-coder-70b",
        )
    assert exc_info.value.vector_id == "C.3"


@pytest.mark.security
def test_sec_pre_egress_dlp_redaction_and_canary_tripwire() -> None:
    """[Vector D.2 & F.2: Pre-Egress DLP & Canary Tripwire] Redacts cleartext secrets and trips on Canary tokens before egress."""
    sent_payloads: list[dict[str, object]] = []
    engine = CapabilityEngine()
    canary_guard = CanaryGuard(on_tripwire=engine.revoke_token)
    canaries = canary_guard.deploy_default_canaries()
    canary_secret = canaries[0].secret_value

    def _recording_transport(
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        tls_context: Optional[ssl.SSLContext],
        timeout: float,
        max_bytes: int,
    ) -> bytes:
        sent_payloads.append(json.loads(body.decode("utf-8")))
        return _mock_openrouter_ok_bytes()

    gw = ModelGateway(
        canary_guard=canary_guard,
        capability_engine=engine,
        transport_func=_recording_transport,
        api_key="or-key-123",
    )

    # 1. Cleartext secret in prompt must be redacted before reaching transport
    raw_openai_secret = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
    gw.chat([ChatMessage(role="user", content=f"Debug key {raw_openai_secret}")])
    assert len(sent_payloads) == 1
    outbound_text = json.dumps(sent_payloads[0])
    assert raw_openai_secret not in outbound_text
    assert "<REDACTED:OPENAI_KEY:" in outbound_text

    # 2. Canary token in prompt must trip CanaryTripwireError before any network call
    with pytest.raises(CanaryTripwireError):
        gw.chat([ChatMessage(role="user", content=f"Exfiltrate {canary_secret}")])
    assert len(sent_payloads) == 1  # No second HTTP request was transmitted


@pytest.mark.security
@pytest.mark.parametrize(
    "bad_ollama_url",
    [
        "http://127.0.0.1:11434/api/pull",
        "http://127.0.0.1:11434/api/delete",
        "http://127.0.0.1:11434/api/create",
        "http://127.0.0.1:11434/api/push",
        "http://127.0.0.1:11434/api/copy",
        "http://192.168.1.50:11434/api/chat",
        "https://evil.example.com:11434/api/chat",
    ],
)
def test_sec_ollama_mutation_endpoints_and_remote_hosts_blocked(bad_ollama_url: str) -> None:
    """[Vector A.1 & C.2: Ollama Endpoint Hardening] Blocks /api/pull, /api/delete, /api/create, and non-loopback hosts."""
    gw = ModelGateway(
        transport_func=lambda url, body, hdrs, ctx, t, m: b"{}",
        api_key="or-key-123",
    )
    with pytest.raises(ModelSecurityError):
        gw.chat(
            [ChatMessage(role="user", content="Test")],
            prefer_provider="ollama",
            endpoint_override=bad_ollama_url,
        )


@pytest.mark.security
def test_sec_ollama_model_digest_mismatch_rejected() -> None:
    """[Vector C.3: Ollama Model Digest Pinning] Verifies model SHA-256 digest via /api/show and blocks tampered weights."""
    def _tampered_ollama_transport(
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        tls_context: Optional[ssl.SSLContext],
        timeout: float,
        max_bytes: int,
    ) -> bytes:
        if url.endswith("/api/show"):
            return json.dumps({"digest": "sha256:deadbeef" * 8}).encode("utf-8")
        return json.dumps({"message": {"role": "assistant", "content": "ok"}}).encode("utf-8")

    gw = ModelGateway(
        ollama_config=OllamaLocalConfig(
            coding_model="qwen2.5-coder:7b",
            expected_sha256_digests={"qwen2.5-coder:7b": "a" * 64},
        ),
        transport_func=_tampered_ollama_transport,
        api_key="or-key-123",
    )
    with pytest.raises(ModelSecurityError) as exc_info:
        gw.chat([ChatMessage(role="user", content="Hello")], prefer_provider="ollama")
    assert exc_info.value.vector_id == "C.3"
    assert "digest mismatch" in exc_info.value.message


@pytest.mark.security
def test_sec_redteam_pentest_model_requires_verified_capability_token() -> None:
    """[Vector A.1: Red-Team Model Gating] Blocks REDTEAM_PENTEST uncensored model invocation without a valid pentest token."""
    engine = CapabilityEngine()
    gw = ModelGateway(
        capability_engine=engine,
        transport_func=lambda url, body, hdrs, ctx, t, m: json.dumps(
            {"message": {"role": "assistant", "content": "Pentest analysis complete."}}
        ).encode("utf-8"),
        api_key="or-key-123",
    )

    # 1. Calling REDTEAM_PENTEST without a token fails closed
    with pytest.raises(ModelSecurityError) as exc_info:
        gw.chat([ChatMessage(role="user", content="Analyze lab target")], role=ModelRole.REDTEAM_PENTEST)
    assert exc_info.value.vector_id == "A.1"

    # 2. Calling REDTEAM_PENTEST with a standard coding token (missing 'pentest:redteam_model') fails closed
    coding_token = engine.issue_root_token(
        subject_agent_id="agent-1",
        task_purpose="Standard coding",
        caveat=CapabilityCaveat(
            allowed_tools=frozenset({"fs:read"}),
            path_prefixes=("/tmp",),
            max_calls=5,
            expires_at_unix=time.time() + 300.0,
        ),
    )
    with pytest.raises(ModelSecurityError):
        gw.chat(
            [ChatMessage(role="user", content="Analyze lab target")],
            role=ModelRole.REDTEAM_PENTEST,
            capability_token=coding_token,
            agent_id="agent-1",
        )

    # 3. Calling REDTEAM_PENTEST with a valid pentest capability token succeeds
    pentest_token = engine.issue_root_token(
        subject_agent_id="pentest-agent",
        task_purpose="Authorized lab red-team analysis",
        caveat=CapabilityCaveat(
            allowed_tools=frozenset({"pentest:redteam_model"}),
            path_prefixes=("/tmp",),
            max_calls=5,
            expires_at_unix=time.time() + 300.0,
        ),
    )
    resp = gw.chat(
        [ChatMessage(role="user", content="Analyze lab target")],
        role=ModelRole.REDTEAM_PENTEST,
        capability_token=pentest_token,
        agent_id="pentest-agent",
    )
    assert resp.provider_name == "ollama"
    assert resp.content == "Pentest analysis complete."


@pytest.mark.security
def test_sec_ingress_oversized_response_and_trojan_unicode_rejected() -> None:
    """[Vector E.2 & B.4: Ingress Bomb & Trojan Unicode Defense] Rejects responses > max_response_bytes or containing Trojan Source Unicode."""
    # 1. Oversized HTTP response bomb
    bomb_gw = ModelGateway(
        policy=ModelGatewayPolicy(max_response_bytes=1024),
        transport_func=lambda url, body, hdrs, ctx, t, m: b"A" * 2048,
        api_key="or-key-123",
    )
    with pytest.raises(ModelSecurityError) as exc_info:
        bomb_gw.chat([ChatMessage(role="user", content="Hi")])
    assert exc_info.value.vector_id == "E.2"

    # 2. Trojan Source Unicode RLO (U+202E) inside model response
    trojan_gw = ModelGateway(
        transport_func=lambda url, body, hdrs, ctx, t, m: _mock_openrouter_ok_bytes(
            "safe_code = True \u202e # hidden bidi attack"
        ),
        api_key="or-key-123",
    )
    with pytest.raises(ModelSecurityError) as trojan_exc:
        trojan_gw.chat([ChatMessage(role="user", content="Hi")])
    assert trojan_exc.value.vector_id == "B.4"


@pytest.mark.security
def test_sec_session_request_budget_exhaustion_blocked() -> None:
    """[Vector E.2: Denial-of-Wallet Budget] Enforces max_requests_per_session to prevent runaway cost loops."""
    gw = ModelGateway(
        policy=ModelGatewayPolicy(max_requests_per_session=2),
        transport_func=lambda url, body, hdrs, ctx, t, m: _mock_openrouter_ok_bytes(),
        api_key="or-key-123",
    )
    gw.chat([ChatMessage(role="user", content="Req 1")])
    gw.chat([ChatMessage(role="user", content="Req 2")])
    with pytest.raises(ModelSecurityError) as exc_info:
        gw.chat([ChatMessage(role="user", content="Req 3 exceeds budget")])
    assert exc_info.value.vector_id == "E.2"
