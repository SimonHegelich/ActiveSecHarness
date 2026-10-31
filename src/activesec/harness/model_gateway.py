"""Ring-0 Hardened ModelGateway & ModelRouter for OpenRouter and Local Ollama.

Implements zero-dependency (stdlib urllib.request, ssl, json) LLM transport with:
1. API Key Isolation & Environment Scrubbing (`os.environ.pop("OPENROUTER_API_KEY", None)`).
2. Denial-of-Wallet Session Quotas (`max_requests_per_session`, `max_prompt_chars`).
3. Pre-Egress Canary Tripwire & Bidirectional Secret DLP Redaction.
4. OpenRouter Hardening: TLS 1.3 via `NetworkGuard`, strict host pinning (`openrouter.ai`),
   model allowlisting, and mandatory `"provider": {"data_collection": "deny", "allow_fallbacks": False, "require_parameters": True}`.
5. Local Ollama Hardening: Strict loopback binding (`127.0.0.1:11434`), mutation endpoint blocking
   (`/api/pull`, `/api/create`, `/api/delete`, `/api/push`, `/api/copy`), and SHA-256 Model Digest Pinning.
6. Role-Based Routing (`CODING`, `SUDO_EXPLAINER`, `REDTEAM_PENTEST`) requiring a cryptographically
   verified pentest `CapabilityToken` before invoking uncensored/red-team models.
7. Ingress Protection: Streaming response byte cap (`max_response_bytes`) and Trojan Source Unicode rejection.
"""

from __future__ import annotations

import enum
import json
import os
import ssl
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple

from activesec.core.capability_token import CapabilityEngine, CapabilityToken
from activesec.core.component import ComponentSecurityAssessment, SecureComponent
from activesec.core.exceptions import ModelSecurityError
from activesec.guards.canary_guard import CanaryGuard
from activesec.guards.credential_guard import CredentialGuard
from activesec.guards.network_guard import NetworkGuard
from activesec.sovereign.deobfuscator import TROJAN_SOURCE_UNICODE_CHARS


class ModelRole(str, enum.Enum):
    """Logical role determining which model backend and security policy apply."""

    CODING = "CODING"
    SUDO_EXPLAINER = "SUDO_EXPLAINER"
    REDTEAM_PENTEST = "REDTEAM_PENTEST"


@dataclass(frozen=True, slots=True)
class ChatMessage:
    """Immutable chat message exchanged with a model provider."""

    role: str
    content: str


@dataclass(frozen=True, slots=True)
class ToolCallRequest:
    """Immutable descriptor of a tool invocation requested by an agent."""

    tool_name: str
    arguments: Mapping[str, str] = field(default_factory=dict)
    target_path: Optional[str] = None
    binary_name: Optional[str] = None
    network_destination: Optional[str] = None
    raw_command: Optional[str] = None


@dataclass(frozen=True, slots=True)
class ModelResponse:
    """Immutable validated response returned by ModelGateway."""

    content: str
    tool_call: Optional[ToolCallRequest]
    model_id: str
    provider_name: str


@dataclass(frozen=True, slots=True)
class OpenRouterConfig:
    """Immutable hardened configuration for OpenRouter HTTPS inference."""

    endpoint_url: str = "https://openrouter.ai/api/v1/chat/completions"
    default_model: str = "qwen/qwen3-coder"
    allowed_models: FrozenSet[str] = frozenset(
        {
            "qwen/qwen3-coder",
            "deepseek/deepseek-v3.2",
            "anthropic/claude-sonnet-4",
            "google/gemini-2.5-pro",
        }
    )
    timeout_seconds: float = 30.0
    temperature: float = 0.0
    max_tokens: int = 2048


@dataclass(frozen=True, slots=True)
class OllamaLocalConfig:
    """Immutable hardened configuration for local air-gapped Ollama inference.

    Residual risk: when ``expected_sha256_digests`` is empty, ModelGateway still pins the
    Ollama endpoint to loopback ``http://127.0.0.1:11434`` and blocks mutation APIs
    (``/api/pull``, ``/api/create``, ``/api/delete``, ``/api/push``, ``/api/copy``), but
    cannot cryptographically pin a specific model blob until digests are supplied.
    """

    base_url: str = "http://127.0.0.1:11434"
    coding_model: str = "qwen3:4b"
    explainer_model: str = "qwen3:4b"
    redteam_model: str = "dolphin-llama3:8b"
    expected_sha256_digests: Mapping[str, str] = field(default_factory=dict)
    timeout_seconds: float = 30.0
    temperature: float = 0.0


@dataclass(frozen=True, slots=True)
class ModelGatewayPolicy:
    """Immutable session budget and ingress/egress security policy for ModelGateway."""

    max_requests_per_session: int = 50
    max_prompt_chars: int = 100_000
    max_response_bytes: int = 2 * 1024 * 1024  # 2 MB hard cap
    scrub_env: bool = True
    required_pentest_tool_scope: str = "pentest:redteam_model"


TransportFunc = Callable[[str, bytes, Mapping[str, str], Optional[ssl.SSLContext], float, int], bytes]


class ModelRouter:
    """Role-based model router enforcing capability gating for REDTEAM_PENTEST models."""

    def __init__(
        self,
        *,
        openrouter_config: Optional[OpenRouterConfig] = None,
        ollama_config: Optional[OllamaLocalConfig] = None,
        prefer_local_for_explainer: bool = True,
        required_pentest_tool_scope: str = "pentest:redteam_model",
    ) -> None:
        self._openrouter_config = openrouter_config or OpenRouterConfig()
        self._ollama_config = ollama_config or OllamaLocalConfig()
        self._prefer_local_for_explainer = prefer_local_for_explainer
        self._required_pentest_tool_scope = required_pentest_tool_scope

    def select_route(
        self,
        role: ModelRole,
        *,
        requested_model: Optional[str] = None,
        prefer_provider: Optional[str] = None,
        capability_engine: Optional[CapabilityEngine] = None,
        capability_token: Optional[CapabilityToken] = None,
        agent_id: str = "agent",
        context_tainted: bool = False,
    ) -> Tuple[str, str]:
        """Return (provider_name, model_id) after verifying role and capability constraints."""
        if role == ModelRole.REDTEAM_PENTEST:
            if capability_engine is None or capability_token is None:
                raise ModelSecurityError(
                    "REDTEAM_PENTEST model invocation requires a verified CapabilityToken and CapabilityEngine.",
                    vector_id="A.1",
                    component_id="model_gateway",
                )
            try:
                capability_engine.verify_tool_call(
                    token=capability_token,
                    agent_id=agent_id,
                    tool_name=self._required_pentest_tool_scope,
                    context_tainted=context_tainted,
                )
            except Exception as exc:
                raise ModelSecurityError(
                    f"REDTEAM_PENTEST capability verification failed: {exc}",
                    vector_id="A.1",
                    component_id="model_gateway",
                ) from exc
            return ("ollama", requested_model or self._ollama_config.redteam_model)

        if role == ModelRole.SUDO_EXPLAINER and self._prefer_local_for_explainer and prefer_provider != "openrouter":
            return ("ollama", requested_model or self._ollama_config.explainer_model)

        provider = prefer_provider or "openrouter"
        if provider == "ollama":
            return ("ollama", requested_model or self._ollama_config.coding_model)
        if provider == "openrouter":
            return ("openrouter", requested_model or self._openrouter_config.default_model)

        raise ModelSecurityError(
            f"Unsupported model provider '{provider}'.",
            vector_id="C.3",
            component_id="model_gateway",
        )


class ModelGateway(SecureComponent):
    """Ring-0 hardened model gateway mediating OpenRouter and local Ollama inference."""

    FORBIDDEN_OLLAMA_PATHS: FrozenSet[str] = frozenset(
        {
            "/api/pull",
            "/api/create",
            "/api/delete",
            "/api/push",
            "/api/copy",
        }
    )
    ALLOWED_OLLAMA_PATHS: FrozenSet[str] = frozenset(
        {
            "/api/chat",
            "/api/show",
        }
    )

    def __init__(
        self,
        *,
        policy: Optional[ModelGatewayPolicy] = None,
        openrouter_config: Optional[OpenRouterConfig] = None,
        ollama_config: Optional[OllamaLocalConfig] = None,
        canary_guard: Optional[CanaryGuard] = None,
        credential_guard: Optional[CredentialGuard] = None,
        capability_engine: Optional[CapabilityEngine] = None,
        transport_func: Optional[TransportFunc] = None,
        api_key: Optional[str] = None,
    ) -> None:
        self._policy = policy or ModelGatewayPolicy()
        self._openrouter_config = openrouter_config or OpenRouterConfig()
        self._ollama_config = ollama_config or OllamaLocalConfig()
        self._canary_guard = canary_guard or CanaryGuard()
        self._credential_guard = credential_guard or CredentialGuard()
        self._capability_engine = capability_engine
        self._transport_func: TransportFunc = transport_func or self._default_http_transport

        env_key = os.environ.pop("OPENROUTER_API_KEY", None) if self._policy.scrub_env else os.environ.get("OPENROUTER_API_KEY")
        self._openrouter_api_key: Optional[str] = api_key if api_key is not None else env_key

        self._router = ModelRouter(
            openrouter_config=self._openrouter_config,
            ollama_config=self._ollama_config,
            required_pentest_tool_scope=self._policy.required_pentest_tool_scope,
        )
        self._request_count: int = 0
        self._verified_ollama_digests: set[str] = set()

    @classmethod
    def security_assessment(cls) -> ComponentSecurityAssessment:
        return ComponentSecurityAssessment(
            component_id="model_gateway",
            title="Ring-0 Hardened OpenRouter & Local Ollama Model Gateway",
            ring_level=0,
            source_path="src/activesec/harness/model_gateway.py",
            security_test_path="tests/security/test_sec_model_gateway.py",
            threat_vectors=("A.1", "A.2", "B.4", "C.1", "C.2", "C.3", "D.2", "E.2", "F.2"),
            summary=(
                "Mediates all LLM inference across cloud (OpenRouter) and local air-gapped (Ollama) "
                "models. Enforces immediate API key scrubbing from os.environ, per-session Denial-of-Wallet "
                "call budgets, pre-egress Canary tripwire & Secret DLP redaction, OpenRouter ZDR privacy "
                "routing invariants, local Ollama mutation blocking & SHA-256 digest pinning, capability-gated "
                "red-team model access, and bounded ingress stream reading with Trojan Source filtering."
            ),
            enforced_invariants=(
                "Pops OPENROUTER_API_KEY from os.environ on initialization when scrub_env=True so child processes cannot leak it.",
                "Runs CanaryGuard.check_stream_for_canaries() and CredentialGuard.redact_secrets() on every prompt message before network egress.",
                "Enforces TLS 1.3 via NetworkGuard.create_hardened_tls_context(), pins OpenRouter host to openrouter.ai, validates allowed_models, and injects provider={'data_collection': 'deny', 'allow_fallbacks': False, 'require_parameters': True}.",
                "Restricts local Ollama strictly to http://127.0.0.1:11434/api/chat and /api/show while blocking /api/pull, /api/create, /api/delete, /api/push, and /api/copy.",
                "Verifies SHA-256 model digests via /api/show when expected_sha256_digests is configured and requires a verified CapabilityToken for ModelRole.REDTEAM_PENTEST.",
                "Caps HTTP response streams at max_response_bytes (2 MB) and rejects responses containing Trojan Source Unicode control characters.",
            ),
            residual_risks=(
                "Cloud model output could still propose subtle logic bugs in generated code (mitigated by routing all tool calls through Ring-0 SecurityKernel and SandboxGuard).",
            ),
        )

    @property
    def request_count(self) -> int:
        return self._request_count

    @staticmethod
    def _default_http_transport(
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        tls_context: Optional[ssl.SSLContext],
        timeout: float,
        max_response_bytes: int,
    ) -> bytes:
        req = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")
        with urllib.request.urlopen(req, timeout=timeout, context=tls_context) as resp:
            chunks: List[bytes] = []
            total = 0
            while True:
                chunk = resp.read(65_536)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_response_bytes:
                    raise ModelSecurityError(
                        f"Model HTTP response exceeded max_response_bytes ({max_response_bytes} bytes).",
                        vector_id="E.2",
                        component_id="model_gateway",
                    )
                chunks.append(chunk)
            return b"".join(chunks)

    def _enforce_budget_and_sanitize_messages(
        self,
        messages: Sequence[ChatMessage],
        *,
        active_token_id: Optional[str] = None,
    ) -> List[Dict[str, str]]:
        if not messages:
            raise ModelSecurityError(
                "Cannot invoke model with an empty message sequence.",
                vector_id="E.2",
                component_id="model_gateway",
            )
        if self._request_count >= self._policy.max_requests_per_session:
            raise ModelSecurityError(
                f"Denial-of-Wallet defense: session request budget exhausted ({self._request_count}/{self._policy.max_requests_per_session}).",
                vector_id="E.2",
                component_id="model_gateway",
            )

        total_chars = 0
        sanitized: List[Dict[str, str]] = []
        for msg in messages:
            # 1. Check CanaryGuard tripwire BEFORE redaction so sk-canary / AKIA canaries trip immediately
            self._canary_guard.check_stream_for_canaries(msg.content, active_token_id=active_token_id)

            # 2. Redact any real cleartext secrets before egress
            clean_content = self._credential_guard.redact_secrets(msg.content)
            total_chars += len(clean_content)
            if total_chars > self._policy.max_prompt_chars:
                raise ModelSecurityError(
                    f"Prompt size ({total_chars} chars) exceeds max_prompt_chars ({self._policy.max_prompt_chars}).",
                    vector_id="E.2",
                    component_id="model_gateway",
                )
            sanitized.append({"role": msg.role, "content": clean_content})

        self._request_count += 1
        return sanitized

    def _validate_openrouter_endpoint(self, url: str) -> None:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme.lower() != "https":
            raise ModelSecurityError(
                f"OpenRouter requires HTTPS transport; got '{parsed.scheme}://'.",
                vector_id="C.1",
                component_id="model_gateway",
            )
        if (parsed.hostname or "").lower() != "openrouter.ai" or parsed.path != "/api/v1/chat/completions":
            raise ModelSecurityError(
                f"Untrusted OpenRouter endpoint '{url}'; must be 'https://openrouter.ai/api/v1/chat/completions'.",
                vector_id="C.3",
                component_id="model_gateway",
            )

    def validate_ollama_url(self, url: str) -> str:
        """Strictly validate that an Ollama URL points to 127.0.0.1:11434 and an allowed read/inference path."""
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme.lower() != "http":
            raise ModelSecurityError(
                f"Local Ollama endpoint must use loopback http://127.0.0.1:11434; got scheme '{parsed.scheme}'.",
                vector_id="C.2",
                component_id="model_gateway",
            )
        if (parsed.hostname or "") != "127.0.0.1" or (parsed.port or 80) != 11434:
            raise ModelSecurityError(
                f"Local Ollama endpoint must be pinned to 127.0.0.1:11434; got '{parsed.netloc}'.",
                vector_id="C.2",
                component_id="model_gateway",
            )
        norm_path = parsed.path.rstrip("/") or "/"
        if norm_path in self.FORBIDDEN_OLLAMA_PATHS or any(
            norm_path.startswith(forbidden) for forbidden in self.FORBIDDEN_OLLAMA_PATHS
        ):
            raise ModelSecurityError(
                f"Forbidden Ollama management/mutation endpoint blocked: '{norm_path}'.",
                vector_id="A.1",
                component_id="model_gateway",
            )
        if norm_path not in self.ALLOWED_OLLAMA_PATHS:
            raise ModelSecurityError(
                f"Disallowed Ollama API path '{norm_path}'; only {sorted(self.ALLOWED_OLLAMA_PATHS)} are permitted.",
                vector_id="A.1",
                component_id="model_gateway",
            )
        return f"http://127.0.0.1:11434{norm_path}"

    def _verify_ollama_model_digest(self, model_id: str) -> None:
        expected = self._ollama_config.expected_sha256_digests.get(model_id)
        if not expected:
            return
        if model_id in self._verified_ollama_digests:
            return

        show_url = self.validate_ollama_url(f"{self._ollama_config.base_url.rstrip('/')}/api/show")
        payload = json.dumps({"name": model_id}, sort_keys=True).encode("utf-8")
        raw_bytes = self._invoke_transport(
            show_url,
            payload,
            headers={"Content-Type": "application/json"},
            tls_context=None,
            timeout=self._ollama_config.timeout_seconds,
        )
        try:
            data = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ModelSecurityError(
                f"Invalid JSON from Ollama /api/show during digest verification: {exc}",
                vector_id="C.3",
                component_id="model_gateway",
            ) from exc

        actual_digest = str(data.get("digest", "")).strip().lower()
        if actual_digest.startswith("sha256:"):
            actual_digest = actual_digest[len("sha256:") :]
        expected_clean = expected.strip().lower()
        if expected_clean.startswith("sha256:"):
            expected_clean = expected_clean[len("sha256:") :]

        if not actual_digest or actual_digest != expected_clean:
            raise ModelSecurityError(
                f"Ollama model digest mismatch for '{model_id}': expected '{expected_clean[:16]}...', got '{actual_digest[:16] or 'MISSING'}...'.",
                vector_id="C.3",
                component_id="model_gateway",
            )
        self._verified_ollama_digests.add(model_id)

    def _invoke_transport(
        self,
        url: str,
        body: bytes,
        *,
        headers: Mapping[str, str],
        tls_context: Optional[ssl.SSLContext],
        timeout: float,
    ) -> bytes:
        raw = self._transport_func(
            url,
            body,
            headers,
            tls_context,
            timeout,
            self._policy.max_response_bytes,
        )
        if len(raw) > self._policy.max_response_bytes:
            raise ModelSecurityError(
                f"Model HTTP response size ({len(raw)} bytes) exceeded max_response_bytes ({self._policy.max_response_bytes} bytes).",
                vector_id="E.2",
                component_id="model_gateway",
            )
        return raw

    @staticmethod
    def _inspect_ingress_text(text: str) -> None:
        for ch in text:
            cp = ord(ch)
            if cp in TROJAN_SOURCE_UNICODE_CHARS:
                raise ModelSecurityError(
                    f"Trojan Source Unicode control character (U+{cp:04X}) rejected in model response.",
                    vector_id="B.4",
                    component_id="model_gateway",
                )

    @staticmethod
    def _parse_tool_call_dict(raw_tool: Mapping[str, object]) -> ToolCallRequest:
        tool_name = str(raw_tool.get("tool_name") or raw_tool.get("name") or "").strip()
        if not tool_name:
            raise ModelSecurityError(
                "Malformed tool call in model response: missing 'tool_name'.",
                vector_id="F.2",
                component_id="model_gateway",
            )
        raw_args = raw_tool.get("arguments", {})
        if isinstance(raw_args, str):
            try:
                raw_args = json.loads(raw_args)
            except json.JSONDecodeError as exc:
                raise ModelSecurityError(
                    f"Malformed JSON in tool call arguments: {exc}",
                    vector_id="F.2",
                    component_id="model_gateway",
                ) from exc
        if not isinstance(raw_args, Mapping):
            raise ModelSecurityError(
                "Tool call arguments must be a JSON object mapping.",
                vector_id="F.2",
                component_id="model_gateway",
            )
        str_args: Dict[str, str] = {str(k): str(v) for k, v in raw_args.items()}

        target_path = raw_tool.get("target_path") or str_args.get("target_path")
        binary_name = raw_tool.get("binary_name") or str_args.get("binary_name")
        network_destination = raw_tool.get("network_destination") or str_args.get("network_destination")
        raw_command = raw_tool.get("raw_command") or str_args.get("raw_command")

        return ToolCallRequest(
            tool_name=tool_name,
            arguments=str_args,
            target_path=str(target_path) if target_path is not None else None,
            binary_name=str(binary_name) if binary_name is not None else None,
            network_destination=str(network_destination) if network_destination is not None else None,
            raw_command=str(raw_command) if raw_command is not None else None,
        )

    @staticmethod
    def _extract_embedded_tool_call(content: str) -> Optional[ToolCallRequest]:
        """Extract a tool_call JSON object from raw model text, markdown fences, or slightly truncated JSON."""
        stripped = content.strip()
        if not stripped:
            return None

        # Strip optional ```json ... ``` or ``` ... ``` fences
        if stripped.startswith("```"):
            lines = stripped.splitlines()
            if len(lines) >= 2:
                inner_lines = lines[1:]
                if inner_lines and inner_lines[-1].strip().startswith("```"):
                    inner_lines = inner_lines[:-1]
                stripped = "\n".join(inner_lines).strip()

        if '"tool_name"' not in stripped:
            return None

        start_idx = stripped.find("{")
        if start_idx == -1:
            return None
        candidate = stripped[start_idx:]

        # Try exact JSON parse, then repair missing closing braces (common with small local models)
        for suffix in ("", "}", "}}", '"}', '"}}'):
            try:
                embedded = json.loads(candidate + suffix)
                if isinstance(embedded, Mapping) and "tool_name" in embedded:
                    return ModelGateway._parse_tool_call_dict(embedded)
            except (json.JSONDecodeError, ModelSecurityError):
                continue
        return None

    def _parse_and_validate_response(
        self,
        raw_bytes: bytes,
        *,
        provider_name: str,
        fallback_model_id: str,
    ) -> ModelResponse:
        try:
            decoded_text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ModelSecurityError(
                f"Model response is not valid UTF-8: {exc}",
                vector_id="B.4",
                component_id="model_gateway",
            ) from exc

        self._inspect_ingress_text(decoded_text)

        try:
            payload = json.loads(decoded_text)
        except json.JSONDecodeError as exc:
            raise ModelSecurityError(
                f"Model response is not valid JSON: {exc}",
                vector_id="F.2",
                component_id="model_gateway",
            ) from exc

        if not isinstance(payload, Mapping):
            raise ModelSecurityError(
                "Model JSON response root must be an object.",
                vector_id="F.2",
                component_id="model_gateway",
            )

        content = ""
        tool_call: Optional[ToolCallRequest] = None
        model_id = str(payload.get("model") or fallback_model_id)

        if "choices" in payload and isinstance(payload["choices"], list) and payload["choices"]:
            first_choice = payload["choices"][0]
            if isinstance(first_choice, Mapping):
                msg = first_choice.get("message", {})
                if isinstance(msg, Mapping):
                    content = str(msg.get("content") or "")
                    if isinstance(msg.get("tool_call"), Mapping):
                        tool_call = self._parse_tool_call_dict(msg["tool_call"])
                    elif isinstance(msg.get("tool_calls"), list) and msg["tool_calls"]:
                        first_tc = msg["tool_calls"][0]
                        if isinstance(first_tc, Mapping):
                            fn_block = first_tc.get("function", first_tc)
                            if isinstance(fn_block, Mapping):
                                tool_call = self._parse_tool_call_dict(fn_block)
        elif "message" in payload and isinstance(payload["message"], Mapping):
            msg = payload["message"]
            content = str(msg.get("content") or "")
            if isinstance(msg.get("tool_call"), Mapping):
                tool_call = self._parse_tool_call_dict(msg["tool_call"])

        self._inspect_ingress_text(content)

        # Also support structured JSON tool_call embedded in content if tool_call not already set
        if tool_call is None:
            tool_call = self._extract_embedded_tool_call(content)

        return ModelResponse(
            content=content,
            tool_call=tool_call,
            model_id=model_id,
            provider_name=provider_name,
        )

    def chat(
        self,
        messages: Sequence[ChatMessage],
        *,
        role: ModelRole = ModelRole.CODING,
        requested_model: Optional[str] = None,
        prefer_provider: Optional[str] = None,
        capability_token: Optional[CapabilityToken] = None,
        agent_id: str = "agent",
        context_tainted: bool = False,
        endpoint_override: Optional[str] = None,
    ) -> ModelResponse:
        """Route, sanitize, and execute a chat completion across OpenRouter or local Ollama."""
        active_token_id = capability_token.token_id if capability_token is not None else None
        provider, model_id = self._router.select_route(
            role,
            requested_model=requested_model,
            prefer_provider=prefer_provider,
            capability_engine=self._capability_engine,
            capability_token=capability_token,
            agent_id=agent_id,
            context_tainted=context_tainted,
        )

        sanitized_messages = self._enforce_budget_and_sanitize_messages(
            messages,
            active_token_id=active_token_id,
        )

        if provider == "openrouter":
            if model_id not in self._openrouter_config.allowed_models:
                raise ModelSecurityError(
                    f"Model '{model_id}' is not in OpenRouterConfig.allowed_models.",
                    vector_id="C.3",
                    component_id="model_gateway",
                )
            if not self._openrouter_api_key:
                raise ModelSecurityError(
                    "Missing OpenRouter API key (neither injected nor present in OPENROUTER_API_KEY).",
                    vector_id="D.2",
                    component_id="model_gateway",
                )
            target_url = endpoint_override or self._openrouter_config.endpoint_url
            self._validate_openrouter_endpoint(target_url)

            request_obj: Dict[str, object] = {
                "max_tokens": self._openrouter_config.max_tokens,
                "messages": sanitized_messages,
                "model": model_id,
                "provider": {
                    "allow_fallbacks": False,
                    "data_collection": "deny",
                    "require_parameters": True,
                },
                "temperature": self._openrouter_config.temperature,
            }
            body_bytes = json.dumps(request_obj, sort_keys=True).encode("utf-8")
            headers = {
                "Authorization": f"Bearer {self._openrouter_api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://github.com/SimonHegelich/ActiveSecHarness",
                "X-Title": "ActiveSecHarness",
            }
            tls_ctx = NetworkGuard.create_hardened_tls_context()
            raw_resp = self._invoke_transport(
                target_url,
                body_bytes,
                headers=headers,
                tls_context=tls_ctx,
                timeout=self._openrouter_config.timeout_seconds,
            )
            return self._parse_and_validate_response(
                raw_resp,
                provider_name="openrouter",
                fallback_model_id=model_id,
            )

        # Local Ollama path
        raw_ollama_url = endpoint_override or f"{self._ollama_config.base_url.rstrip('/')}/api/chat"
        validated_url = self.validate_ollama_url(raw_ollama_url)
        self._verify_ollama_model_digest(model_id)

        ollama_req: Dict[str, object] = {
            "messages": sanitized_messages,
            "model": model_id,
            "options": {"temperature": self._ollama_config.temperature},
            "stream": False,
        }
        body_bytes = json.dumps(ollama_req, sort_keys=True).encode("utf-8")
        raw_resp = self._invoke_transport(
            validated_url,
            body_bytes,
            headers={"Content-Type": "application/json"},
            tls_context=None,
            timeout=self._ollama_config.timeout_seconds,
        )
        return self._parse_and_validate_response(
            raw_resp,
            provider_name="ollama",
            fallback_model_id=model_id,
        )
