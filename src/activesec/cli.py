"""Command-Line Interface, Self-Test, and Interactive Ring-3 Chat for ActiveSecHarness."""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, List, Mapping, Optional, Sequence, TextIO, Tuple

from activesec.core.audit_log import HashChainedAuditLog
from activesec.core.capability_token import CapabilityCaveat, CapabilityEngine, CapabilityToken
from activesec.core.exceptions import ActiveSecError, CanaryTripwireError, ModelSecurityError
from activesec.core.security_kernel import SecurityKernel
from activesec.core.tool_registry import CertifiedToolRegistry
from activesec.core.user_wiki_manager import UserWikiManager
from activesec.core.wiki_manager import WikiManager
from activesec.guards.canary_guard import CanaryGuard
from activesec.guards.code_verifier import CodeVerifier
from activesec.harness.agent_loop import AgentLoop, AgentRunSummary, AgentSession
from activesec.harness.dual_model_reviewer import DualModelReviewer
from activesec.harness.model_gateway import (
    ModelGateway,
    ModelGatewayPolicy,
    ModelRole,
    OllamaLocalConfig,
    OpenRouterConfig,
)

CHAT_AGENT_ID = "chat-agent"
DEFAULT_WORKSPACE_NAME = "workspace_live"
DEFAULT_CHAT_MAX_STEPS = 8
DEFAULT_TOKEN_TTL_SECONDS = 3600.0
DEFAULT_TOKEN_MAX_CALLS = 64
CODING_MODEL_HINTS = ("coder", "qwen", "phi", "llama", "mistral", "deepseek", "gemini", "claude")
EMBEDDING_MODEL_HINTS = ("embed", "minilm", "nomic-embed", "bge-", "e5-")

CHAT_SYSTEM_PROMPT = (
    "You are an ActiveSecHarness Ring-3 coding agent. Every tool invocation is mediated "
    "by the Ring-0 SecurityKernel. You may only use fs:read and fs:write inside the "
    "workspace. Never request shell, network, or archive tools.\n"
    "When you need a tool, respond with ONLY a single JSON object (no markdown fences, "
    "no prose). Exact schema:\n"
    '{"tool_name":"fs:write","target_path":"<absolute_path>","arguments":{"content":"<text>"}}\n'
    "or\n"
    '{"tool_name":"fs:read","target_path":"<absolute_path>"}\n'
    "After an OBSERVATION confirms the tool result, reply with a short final sentence and NO JSON."
)


@dataclass(frozen=True, slots=True)
class ReplCommand:
    """Parsed interactive REPL command."""

    kind: str  # task | quit | status | wiki | learn | test | models | empty | unknown
    payload: str = ""


@dataclass
class ChatRuntime:
    """Mutable interactive chat runtime bound to one workspace and provider."""

    workspace_dir: str
    provider: str
    model: str
    max_steps: int
    engine: CapabilityEngine
    audit_log: HashChainedAuditLog
    canary_guard: CanaryGuard
    tool_registry: CertifiedToolRegistry
    kernel: SecurityKernel
    gateway: ModelGateway
    loop: AgentLoop
    token: CapabilityToken
    code_verifier: CodeVerifier
    user_wiki_manager: UserWikiManager
    dual_reviewer: DualModelReviewer
    reviewer_enabled: bool = True
    auto_repair_enabled: bool = True
    last_session: Optional[AgentSession] = None
    tasks_completed: int = 0
    openrouter_key_present: bool = False
    ollama_models: Tuple[str, ...] = ()
    digest_pinning_enabled: bool = False


def load_dotenv_file(path: Path) -> Mapping[str, str]:
    """Load KEY=VALUE pairs from a local dotenv file without printing values.

    Only simple ``KEY=VALUE`` lines are accepted. Quotes around values are stripped.
    Existing process environment variables are never overwritten.
    """
    loaded: dict[str, str] = {}
    if not path.is_file():
        return loaded
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return loaded
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        if not key:
            continue
        if key in os.environ and os.environ[key]:
            continue
        os.environ[key] = value
        loaded[key] = "<set>"
    return loaded


def ensure_openrouter_key_from_dotenv(repo_root: Optional[Path] = None) -> bool:
    """Ensure OPENROUTER_API_KEY is available from the environment or a gitignored ``.env``.

    Returns True if a non-empty key is present after loading (never returns the key).
    """
    if os.environ.get("OPENROUTER_API_KEY"):
        return True
    root = repo_root or Path.cwd()
    for candidate in (root / ".env", root / ".env.local"):
        load_dotenv_file(candidate)
        if os.environ.get("OPENROUTER_API_KEY"):
            return True
    return False


def probe_ollama_models(*, base_url: str = "http://127.0.0.1:11434", timeout: float = 3.0) -> List[str]:
    """Return installed Ollama model names, or raise ModelSecurityError if unreachable."""
    tags_url = f"{base_url.rstrip('/')}/api/tags"
    # Discovery uses tags endpoint outside ModelGateway mutation allowlist intentionally;
    # chat inference still goes only through ModelGateway-validated /api/chat.
    try:
        with urllib.request.urlopen(tags_url, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
        raise ModelSecurityError(
            "Cannot reach local Ollama at http://127.0.0.1:11434/api/tags. "
            "Start it with `ollama serve` and ensure at least one coding model is pulled "
            "(e.g. `ollama pull qwen3:4b`).",
            vector_id="C.2",
            component_id="cli",
        ) from exc
    models = [str(m.get("name", "")).strip() for m in payload.get("models", []) if m.get("name")]
    return [m for m in models if m]


def _is_embedding_model(name: str) -> bool:
    lower = name.lower()
    return any(hint in lower for hint in EMBEDDING_MODEL_HINTS)


def select_coding_model(discovered: Sequence[str], *, requested: Optional[str], fallback: str) -> str:
    """Select a usable coding model from discovered Ollama tags or an explicit override."""
    if requested:
        if discovered and requested not in discovered:
            raise ModelSecurityError(
                f"Requested Ollama model '{requested}' is not installed. Available: {list(discovered)}",
                vector_id="C.3",
                component_id="cli",
            )
        return requested
    if not discovered:
        return fallback
    non_embed = [m for m in discovered if not _is_embedding_model(m)]
    for hint in CODING_MODEL_HINTS:
        for name in non_embed:
            if hint in name.lower():
                return name
    if non_embed:
        return non_embed[0]
    raise ModelSecurityError(
        f"No non-embedding Ollama models found among {list(discovered)}. "
        "Pull a coding model such as `ollama pull qwen3:4b`.",
        vector_id="C.3",
        component_id="cli",
    )


def parse_repl_line(line: str) -> ReplCommand:
    """Parse a single REPL input line into a structured command."""
    text = line.strip()
    if not text:
        return ReplCommand(kind="empty")
    lower = text.lower()
    if lower in {"/quit", "/exit", ":q", "quit", "exit"}:
        return ReplCommand(kind="quit")
    if lower in {"/status", ":status"}:
        return ReplCommand(kind="status")
    if lower in {"/wiki", ":wiki"}:
        return ReplCommand(kind="wiki")
    if lower in {"/learn", "/user-wiki", ":learn"}:
        return ReplCommand(kind="learn")
    if lower == "/test" or lower.startswith("/test "):
        return ReplCommand(kind="test", payload=text[len("/test") :].strip())
    if lower == "/waive" or lower.startswith("/waive "):
        return ReplCommand(kind="waive", payload=text[len("/waive") :].strip())
    if lower == "/promote-test" or lower.startswith("/promote-test "):
        return ReplCommand(kind="promote_test", payload=text[len("/promote-test") :].strip())
    if lower in {"/models", "/model"} or lower.startswith("/models ") or lower.startswith("/model "):
        parts = text.split(maxsplit=1)
        return ReplCommand(kind="models", payload=parts[1].strip() if len(parts) > 1 else "")
    if text.startswith("/"):
        return ReplCommand(kind="unknown", payload=text)
    return ReplCommand(kind="task", payload=text)


def format_security_error(exc: ActiveSecError) -> str:
    """Render a structured ActiveSecError for REPL display without crashing."""
    vector = getattr(exc, "vector_id", "?")
    component = getattr(exc, "component_id", "?")
    return f"[SECURITY_BLOCK component={component} vector={vector}] {exc}"


def _issue_chat_token(engine: CapabilityEngine, workspace_dir: str) -> CapabilityToken:
    caveat = CapabilityCaveat(
        allowed_tools=frozenset({"fs:read", "fs:write"}),
        path_prefixes=(workspace_dir,),
        network_destinations=frozenset(),
        allowed_binaries=frozenset(),
        max_calls=DEFAULT_TOKEN_MAX_CALLS,
        expires_at_unix=time.time() + DEFAULT_TOKEN_TTL_SECONDS,
        require_untainted_context=True,
    )
    return engine.issue_root_token(
        subject_agent_id=CHAT_AGENT_ID,
        task_purpose="Interactive Ring-3 workspace coding session",
        caveat=caveat,
    )


def build_chat_runtime(
    *,
    workspace_dir: str,
    provider: str,
    model: Optional[str],
    max_steps: int,
    reviewer_provider: str = "openrouter",
    reviewer_model: Optional[str] = None,
    reviewer_enabled: bool = True,
    auto_repair_enabled: bool = True,
    user_wiki_dir: Optional[str] = None,
    transport_func=None,
    api_key: Optional[str] = None,
    openrouter_config: Optional[OpenRouterConfig] = None,
    ollama_config: Optional[OllamaLocalConfig] = None,
    skip_provider_probe: bool = False,
) -> ChatRuntime:
    """Construct a least-privilege chat runtime with certified fs tools and DualModelReviewer."""
    real_workspace = os.path.realpath(workspace_dir)
    os.makedirs(real_workspace, mode=0o700, exist_ok=True)

    key_present = bool(api_key) or ensure_openrouter_key_from_dotenv()
    discovered: List[str] = []
    selected_model = model
    digest_pinning = False

    or_cfg = openrouter_config or OpenRouterConfig()
    ol_cfg = ollama_config or OllamaLocalConfig(timeout_seconds=180.0)

    if provider == "ollama":
        if not skip_provider_probe:
            discovered = probe_ollama_models(base_url=ol_cfg.base_url)
        selected_model = select_coding_model(
            discovered,
            requested=model,
            fallback=ol_cfg.coding_model,
        )
        ol_cfg = OllamaLocalConfig(
            base_url=ol_cfg.base_url,
            coding_model=selected_model,
            explainer_model=selected_model,
            redteam_model=ol_cfg.redteam_model,
            expected_sha256_digests=ol_cfg.expected_sha256_digests,
            timeout_seconds=ol_cfg.timeout_seconds,
            temperature=ol_cfg.temperature,
        )
        digest_pinning = selected_model in ol_cfg.expected_sha256_digests
    elif provider == "openrouter":
        if not key_present and api_key is None and transport_func is None:
            raise ModelSecurityError(
                "OPENROUTER_API_KEY is not set. Export it in your shell or place it in a "
                "gitignored `.env` file as OPENROUTER_API_KEY=<value>, then re-run "
                "`PYTHONPATH=src python3 -m activesec.cli --chat --provider openrouter`.",
                vector_id="D.2",
                component_id="cli",
            )
        selected_model = model or or_cfg.default_model
        if selected_model not in or_cfg.allowed_models:
            # Align allowlist for this session only via constructor config (do not weaken TLS/ZDR).
            or_cfg = OpenRouterConfig(
                endpoint_url=or_cfg.endpoint_url,
                default_model=selected_model,
                allowed_models=frozenset(set(or_cfg.allowed_models) | {selected_model}),
                timeout_seconds=or_cfg.timeout_seconds,
                temperature=or_cfg.temperature,
                max_tokens=or_cfg.max_tokens,
            )
    else:
        raise ModelSecurityError(
            f"Unsupported provider '{provider}'. Use openrouter or ollama.",
            vector_id="C.3",
            component_id="cli",
        )

    effective_rev_model = reviewer_model or (
        or_cfg.default_model if reviewer_provider == "openrouter" else (selected_model or ol_cfg.coding_model)
    )
    if reviewer_provider == "openrouter" and effective_rev_model not in or_cfg.allowed_models:
        or_cfg = OpenRouterConfig(
            endpoint_url=or_cfg.endpoint_url,
            default_model=or_cfg.default_model,
            allowed_models=frozenset(set(or_cfg.allowed_models) | {effective_rev_model}),
            timeout_seconds=or_cfg.timeout_seconds,
            temperature=or_cfg.temperature,
            max_tokens=or_cfg.max_tokens,
        )

    engine = CapabilityEngine()
    audit_log = HashChainedAuditLog()
    canary_guard = CanaryGuard(on_tripwire=engine.revoke_token)
    canary_guard.deploy_default_canaries(workspace_dir=real_workspace)

    tool_registry = CertifiedToolRegistry()
    tool_registry.register_default_kernel_tools()
    tool_registry.run_agent_tool_qualification_suite(
        agent_id=CHAT_AGENT_ID,
        candidate_tools=frozenset({"fs:read", "fs:write"}),
        candidate_combinations=frozenset({frozenset({"fs:read", "fs:write"})}),
        qualification_probes=(lambda _agent, _combo: True,),
        ttl_seconds=DEFAULT_TOKEN_TTL_SECONDS,
    )

    kernel = SecurityKernel(
        workspace_dir=real_workspace,
        capability_engine=engine,
        audit_log=audit_log,
        canary_guard=canary_guard,
        tool_registry=tool_registry,
    )

    gateway = ModelGateway(
        policy=ModelGatewayPolicy(max_requests_per_session=200),
        openrouter_config=or_cfg,
        ollama_config=ol_cfg,
        canary_guard=canary_guard,
        capability_engine=engine,
        transport_func=transport_func,
        api_key=api_key if api_key is not None else None,
    )

    code_verifier = CodeVerifier(
        capability_engine=engine,
        tool_registry=tool_registry,
    )
    repo_root = kernel.wiki_manager.repo_root
    if user_wiki_dir is not None:
        real_user_wiki = Path(os.path.realpath(user_wiki_dir))
        effective_root = repo_root if str(real_user_wiki).startswith(str(repo_root) + os.sep) else real_user_wiki.parent
        user_wiki_manager = UserWikiManager(repo_root=effective_root, user_wiki_dir=real_user_wiki)
    else:
        user_wiki_manager = UserWikiManager(repo_root=repo_root)

    dual_reviewer = DualModelReviewer(
        gateway=gateway,
        code_verifier=code_verifier,
        user_wiki_manager=user_wiki_manager,
        reviewer_provider=reviewer_provider,
        reviewer_model=effective_rev_model,
        fallback_local_reviewer_model=selected_model or ol_cfg.coding_model,
        openrouter_key_available=(key_present or bool(api_key)),
    )

    token = _issue_chat_token(engine, real_workspace)
    loop = AgentLoop(
        kernel=kernel,
        gateway=gateway,
        role=ModelRole.CODING,
        prefer_provider=provider,
        halt_on_security_violation=True,
    )

    assert selected_model is not None
    return ChatRuntime(
        workspace_dir=real_workspace,
        provider=provider,
        model=selected_model,
        max_steps=max_steps,
        engine=engine,
        audit_log=audit_log,
        canary_guard=canary_guard,
        tool_registry=tool_registry,
        kernel=kernel,
        gateway=gateway,
        loop=loop,
        token=token,
        code_verifier=code_verifier,
        user_wiki_manager=user_wiki_manager,
        dual_reviewer=dual_reviewer,
        reviewer_enabled=reviewer_enabled,
        auto_repair_enabled=auto_repair_enabled,
        openrouter_key_present=key_present or bool(api_key),
        ollama_models=tuple(discovered),
        digest_pinning_enabled=digest_pinning,
    )


def refresh_chat_token(runtime: ChatRuntime) -> None:
    """Issue a fresh least-privilege capability token for the chat agent."""
    runtime.token = _issue_chat_token(runtime.engine, runtime.workspace_dir)


def status_lines(runtime: ChatRuntime) -> List[str]:
    """Return human-readable runtime status lines for ``/status``."""
    caveat = runtime.token.caveats[-1]
    used = runtime.engine.get_call_count(runtime.token.token_id)
    revoked = runtime.engine.is_revoked(runtime.token.token_id)
    taint = False if runtime.last_session is None else runtime.last_session.context_tainted
    ttl_left = max(0.0, caveat.expires_at_unix - time.time())
    lines = [
        f"provider={runtime.provider}",
        f"model={runtime.model}",
        f"reviewer_provider={runtime.dual_reviewer.reviewer_provider}",
        f"reviewer_model={runtime.dual_reviewer.reviewer_model}",
        f"reviewer_enabled={runtime.reviewer_enabled}",
        f"auto_repair_enabled={runtime.auto_repair_enabled}",
        f"user_academy_level={runtime.user_wiki_manager.current_mastery_level}",
        f"workspace={runtime.workspace_dir}",
        f"context_tainted={taint}",
        f"token_id={runtime.token.token_id[:12]}…",
        f"token_revoked={revoked}",
        f"token_calls={used}/{caveat.max_calls}",
        f"token_ttl_seconds_left={ttl_left:.0f}",
        f"tasks_completed={runtime.tasks_completed}",
        f"audit_entries={len(runtime.audit_log.entries)}",
        f"openrouter_key_present={runtime.openrouter_key_present}",
        f"ollama_models={list(runtime.ollama_models) if runtime.ollama_models else '(not probed)'}",
        f"digest_pinning_enabled={runtime.digest_pinning_enabled}",
    ]
    return lines


def handle_models_command(runtime: ChatRuntime, payload: str, *, out: TextIO) -> None:
    """Display or switch active coder/reviewer models (`/models`, `/model coder ...`, `/model reviewer ...`)."""
    if not payload:
        print(
            f"[models] coder={runtime.provider}/{runtime.model} | "
            f"reviewer={runtime.dual_reviewer.reviewer_provider}/{runtime.dual_reviewer.reviewer_model} "
            f"(openrouter_key_present={runtime.openrouter_key_present})",
            file=out,
        )
        print(
            "[models] Usage: `/model coder <provider>/<model>` or `/model reviewer <provider>/<model>`",
            file=out,
        )
        return

    parts = payload.split()
    if len(parts) != 2 or parts[0] not in ("coder", "reviewer") or "/" not in parts[1]:
        print(
            "[error] Invalid syntax. Use `/model coder <provider>/<model>` or `/model reviewer <provider>/<model>`.",
            file=out,
        )
        return

    role_target, spec = parts[0], parts[1]
    prov, mod = spec.split("/", 1)
    if prov not in ("openrouter", "ollama") or not mod:
        print("[error] Provider must be 'openrouter' or 'ollama'.", file=out)
        return

    if role_target == "coder":
        runtime.provider = prov
        runtime.model = mod
        runtime.loop._prefer_provider = prov
        print(f"[models] Updated coder model to {prov}/{mod}", file=out)
    else:
        runtime.dual_reviewer.configure_reviewer(provider=prov, model=mod)
        print(f"[models] Updated reviewer model to {prov}/{mod}", file=out)


def print_agent_summary(summary: AgentRunSummary, *, out: TextIO) -> None:
    """Print model replies and tool observations from one AgentLoop run."""
    for outcome in summary.outcomes:
        content = (outcome.model_response.content or "").strip()
        if content:
            print(f"[model] {content}", file=out)
        if outcome.tool_result is not None:
            print(
                f"[tool:{outcome.tool_result.tool_name}] {outcome.tool_result.output}",
                file=out,
            )
        if outcome.blocked_error is not None:
            print(format_security_error(outcome.blocked_error), file=out)
    if summary.final_answer and (
        not summary.outcomes or summary.outcomes[-1].model_response.content != summary.final_answer
    ):
        print(f"[final] {summary.final_answer}", file=out)


def _extract_written_python_files(summary: AgentRunSummary, workspace_dir: str) -> List[str]:
    """Return unique canonical paths of `.py` files written during `summary`."""
    written: List[str] = []
    for outcome in summary.outcomes:
        req = outcome.model_response.tool_call
        if outcome.tool_result is not None and req is not None and req.tool_name == "fs:write":
            raw_target = req.target_path or req.arguments.get("target_path") or req.arguments.get("path")
            if raw_target and str(raw_target).endswith(".py"):
                real_p = os.path.realpath(
                    raw_target if os.path.isabs(raw_target) else os.path.join(workspace_dir, raw_target)
                )
                if os.path.isfile(real_p) and real_p not in written:
                    written.append(real_p)
    return written


def _recover_unexecuted_python_write_via_kernel(
    runtime: ChatRuntime,
    summary: AgentRunSummary,
    *,
    out: TextIO,
) -> List[str]:
    """If a small local model emitted a slightly truncated JSON fs:write or fenced Python block without a parsed tool_call, recover and execute it via SecurityKernel."""
    recovered: List[str] = []
    for outcome in summary.outcomes:
        if outcome.tool_result is not None:
            continue
        raw_text = (outcome.model_response.content or "").strip()
        if not raw_text:
            continue

        tc = ModelGateway._extract_embedded_tool_call(raw_text)
        if tc is not None and tc.tool_name == "fs:write":
            tool_res = runtime.kernel.execute_tool_call(
                tc,
                token=runtime.token,
                agent_id=CHAT_AGENT_ID,
                context_tainted=False if runtime.last_session is None else runtime.last_session.context_tainted,
            )
            print(f"[tool:{tool_res.tool_name}] {tool_res.output}", file=out)
            raw_target = tc.target_path or tc.arguments.get("target_path") or tc.arguments.get("path")
            if raw_target and str(raw_target).endswith(".py"):
                real_p = os.path.realpath(
                    raw_target if os.path.isabs(raw_target) else os.path.join(runtime.workspace_dir, raw_target)
                )
                if os.path.isfile(real_p) and real_p not in recovered:
                    recovered.append(real_p)
    return recovered


def run_chat_task(runtime: ChatRuntime, task: str, *, out: TextIO = sys.stdout) -> None:
    """Execute one user task through AgentLoop and run Dual-Model Security Verification on any written Python files."""
    if runtime.engine.is_revoked(runtime.token.token_id):
        print("[info] Previous capability token was revoked; issuing a fresh token.", file=out)
        refresh_chat_token(runtime)

    caveat = runtime.token.caveats[-1]
    used = runtime.engine.get_call_count(runtime.token.token_id)
    if used >= caveat.max_calls or time.time() > caveat.expires_at_unix:
        print("[info] Capability token quota/TTL exhausted; issuing a fresh token.", file=out)
        refresh_chat_token(runtime)

    system_prompt = (
        f"{CHAT_SYSTEM_PROMPT}\nWorkspace absolute path: {runtime.workspace_dir}\n"
        "Prefer absolute paths under that workspace for fs:read and fs:write."
    )
    session = AgentSession(
        agent_id=CHAT_AGENT_ID,
        active_token=runtime.token,
        max_steps=runtime.max_steps,
        system_prompt=system_prompt,
    )
    runtime.last_session = session

    try:
        summary = runtime.loop.run(session, task, source_trust="TRUSTED", auto_sync_wiki=False)
        print_agent_summary(summary, out=out)
        runtime.tasks_completed += 1
        runtime.token = session.active_token

        if runtime.reviewer_enabled:
            written_py_files = _extract_written_python_files(summary, runtime.workspace_dir)
            if not written_py_files:
                written_py_files = _recover_unexecuted_python_write_via_kernel(runtime, summary, out=out)
            for py_file in written_py_files:
                loop_res = runtime.dual_reviewer.run_verified_coding_loop(
                    py_file,
                    task_description=task,
                    workspace_dir=runtime.workspace_dir,
                    coder_provider=runtime.provider,
                    coder_model=runtime.model,
                    auto_repair=runtime.auto_repair_enabled,
                )
                print(DualModelReviewer.format_verdict_for_user(loop_res), file=out)
    except CanaryTripwireError as exc:
        print(format_security_error(exc), file=out)
        print("[info] Canary tripwire fired; token revoked. A new token will be issued on the next task.", file=out)
        refresh_chat_token(runtime)
    except ActiveSecError as exc:
        print(format_security_error(exc), file=out)
        if runtime.engine.is_revoked(runtime.token.token_id):
            refresh_chat_token(runtime)


def sync_wiki_for_runtime(runtime: ChatRuntime, *, quiet: bool = False) -> bool:
    """Synchronize Karpathy wiki with current audit telemetry."""
    try:
        ok, _ = runtime.kernel.wiki_manager.sync_all(
            execute_pytest=False,
            audit_log=runtime.audit_log,
            session_label="cli_chat",
            quiet=quiet,
        )
        return bool(ok)
    except ActiveSecError as exc:
        print(format_security_error(exc), file=sys.stderr)
        return False


def iter_repl_lines(input_stream: TextIO) -> Iterator[str]:
    """Yield REPL lines until EOF."""
    while True:
        try:
            line = input_stream.readline()
        except KeyboardInterrupt:
            yield "/quit"
            return
        if line == "":
            return
        yield line


def run_interactive_chat(
    runtime: ChatRuntime,
    *,
    input_stream: TextIO = sys.stdin,
    output_stream: TextIO = sys.stdout,
    sync_wiki_on_exit: bool = False,
    banner: bool = True,
) -> int:
    """Run the interactive chat REPL until ``/quit`` or EOF."""
    if banner:
        print("=== ActiveSecHarness Interactive Chat (Ring-3 + Dual-Model Verifier) ===", file=output_stream)
        print(
            f"Coder: {runtime.provider}/{runtime.model} | "
            f"Reviewer: {runtime.dual_reviewer.reviewer_provider}/{runtime.dual_reviewer.reviewer_model}",
            file=output_stream,
        )
        print(f"Workspace: {runtime.workspace_dir}", file=output_stream)
        print("Commands: /status  /models  /test  /waive  /promote-test  /learn  /wiki  /quit", file=output_stream)
        if runtime.provider == "ollama" and not runtime.digest_pinning_enabled:
            print(
                "[residual_risk] Ollama model digest pinning is not configured "
                "(expected_sha256_digests empty). Endpoint remains pinned to "
                "127.0.0.1:11434 with mutation APIs blocked.",
                file=output_stream,
            )
        print("Enter a coding task, or /quit to exit.", file=output_stream)

    for raw in iter_repl_lines(input_stream):
        cmd = parse_repl_line(raw)
        if cmd.kind == "empty":
            continue
        if cmd.kind == "quit":
            break
        if cmd.kind == "unknown":
            print(
                f"[error] Unknown command '{cmd.payload}'. Try /status, /models, /test, /waive, /promote-test, /learn, /wiki, /quit.",
                file=output_stream,
            )
            continue
        if cmd.kind == "waive":
            parts = cmd.payload.split(maxsplit=2)
            if len(parts) < 3:
                print(
                    "[error] Usage: `/waive <filename> <rule_id> <justification>` (e.g. `/waive build_zip.py EXTRACTALL Trusted internal fixture`)",
                    file=output_stream,
                )
                continue
            fname, rule_id, justification = parts[0], parts[1], parts[2]
            target_f = fname if os.path.isabs(fname) else os.path.join(runtime.workspace_dir, fname)
            try:
                waiver = runtime.code_verifier.grant_context_waiver(
                    file_path=target_f,
                    rule_id=rule_id,
                    justification=justification,
                    granted_by_ring=1,
                )
                runtime.audit_log.append_event(
                    event_type="RING1_CONTEXT_WAIVER_GRANTED",
                    actor_id="ring1_operator",
                    ring_level=1,
                    vector_id="NONE",
                    details={
                        "file_path": waiver.canonical_file_path,
                        "justification": waiver.justification,
                        "rule_id": waiver.rule_id,
                        "waiver_id": waiver.waiver_id,
                    },
                )
                print(
                    f"[waive] Granted Ring-1 ContextWaiver '{waiver.waiver_id}' for rule '{waiver.rule_id}' on {os.path.basename(waiver.canonical_file_path)}.",
                    file=output_stream,
                )
            except ActiveSecError as exc:
                print(format_security_error(exc), file=output_stream)
            continue
        if cmd.kind == "promote_test":
            test_id = cmd.payload.strip()
            if not test_id:
                print("[error] Usage: `/promote-test <test_id>`", file=output_stream)
                continue
            try:
                promoted = runtime.dual_reviewer.test_synthesizer.promote_verified_test(
                    test_id,
                    authorized_by_ring=1,
                )
                runtime.audit_log.append_event(
                    event_type="RING1_TEST_PROMOTED_TO_CATALOG",
                    actor_id="ring1_operator",
                    ring_level=1,
                    vector_id="NONE",
                    details={
                        "target_file": promoted.target_file_path,
                        "test_id": promoted.test_id,
                        "test_script": promoted.test_script_path,
                    },
                )
                print(
                    f"[promote-test] Promoted verified test '{promoted.test_id}' into reusable project catalog.",
                    file=output_stream,
                )
            except ActiveSecError as exc:
                print(format_security_error(exc), file=output_stream)
            continue
        if cmd.kind == "status":
            for line in status_lines(runtime):
                print(line, file=output_stream)
            continue
        if cmd.kind == "models":
            handle_models_command(runtime, cmd.payload, out=output_stream)
            continue
        if cmd.kind == "learn":
            print(runtime.user_wiki_manager.format_terminal_summary(), file=output_stream)
            continue
        if cmd.kind == "test":
            py_files = sorted(Path(runtime.workspace_dir).glob("*.py"))
            if not py_files:
                print("[test] No Python files found in workspace.", file=output_stream)
                continue
            for py_f in py_files:
                rep = runtime.code_verifier.verify_python_file(str(py_f), workspace_dir=runtime.workspace_dir)
                state = "APPROVED (SAFE)" if rep.approved_for_execution else "BLOCKED (UNSAFE)"
                print(
                    f"[test:{py_f.name}] {state} via SoD sub-agent {rep.sod_sub_agent_id} "
                    f"(ast_findings={len(rep.ast_findings)}, probes={len(rep.probe_outcomes)})",
                    file=output_stream,
                )
                if not rep.approved_for_execution and runtime.reviewer_enabled:
                    loop_res = runtime.dual_reviewer.run_verified_coding_loop(
                        str(py_f),
                        task_description=f"Verify and repair workspace Python module {py_f.name}",
                        workspace_dir=runtime.workspace_dir,
                        coder_provider=runtime.provider,
                        coder_model=runtime.model,
                        auto_repair=runtime.auto_repair_enabled,
                    )
                    print(DualModelReviewer.format_verdict_for_user(loop_res), file=output_stream)
                    post_rep = loop_res.final_verdict.deterministic_report
                    post_state = "APPROVED (SAFE)" if loop_res.approved_for_execution else "BLOCKED (UNSAFE)"
                    print(
                        f"[test:{py_f.name}:post-repair] {post_state} via SoD sub-agent {post_rep.sod_sub_agent_id} "
                        f"(ast_findings={len(post_rep.ast_findings)}, probes={len(post_rep.probe_outcomes)})",
                        file=output_stream,
                    )
            continue
        if cmd.kind == "wiki":
            ok = sync_wiki_for_runtime(runtime, quiet=False)
            print("[wiki] sync ok" if ok else "[wiki] sync failed", file=output_stream)
            continue
        if cmd.kind == "task":
            print(f"[task] {cmd.payload}", file=output_stream)
            run_chat_task(runtime, cmd.payload, out=output_stream)
            continue

    if sync_wiki_on_exit:
        ok = sync_wiki_for_runtime(runtime, quiet=False)
        print("[wiki] exit sync ok" if ok else "[wiki] exit sync failed", file=output_stream)

    try:
        runtime.audit_log.verify_chain()
    except ActiveSecError as exc:
        print(format_security_error(exc), file=sys.stderr)
        return 1
    return 0


def run_scripted_chat(
    lines: Iterable[str],
    *,
    workspace_dir: str,
    provider: str = "openrouter",
    model: Optional[str] = None,
    max_steps: int = DEFAULT_CHAT_MAX_STEPS,
    reviewer_enabled: bool = True,
    auto_repair_enabled: bool = True,
    user_wiki_dir: Optional[str] = None,
    transport_func=None,
    api_key: Optional[str] = "scripted-test-key",
    sync_wiki_on_exit: bool = False,
    output_stream: Optional[TextIO] = None,
) -> int:
    """Run a non-interactive scripted chat session (used by offline tests)."""
    out = output_stream or sys.stdout
    runtime = build_chat_runtime(
        workspace_dir=workspace_dir,
        provider=provider,
        model=model,
        max_steps=max_steps,
        reviewer_enabled=reviewer_enabled,
        auto_repair_enabled=auto_repair_enabled,
        user_wiki_dir=user_wiki_dir,
        transport_func=transport_func,
        api_key=api_key,
        skip_provider_probe=True,
    )
    from io import StringIO

    buf = StringIO("\n".join(lines) + "\n")
    return run_interactive_chat(
        runtime,
        input_stream=buf,
        output_stream=out,
        sync_wiki_on_exit=sync_wiki_on_exit,
        banner=False,
    )


def run_self_test() -> int:
    """Execute a live deterministic end-to-end demonstration of ActiveSecHarness."""
    print("=== ActiveSecHarness Ring-0 MVP Self-Test ===")
    with tempfile.TemporaryDirectory(prefix="activesec_selftest_") as tmp_dir:
        workspace = os.path.join(tmp_dir, "workspace")
        os.makedirs(workspace, mode=0o700, exist_ok=True)

        # Create a benign workspace file
        hello_path = os.path.join(workspace, "hello.txt")
        with open(hello_path, "w", encoding="utf-8") as fh:
            fh.write("ActiveSecHarness verified workspace artifact.\n")

        engine = CapabilityEngine()
        audit_log = HashChainedAuditLog()
        canary_guard = CanaryGuard(on_tripwire=engine.revoke_token)
        canaries = canary_guard.deploy_default_canaries(workspace_dir=workspace)
        honeyfile_path = next(c.honeypot_path for c in canaries if c.honeypot_path is not None)

        kernel = SecurityKernel(
            workspace_dir=workspace,
            capability_engine=engine,
            audit_log=audit_log,
            canary_guard=canary_guard,
        )

        # Deterministic offline mock transport for self-test
        call_counter = {"step": 0}

        def _selftest_transport(
            url: str,
            body: bytes,
            headers: Mapping[str, str],
            tls_context: Optional[ssl.SSLContext],
            timeout: float,
            max_response_bytes: int,
        ) -> bytes:
            call_counter["step"] += 1
            step = call_counter["step"]
            if step == 1:
                resp = {
                    "model": "qwen/qwen3-coder",
                    "choices": [
                        {
                            "message": {
                                "content": "Reading workspace file hello.txt.",
                                "tool_call": {
                                    "tool_name": "fs:read",
                                    "target_path": hello_path,
                                },
                            }
                        }
                    ],
                }
            elif step == 2:
                resp = {
                    "model": "qwen/qwen3-coder",
                    "choices": [
                        {
                            "message": {
                                "content": "Workspace file verified successfully.",
                            }
                        }
                    ],
                }
            else:
                # Step 3: Simulate an injected agent attempting to read the Canary honeyfile
                resp = {
                    "model": "qwen/qwen3-coder",
                    "choices": [
                        {
                            "message": {
                                "content": "Attempting to harvest credentials.",
                                "tool_call": {
                                    "tool_name": "fs:read",
                                    "target_path": honeyfile_path,
                                },
                            }
                        }
                    ],
                }
            return json.dumps(resp).encode("utf-8")

        mock_key = "selftest"
        gateway = ModelGateway(
            openrouter_config=OpenRouterConfig(),
            ollama_config=OllamaLocalConfig(),
            canary_guard=canary_guard,
            capability_engine=engine,
            transport_func=_selftest_transport,
            api_key=mock_key,
        )

        caveat = CapabilityCaveat(
            allowed_tools=frozenset({"fs:read", "fs:write"}),
            path_prefixes=(workspace,),
            max_calls=5,
            expires_at_unix=time.time() + 300.0,
            require_untainted_context=True,
        )
        token = engine.issue_root_token(
            subject_agent_id="selftest-agent",
            task_purpose="Self-test workspace read",
            caveat=caveat,
        )

        session = AgentSession(agent_id="selftest-agent", active_token=token, max_steps=5)
        loop = AgentLoop(kernel=kernel, gateway=gateway, role=ModelRole.CODING, prefer_provider="openrouter")

        # 1. Run benign task
        summary = loop.run(session, "Read hello.txt and summarize.")
        print(f"[PASS] Benign task completed in {summary.steps_executed} steps: '{summary.final_answer}'")

        # 2. Simulate adversarial Canary honeyfile access and verify immediate block & token revocation
        canary_blocked = False
        try:
            loop.step(session)
        except CanaryTripwireError as exc:
            canary_blocked = True
            print(f"[PASS] Adversarial Canary access blocked & token revoked: {exc}")

        if not canary_blocked:
            print("[FAIL] Canary tripwire did not trigger!", file=sys.stderr)
            return 1

        # 3. Verify cryptographic audit log chain
        audit_log.verify_chain()
        print(f"[PASS] HashChainedAuditLog verified ({len(audit_log.entries)} tamper-evident entries).")

        # 4. Synchronize runtime security telemetry with the Ring-0 Karpathy WikiManager
        telemetry = kernel.sync_runtime_wiki(session_label="cli_self_test", execute_pytest=False, quiet=True)
        print(
            f"[PASS] Karpathy WikiManager synchronized runtime telemetry "
            f"(events={telemetry.total_events}, allowed={telemetry.allowed_tool_calls}, "
            f"canary_alerts={telemetry.canary_alerts}, vectors={list(telemetry.triggered_vectors)})."
        )
        return 0


def _default_workspace_path() -> str:
    return str((Path.cwd() / DEFAULT_WORKSPACE_NAME).resolve())


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="activesec",
        description="ActiveSecHarness: Ring-0 Security Kernel & Capability-Mediated Agent Harness",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run a live deterministic end-to-end verification of safe execution and blocked attack vectors.",
    )
    parser.add_argument(
        "--sync-wiki",
        action="store_true",
        help="Run the native Ring-0 WikiManager to audit ASTs, execute security tests, and synchronize wiki/.",
    )
    parser.add_argument(
        "--chat",
        action="store_true",
        help="Start an interactive Ring-3 coding chat REPL mediated by SecurityKernel.",
    )
    parser.add_argument(
        "--provider",
        choices=("openrouter", "ollama"),
        default="ollama",
        help="Model provider for --chat coder (default: ollama).",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Optional coder model identifier override (must be allowlisted / installed).",
    )
    parser.add_argument(
        "--reviewer-provider",
        choices=("openrouter", "ollama"),
        default="openrouter",
        help="Second reviewer model provider (default: openrouter).",
    )
    parser.add_argument(
        "--reviewer-model",
        type=str,
        default=None,
        help="Optional reviewer model identifier override.",
    )
    parser.add_argument(
        "--no-auto-repair",
        action="store_true",
        help="Disable automatic self-healing Fix-Test-Verify repair loop when unsafe code is detected.",
    )
    parser.add_argument(
        "--workspace",
        type=str,
        default=None,
        help=f"Workspace directory for --chat (default: ./{DEFAULT_WORKSPACE_NAME}).",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=DEFAULT_CHAT_MAX_STEPS,
        help=f"Maximum AgentLoop steps per user task (default: {DEFAULT_CHAT_MAX_STEPS}).",
    )
    parser.add_argument(
        "--sync-wiki-on-exit",
        action="store_true",
        help="When used with --chat, synchronize the Karpathy wiki on REPL exit.",
    )
    args = parser.parse_args(argv)

    if args.sync_wiki and not args.chat:
        try:
            manager = WikiManager()
            ok, _ = manager.sync_all(execute_pytest=True, quiet=False)
            return 0 if ok else 1
        except ActiveSecError as exc:
            print(f"[ERROR] Wiki synchronization failed: {exc}", file=sys.stderr)
            return 1

    if args.self_test:
        try:
            return run_self_test()
        except ActiveSecError as exc:
            print(f"[ERROR] Security check failed during self-test: {exc}", file=sys.stderr)
            return 1

    if args.chat:
        workspace = args.workspace or _default_workspace_path()
        try:
            if args.max_steps < 1:
                raise ModelSecurityError(
                    "--max-steps must be >= 1.",
                    vector_id="E.2",
                    component_id="cli",
                )
            runtime = build_chat_runtime(
                workspace_dir=workspace,
                provider=args.provider,
                model=args.model,
                max_steps=args.max_steps,
                reviewer_provider=args.reviewer_provider,
                reviewer_model=args.reviewer_model,
                auto_repair_enabled=not args.no_auto_repair,
            )
            return run_interactive_chat(
                runtime,
                sync_wiki_on_exit=bool(args.sync_wiki_on_exit or args.sync_wiki),
            )
        except ActiveSecError as exc:
            print(format_security_error(exc), file=sys.stderr)
            return 1

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
