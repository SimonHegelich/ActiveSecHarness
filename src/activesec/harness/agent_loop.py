"""Ring-2 Minimal Object-Oriented AgentLoop & Taint-Tracking AgentSession.

Inspired by mini-swe-agent, this module keeps the agent loop small, transparent, and strictly
confined to Ring 2:
1. Tracks conversation history (`messages`), monotonic `context_tainted` state, `active_token`,
   and `step_count` bounded by `max_steps`.
2. Marks `context_tainted = True` permanently for the session whenever untrusted external data
   (`source_trust="UNTRUSTED"`) is ingested into the agent's context window.
3. Routes all LLM inference through `ModelGateway` and all tool calls exclusively through
   the Ring-0 `SecurityKernel`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

from activesec.core.capability_token import CapabilityToken
from activesec.core.component import ComponentSecurityAssessment, SecureComponent
from activesec.core.exceptions import (
    ActiveSecError,
    CanaryTripwireError,
    CapabilityViolationError,
)
from activesec.core.security_kernel import SecurityKernel, ToolExecutionResult
from activesec.core.wiki_manager import WikiManager
from activesec.harness.model_gateway import (
    ChatMessage,
    ModelGateway,
    ModelResponse,
    ModelRole,
)


@dataclass(frozen=True, slots=True)
class AgentStepOutcome:
    """Immutable record of a single agent reasoning + kernel-mediated tool step."""

    step_index: int
    model_response: ModelResponse
    tool_result: Optional[ToolExecutionResult]
    blocked_error: Optional[ActiveSecError]
    finished: bool


@dataclass(frozen=True, slots=True)
class AgentRunSummary:
    """Immutable summary of a completed or halted agent loop execution."""

    agent_id: str
    steps_executed: int
    final_answer: str
    context_tainted: bool
    outcomes: Tuple[AgentStepOutcome, ...]


class AgentSession:
    """Session state container tracking messages, taint status, capability token, and step quota."""

    def __init__(
        self,
        *,
        agent_id: str,
        active_token: CapabilityToken,
        max_steps: int = 15,
        system_prompt: str = (
            "You are an ActiveSecHarness Ring-2 coding agent. Every tool invocation is mediated "
            "by the Ring-0 SecurityKernel."
        ),
    ) -> None:
        if max_steps < 1:
            raise CapabilityViolationError(
                "AgentSession max_steps must be >= 1.",
                vector_id="E.2",
                component_id="agent_loop",
            )
        self._agent_id: str = agent_id
        self._active_token: CapabilityToken = active_token
        self._max_steps: int = max_steps
        self._context_tainted: bool = False
        self._step_count: int = 0
        self._messages: List[ChatMessage] = [
            ChatMessage(role="system", content=system_prompt),
        ]

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @property
    def active_token(self) -> CapabilityToken:
        return self._active_token

    @property
    def max_steps(self) -> int:
        return self._max_steps

    @property
    def context_tainted(self) -> bool:
        return self._context_tainted

    @property
    def step_count(self) -> int:
        return self._step_count

    @property
    def messages(self) -> Tuple[ChatMessage, ...]:
        return tuple(self._messages)

    def update_token(self, new_token: CapabilityToken) -> None:
        """Replace the active token (e.g., with an attenuated token)."""
        self._active_token = new_token

    def ingest_message(
        self,
        content: str,
        *,
        role: str = "user",
        source_trust: str = "TRUSTED",
    ) -> None:
        """Append a message to the session and taint the context if source_trust is UNTRUSTED."""
        normalized_trust = source_trust.strip().upper()
        if normalized_trust != "TRUSTED":
            # Monotonic taint latch: once tainted by untrusted data, context remains tainted
            self._context_tainted = True
        self._messages.append(ChatMessage(role=role, content=content))


class AgentLoop(SecureComponent):
    """Ring-2 minimal agent execution loop mediated by ModelGateway and SecurityKernel."""

    def __init__(
        self,
        *,
        kernel: SecurityKernel,
        gateway: ModelGateway,
        role: ModelRole = ModelRole.CODING,
        prefer_provider: str = "openrouter",
        halt_on_security_violation: bool = True,
        wiki_manager: Optional[WikiManager] = None,
    ) -> None:
        self._kernel = kernel
        self._gateway = gateway
        self._role = role
        self._prefer_provider = prefer_provider
        self._halt_on_security_violation = halt_on_security_violation
        self._wiki_manager: WikiManager = wiki_manager or kernel.wiki_manager

    @classmethod
    def security_assessment(cls) -> ComponentSecurityAssessment:
        return ComponentSecurityAssessment(
            component_id="agent_loop",
            title="Ring-2 Taint-Tracking Agent Loop & Kernel-Mediated Executor",
            ring_level=2,
            source_path="src/activesec/harness/agent_loop.py",
            security_test_path="tests/security/test_sec_agent_loop.py",
            threat_vectors=("A.1", "E.2", "F.2", "F.3"),
            summary=(
                "Implements a minimal, inspectable Ring-2 agent execution loop inspired by "
                "mini-swe-agent. Tracks monotonic prompt-injection taint across untrusted data "
                "ingestion, enforces hard step budgets, delegates all LLM calls through "
                "ModelGateway, and executes every tool call exclusively via SecurityKernel."
            ),
            enforced_invariants=(
                "Has zero direct filesystem, subprocess, or socket execution primitives; all tool calls pass through SecurityKernel.execute_tool_call().",
                "Monotonically latches session.context_tainted = True whenever source_trust != 'TRUSTED' data is ingested.",
                "Propagates context_tainted and active_token to both ModelGateway.chat() and SecurityKernel.execute_tool_call().",
                "Enforces a hard per-session step limit (max_steps) and immediately halts on CanaryTripwireError.",
            ),
            residual_risks=(
                "An untainted agent may still make non-malicious mistakes within its explicitly permitted workspace subdirectory (mitigated by narrow CapabilityCaveat scoping).",
            ),
        )

    def step(self, session: AgentSession) -> AgentStepOutcome:
        """Execute a single reasoning and tool-mediation step."""
        if session.step_count >= session.max_steps:
            raise CapabilityViolationError(
                f"AgentSession exceeded max_steps ({session.max_steps}).",
                vector_id="E.2",
                component_id="agent_loop",
            )

        session._step_count += 1
        model_resp = self._gateway.chat(
            session.messages,
            role=self._role,
            prefer_provider=self._prefer_provider,
            capability_token=session.active_token,
            agent_id=session.agent_id,
            context_tainted=session.context_tainted,
        )
        session.ingest_message(model_resp.content, role="assistant", source_trust="TRUSTED")

        if model_resp.tool_call is None:
            return AgentStepOutcome(
                step_index=session.step_count,
                model_response=model_resp,
                tool_result=None,
                blocked_error=None,
                finished=True,
            )

        try:
            tool_res = self._kernel.execute_tool_call(
                model_resp.tool_call,
                token=session.active_token,
                agent_id=session.agent_id,
                context_tainted=session.context_tainted,
            )
        except CanaryTripwireError:
            # Never continue after a zero-false-positive canary tripwire
            raise
        except ActiveSecError as exc:
            if self._halt_on_security_violation:
                raise
            session.ingest_message(
                f"[SECURITY_KERNEL_BLOCKED:{exc.vector_id}] {exc.message}",
                role="user",
                source_trust="TRUSTED",
            )
            return AgentStepOutcome(
                step_index=session.step_count,
                model_response=model_resp,
                tool_result=None,
                blocked_error=exc,
                finished=False,
            )

        session.ingest_message(
            f"[OBSERVATION:{tool_res.tool_name}] {tool_res.output}",
            role="user",
            source_trust="TRUSTED",
        )
        return AgentStepOutcome(
            step_index=session.step_count,
            model_response=model_resp,
            tool_result=tool_res,
            blocked_error=None,
            finished=False,
        )

    def run(
        self,
        session: AgentSession,
        task_prompt: Optional[str] = None,
        *,
        source_trust: str = "TRUSTED",
        auto_sync_wiki: bool = False,
    ) -> AgentRunSummary:
        """Run the agent loop until completion, security halt, or max_steps."""
        if task_prompt is not None:
            session.ingest_message(task_prompt, role="user", source_trust=source_trust)

        outcomes: List[AgentStepOutcome] = []
        final_answer = ""

        try:
            while session.step_count < session.max_steps:
                outcome = self.step(session)
                outcomes.append(outcome)
                if outcome.finished:
                    final_answer = outcome.model_response.content
                    break
        finally:
            if auto_sync_wiki:
                self._wiki_manager.sync_all(
                    execute_pytest=False,
                    audit_log=self._kernel.audit_log,
                    session_label=f"agent_loop:{session.agent_id}",
                    quiet=True,
                )

        return AgentRunSummary(
            agent_id=session.agent_id,
            steps_executed=session.step_count,
            final_answer=final_answer,
            context_tainted=session.context_tainted,
            outcomes=tuple(outcomes),
        )
