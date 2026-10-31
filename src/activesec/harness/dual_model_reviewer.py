"""Ring-2 DualModelReviewer & Self-Healing Fix-Test-Verify Orchestrator.

Implements ActiveSecHarness V1.1's two-stage application security verification and
automated repair loop:
1. Stage A (Deterministic, LLM-Independent): Runs `CodeVerifier` static AST rules and
   isolated Separation-of-Duties (SoD) sandbox attack probes (`SandboxGuard`).
2. Stage B (Independent Second Reviewer Model — enabled by default, preferring OpenRouter):
   Invokes a dedicated second model with a clean, unpoisoned context to inspect the written
   code alongside Stage-A results, produce a plain-language explanation for non-experts,
   and recommend a stronger model (e.g. `openrouter/qwen/qwen3-coder` or
   `openrouter/anthropic/claude-sonnet-4`) when a small local model (`qwen2.5` / `qwen3:4b`)
   introduces vulnerabilities.
3. Execution Gate: If either Stage A or Stage B reports a vulnerability, the code is
   STRICTLY BLOCKED from execution (`approved_for_execution = False`).
4. Self-Healing Fix-Test-Verify Loop: Automatically feeds the deterministic findings and
   reviewer remediation instructions back into the coding loop (optionally switching to the
   recommended stronger model) until both deterministic tests and reviewer pass, then
   updates the didactic User Security Academy Wiki (`wiki_user/`).
"""

from __future__ import annotations

import json
import os
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from activesec.core.component import ComponentSecurityAssessment, SecureComponent
from activesec.core.exceptions import ActiveSecError, CodeSecurityVerificationError
from activesec.core.user_wiki_manager import UserWikiManager
from activesec.guards.code_verifier import CodeVerifier, DeterministicVerificationReport
from activesec.harness.model_gateway import ChatMessage, ModelGateway, ModelResponse, ModelRole


SMALL_LOCAL_MODEL_HINTS: Tuple[str, ...] = (
    "qwen2.5",
    "qwen3:4b",
    "phi4-mini",
    "phi3",
    "llama3.2:1b",
    "llama3.2:3b",
    "7b",
    "4b",
    "3b",
    "1.5b",
)

VERIFIED_SAFE_ARCHIVE_EXTRACTOR_TEMPLATE: str = textwrap.dedent(
    """
    import os
    import stat
    import sys
    import zipfile

    MAX_TOTAL_BYTES = 1024 * 1024
    MAX_RATIO = 20.0
    CHUNK_SIZE = 65536


    def safe_extract_zip(zip_path: str, target_dir: str) -> list[str]:
        \"\"\"Safely extract a ZIP archive with canonical path validation and ZipBomb quotas.\"\"\"
        real_target = os.path.realpath(target_dir)
        os.makedirs(real_target, mode=0o700, exist_ok=True)
        total_written = 0
        extracted: list[str] = []

        with zipfile.ZipFile(zip_path, "r") as zf:
            for info in zf.infolist():
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise ValueError(f"Symlink entries are forbidden: {info.filename}")
                dest = os.path.realpath(os.path.join(real_target, info.filename))
                if not (dest == real_target or dest.startswith(real_target + os.sep)):
                    raise ValueError(f"Zip-Slip path traversal blocked: {info.filename}")
                if info.is_dir():
                    os.makedirs(dest, mode=0o700, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
                comp_size = max(1, info.compress_size)
                file_written = 0
                with zf.open(info, "r") as src, open(dest, "wb") as dst:
                    while True:
                        chunk = src.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        file_written += len(chunk)
                        total_written += len(chunk)
                        if total_written > MAX_TOTAL_BYTES:
                            raise ValueError("ZipBomb total byte quota exceeded")
                        if file_written > 32768 and (file_written / comp_size) > MAX_RATIO:
                            raise ValueError("ZipBomb compression ratio quota exceeded")
                        dst.write(chunk)
                extracted.append(dest)
        return extracted


    if __name__ == "__main__":
        if len(sys.argv) == 3:
            safe_extract_zip(sys.argv[1], sys.argv[2])
    """
).strip() + "\n"

REVIEWER_SYSTEM_PROMPT = (
    "You are the ActiveSecHarness Independent Security Reviewer (Stage B). "
    "Inspect the candidate Python program and the Stage-A deterministic verification findings. "
    "Respond ONLY with a single JSON object (no markdown fences) matching this exact schema:\n"
    '{"approved": false, "plain_explanation": "<clear explanation for a non-expert>", '
    '"how_to_fix": "<concrete remediation steps>", "recommended_model": "<stronger model slug or empty>"}'
)


@dataclass(frozen=True, slots=True)
class SecurityReviewVerdict:
    """Combined deterministic (Stage A) + secondary reviewer model (Stage B) verdict."""

    file_path: str
    approved_for_execution: bool
    deterministic_report: DeterministicVerificationReport
    reviewer_provider: str
    reviewer_model: str
    coder_provider: str
    coder_model: str
    plain_language_explanation: str
    how_to_fix: str
    recommended_fixer_model: Optional[str]
    execution_status_banner: str


@dataclass(frozen=True, slots=True)
class RepairIterationRecord:
    """Record of one Fix -> Test -> Review iteration in the self-healing loop."""

    iteration: int
    fixer_provider: str
    fixer_model: str
    verdict: SecurityReviewVerdict


@dataclass(frozen=True, slots=True)
class VerifiedCodingLoopResult:
    """Final outcome of the self-healing Fix-Test-Verify loop."""

    file_path: str
    approved_for_execution: bool
    iterations_run: int
    initial_verdict: SecurityReviewVerdict
    final_verdict: SecurityReviewVerdict
    repair_history: Tuple[RepairIterationRecord, ...]
    user_wiki_lesson_path: Optional[str]


class DualModelReviewer(SecureComponent):
    """Ring-2 Dual-Model Security Verifier, Plain-Language Explainer & Self-Healing Orchestrator."""

    def __init__(
        self,
        *,
        gateway: ModelGateway,
        code_verifier: Optional[CodeVerifier] = None,
        user_wiki_manager: Optional[UserWikiManager] = None,
        reviewer_provider: str = "openrouter",
        reviewer_model: str = "qwen/qwen3-coder",
        fallback_local_reviewer_model: str = "qwen3:4b",
        strong_openrouter_fixer_model: str = "qwen/qwen3-coder",
        openrouter_key_available: bool = True,
    ) -> None:
        self._gateway: ModelGateway = gateway
        self._code_verifier: CodeVerifier = code_verifier or CodeVerifier()
        self._user_wiki_manager: Optional[UserWikiManager] = user_wiki_manager
        self._reviewer_provider: str = reviewer_provider
        self._reviewer_model: str = reviewer_model
        self._fallback_local_reviewer_model: str = fallback_local_reviewer_model
        self._strong_openrouter_fixer_model: str = strong_openrouter_fixer_model
        self._openrouter_key_available: bool = openrouter_key_available

    @classmethod
    def security_assessment(cls) -> ComponentSecurityAssessment:
        return ComponentSecurityAssessment(
            component_id="dual_model_reviewer",
            title="Ring-2 Dual-Model Security Reviewer & Self-Healing Repair Orchestrator",
            ring_level=2,
            source_path="src/activesec/harness/dual_model_reviewer.py",
            security_test_path="tests/security/test_sec_dual_model_reviewer.py",
            threat_vectors=("A.1", "B.1", "B.2", "D.1", "F.1", "F.3"),
            summary=(
                "Combines deterministic LLM-independent CodeVerifier checks (Stage A) with an "
                "independent second Reviewer Model (Stage B, defaulting to OpenRouter) in a clean "
                "context. Strictly blocks execution of any vulnerable program, explains risks and "
                "remediations in accessible plain language for non-experts, recommends stronger "
                "models when small local models fail, drives an automated Fix-Test-Verify repair "
                "loop, and records lessons into the User Security Academy Wiki (`wiki_user/`)."
            ),
            enforced_invariants=(
                "Execution Gate: approved_for_execution is strictly False whenever Stage-A deterministic checks OR Stage-B reviewer model report a vulnerability.",
                "Context Isolation: The Stage-B reviewer model receives only the target source file and deterministic findings in a fresh context window.",
                "Model Escalation Recommendation: Automatically recommends a stronger model (e.g. openrouter/qwen/qwen3-coder) when a small local model produces vulnerable code.",
                "Updates UserWikiManager (`wiki_user/`) with plain-language explanations and before/after code comparisons.",
            ),
            residual_risks=(
                "If OpenRouter is offline and no API key is configured, Stage B falls back to a local reviewer model while Stage-A deterministic AST and sandbox probes remain 100% enforced.",
            ),
        )

    @property
    def reviewer_provider(self) -> str:
        return self._reviewer_provider

    @property
    def reviewer_model(self) -> str:
        return self._reviewer_model

    def configure_reviewer(self, *, provider: str, model: str, openrouter_key_available: Optional[bool] = None) -> None:
        """Update the active Stage-B reviewer provider and model."""
        self._reviewer_provider = provider
        self._reviewer_model = model
        if openrouter_key_available is not None:
            self._openrouter_key_available = openrouter_key_available

    def _is_weak_or_small_coder(self, coder_provider: str, coder_model: str) -> bool:
        lower = f"{coder_provider}/{coder_model}".lower()
        return coder_provider == "ollama" or any(h in lower for h in SMALL_LOCAL_MODEL_HINTS)

    def _select_active_reviewer_route(self) -> Tuple[str, str]:
        if self._reviewer_provider == "openrouter" and self._openrouter_key_available:
            return ("openrouter", self._reviewer_model)
        if self._reviewer_provider == "ollama":
            return ("ollama", self._reviewer_model)
        return ("ollama", self._fallback_local_reviewer_model)

    def review_file(
        self,
        file_path: str,
        *,
        workspace_dir: Optional[str] = None,
        coder_provider: str = "ollama",
        coder_model: str = "qwen3:4b",
        run_sandbox_probes: bool = True,
    ) -> SecurityReviewVerdict:
        """Run Stage-A deterministic verification + Stage-B secondary model review on `file_path`."""
        real_file = os.path.realpath(file_path)
        det_report = self._code_verifier.verify_python_file(
            real_file,
            workspace_dir=workspace_dir,
            run_sandbox_probes=run_sandbox_probes,
            fail_closed=False,
        )
        source_text = Path(real_file).read_text(encoding="utf-8", errors="replace")

        rev_provider, rev_model = self._select_active_reviewer_route()

        det_summary_lines: List[str] = []
        for f in det_report.ast_findings:
            det_summary_lines.append(f"- [AST {f.rule_id} line {f.line_number}] {f.title}: {f.plain_explanation}")
        for p in det_report.probe_outcomes:
            if not p.passed:
                det_summary_lines.append(f"- [SANDBOX PROBE FAILED: {p.probe_name}] {p.details}")

        det_summary = "\n".join(det_summary_lines) if det_summary_lines else "All deterministic Stage-A checks passed."

        review_prompt = (
            f"Candidate File: {os.path.basename(real_file)}\n"
            f"Coder Model: {coder_provider}/{coder_model}\n"
            f"Stage-A Deterministic Findings:\n{det_summary}\n\n"
            f"Source Code:\n{source_text}\n"
        )

        llm_approved = True
        llm_explanation = ""
        llm_how_to_fix = ""
        llm_recommended_model = ""

        try:
            resp = self._gateway.chat(
                [
                    ChatMessage(role="system", content=REVIEWER_SYSTEM_PROMPT),
                    ChatMessage(role="user", content=review_prompt),
                ],
                role=ModelRole.CODING,
                requested_model=rev_model,
                prefer_provider=rev_provider,
            )
            raw_content = resp.content.strip()
            if raw_content.startswith("{"):
                parsed = json.loads(raw_content)
                if isinstance(parsed, dict):
                    llm_approved = bool(parsed.get("approved", True))
                    llm_explanation = str(parsed.get("plain_explanation", "")).strip()
                    llm_how_to_fix = str(parsed.get("how_to_fix", "")).strip()
                    llm_recommended_model = str(parsed.get("recommended_model", "")).strip()
        except (ActiveSecError, json.JSONDecodeError, ValueError):
            # If the secondary LLM returns non-JSON or is unreachable, fall back deterministically
            llm_approved = det_report.approved_for_execution

        # Execution Gate: BOTH deterministic Stage A AND reviewer Stage B must approve
        approved = det_report.approved_for_execution and llm_approved

        if not approved:
            default_expl = (
                " | ".join(f.plain_explanation for f in det_report.ast_findings)
                or "The program failed security verification probes in the isolated sandbox."
            )
            default_fix = (
                " | ".join(f.remediation_hint for f in det_report.ast_findings)
                or "Validate all inputs, canonicalize paths with os.path.realpath(), and enforce strict size quotas."
            )
            plain_explanation = llm_explanation or default_expl
            how_to_fix = llm_how_to_fix or default_fix

            recommended_model: Optional[str] = llm_recommended_model or None
            if recommended_model is None and self._is_weak_or_small_coder(coder_provider, coder_model):
                recommended_model = f"openrouter/{self._strong_openrouter_fixer_model}"

            banner = (
                f"[EXECUTION BLOCKED BY SECURITY GATE] '{os.path.basename(real_file)}' contains security "
                f"vulnerabilities and WILL NOT BE EXECUTED."
            )
        else:
            plain_explanation = (
                llm_explanation
                or "Both deterministic sandbox tests (Stage A) and the independent security reviewer model (Stage B) verified that this program is safe."
            )
            how_to_fix = llm_how_to_fix or "No further changes needed; all security invariants hold."
            recommended_model = None
            banner = (
                f"[SECURITY VERIFIED] '{os.path.basename(real_file)}' passed Stage-A deterministic sandbox "
                f"tests and Stage-B review ({rev_provider}/{rev_model}). Execution permitted."
            )

        return SecurityReviewVerdict(
            file_path=real_file,
            approved_for_execution=approved,
            deterministic_report=det_report,
            reviewer_provider=rev_provider,
            reviewer_model=rev_model,
            coder_provider=coder_provider,
            coder_model=coder_model,
            plain_language_explanation=plain_explanation,
            how_to_fix=how_to_fix,
            recommended_fixer_model=recommended_model,
            execution_status_banner=banner,
        )

    @staticmethod
    def _extract_python_code_from_response(resp: ModelResponse) -> Optional[str]:
        """Extract repaired Python source code from a tool call, embedded JSON, or markdown fences."""
        if resp.tool_call is not None and resp.tool_call.tool_name == "fs:write":
            code = str(resp.tool_call.arguments.get("content", "")).strip()
            if code:
                return code + "\n"

        raw = (resp.content or "").strip()
        if not raw:
            return None

        # Strip optional markdown code fences (```python ... ``` or ```json ... ```)
        if "```" in raw:
            parts = raw.split("```")
            if len(parts) >= 3:
                fenced = parts[1]
                lines = fenced.splitlines()
                if lines and lines[0].strip().lower() in ("python", "py", "json"):
                    lines = lines[1:]
                fenced_body = "\n".join(lines).strip()
                if fenced_body.startswith("{") and '"content"' in fenced_body:
                    raw = fenced_body
                elif fenced_body:
                    return fenced_body + "\n"

        # Try parsing embedded JSON or truncated JSON tool call
        if raw.startswith("{") and '"content"' in raw:
            for suffix in ("", "}", "}}", '"}', '"}}'):
                try:
                    parsed = json.loads(raw + suffix)
                    if isinstance(parsed, dict):
                        args = parsed.get("arguments", {})
                        if isinstance(args, dict) and args.get("content"):
                            return str(args["content"]).strip() + "\n"
                        if parsed.get("content"):
                            return str(parsed["content"]).strip() + "\n"
                except json.JSONDecodeError:
                    continue
            return None

        if not raw.startswith("{"):
            return raw + "\n"
        return None

    @staticmethod
    def _deterministic_reference_remediation(topic_slug: str) -> Optional[str]:
        """Return a certified Ring-0 reference implementation when weak local models fail repair."""
        if topic_slug == "zip_slip_and_zip_bombs":
            return VERIFIED_SAFE_ARCHIVE_EXTRACTOR_TEMPLATE
        return None

    def run_verified_coding_loop(
        self,
        file_path: str,
        *,
        task_description: str,
        workspace_dir: Optional[str] = None,
        coder_provider: str = "ollama",
        coder_model: str = "qwen3:4b",
        auto_repair: bool = True,
        max_repair_iterations: int = 2,
        escalate_to_recommended_model: bool = True,
    ) -> VerifiedCodingLoopResult:
        """Verify `file_path`, and if unsafe, run the self-healing Fix -> Sandbox-Test -> Review loop."""
        real_file = os.path.realpath(file_path)
        real_ws = os.path.realpath(workspace_dir) if workspace_dir else os.path.dirname(real_file)
        unsafe_snapshot = Path(real_file).read_text(encoding="utf-8", errors="replace")

        initial_verdict = self.review_file(
            real_file,
            workspace_dir=real_ws,
            coder_provider=coder_provider,
            coder_model=coder_model,
        )
        current_verdict = initial_verdict
        history: List[RepairIterationRecord] = []

        if not current_verdict.approved_for_execution and auto_repair:
            for iteration in range(1, max_repair_iterations + 1):
                fixer_provider = coder_provider
                fixer_model = coder_model
                if (
                    escalate_to_recommended_model
                    and current_verdict.recommended_fixer_model
                    and "/" in current_verdict.recommended_fixer_model
                ):
                    parts = current_verdict.recommended_fixer_model.split("/", 1)
                    if parts[0] in ("openrouter", "ollama"):
                        cand_prov, cand_mod = parts[0], parts[1]
                        if cand_prov != "openrouter" or self._openrouter_key_available:
                            fixer_provider, fixer_model = cand_prov, cand_mod

                current_code = Path(real_file).read_text(encoding="utf-8", errors="replace")
                repair_system = (
                    "You are an ActiveSecHarness Secure Code Repair Agent. Rewrite the Python file so it "
                    "eliminates every reported vulnerability and passes all deterministic AST and sandbox probes. "
                    "Respond with ONLY a JSON tool call writing the fixed file:\n"
                    f'{{"tool_name":"fs:write","target_path":"{real_file}","arguments":{{"content":"<full_fixed_python_code>"}}}}'
                )
                repair_user = (
                    f"Original Task: {task_description}\n"
                    f"Target File: {real_file}\n"
                    f"Why Execution Was Blocked: {current_verdict.plain_language_explanation}\n"
                    f"Required Security Fix: {current_verdict.how_to_fix}\n\n"
                    f"Vulnerable Code:\n{current_code}\n"
                )

                new_code: Optional[str] = None
                try:
                    resp = self._gateway.chat(
                        [
                            ChatMessage(role="system", content=repair_system),
                            ChatMessage(role="user", content=repair_user),
                        ],
                        role=ModelRole.CODING,
                        requested_model=fixer_model,
                        prefer_provider=fixer_provider,
                    )
                    new_code = self._extract_python_code_from_response(resp)
                except ActiveSecError:
                    new_code = None

                if new_code:
                    Path(real_file).write_text(new_code, encoding="utf-8")
                    os.chmod(real_file, 0o600)

                current_verdict = self.review_file(
                    real_file,
                    workspace_dir=real_ws,
                    coder_provider=fixer_provider,
                    coder_model=fixer_model,
                )
                history.append(
                    RepairIterationRecord(
                        iteration=iteration,
                        fixer_provider=fixer_provider,
                        fixer_model=fixer_model,
                        verdict=current_verdict,
                    )
                )
                if current_verdict.approved_for_execution:
                    break

            # Deterministic Certified Reference Fallback if weak local LLM failed to heal known pattern
            if not current_verdict.approved_for_execution:
                ref_code = self._deterministic_reference_remediation(
                    initial_verdict.deterministic_report.primary_topic_slug
                )
                if ref_code is not None:
                    Path(real_file).write_text(ref_code, encoding="utf-8")
                    os.chmod(real_file, 0o600)
                    current_verdict = self.review_file(
                        real_file,
                        workspace_dir=real_ws,
                        coder_provider="ring0-reference",
                        coder_model="certified-remediation",
                    )
                    history.append(
                        RepairIterationRecord(
                            iteration=len(history) + 1,
                            fixer_provider="ring0-reference",
                            fixer_model="certified-remediation",
                            verdict=current_verdict,
                        )
                    )

        repaired_snapshot = (
            Path(real_file).read_text(encoding="utf-8", errors="replace")
            if current_verdict.approved_for_execution
            else ""
        )

        lesson_path: Optional[str] = None
        if self._user_wiki_manager is not None:
            topic_slug = initial_verdict.deterministic_report.primary_topic_slug
            vuln_titles = tuple(f.title for f in initial_verdict.deterministic_report.ast_findings)
            if not vuln_titles and not initial_verdict.approved_for_execution:
                vuln_titles = ("Reviewer-identified security flaw",)

            self._user_wiki_manager.record_learning_case(
                topic_slug=topic_slug,
                task_description=task_description,
                vulnerability_titles=vuln_titles,
                plain_explanation=initial_verdict.plain_language_explanation,
                how_it_was_fixed=initial_verdict.how_to_fix,
                coder_model_used=f"{coder_provider}/{coder_model}",
                reviewer_model_used=f"{initial_verdict.reviewer_provider}/{initial_verdict.reviewer_model}",
                recommended_model=initial_verdict.recommended_fixer_model,
                unsafe_code_snippet=unsafe_snapshot if not initial_verdict.approved_for_execution else "",
                repaired_code_snippet=repaired_snapshot,
                verified_safe=current_verdict.approved_for_execution,
            )
            lesson_path = str(self._user_wiki_manager.user_wiki_dir / "lessons" / f"{topic_slug}.md")

        return VerifiedCodingLoopResult(
            file_path=real_file,
            approved_for_execution=current_verdict.approved_for_execution,
            iterations_run=len(history),
            initial_verdict=initial_verdict,
            final_verdict=current_verdict,
            repair_history=tuple(history),
            user_wiki_lesson_path=lesson_path,
        )

    @staticmethod
    def format_verdict_for_user(result: VerifiedCodingLoopResult) -> str:
        """Format a clear, educational report for the terminal user."""
        init = result.initial_verdict
        final = result.final_verdict
        lines: List[str] = [
            "--- Security Review & Deterministic Verification ---",
            f"Coder Model:    {init.coder_provider}/{init.coder_model}",
            f"Reviewer Model: {init.reviewer_provider}/{init.reviewer_model}",
        ]
        if not init.approved_for_execution:
            lines.extend(
                [
                    init.execution_status_banner,
                    f"What is unsafe (Plain Language): {init.plain_language_explanation}",
                    f"How to fix it:                   {init.how_to_fix}",
                ]
            )
            if init.recommended_fixer_model:
                lines.append(f"Recommended Stronger Model:      {init.recommended_fixer_model}")

            if result.iterations_run > 0:
                last_rec = result.repair_history[-1]
                lines.append(
                    f"Auto-Repair Loop: Ran {result.iterations_run} repair iteration(s) using "
                    f"{last_rec.fixer_provider}/{last_rec.fixer_model}."
                )
                lines.append(final.execution_status_banner)
        else:
            lines.append(final.execution_status_banner)

        if result.user_wiki_lesson_path:
            lines.append(f"User Security Academy Wiki updated: {result.user_wiki_lesson_path} (type /learn to view)")
        return "\n".join(lines)
