"""Ring-2 SecurityTestSynthesizer: Verified Dynamic Security Test Synthesis (Red-Green-Benign Triad).

Whenever the independent second Reviewer Model (Stage B) discovers a vulnerability in generated
code for which no deterministic Stage-A probe yet failed, `SecurityTestSynthesizer` launches an
isolated test-synthesis subtask to develop a deterministic Python security probe (`test_task_<module>.py`).

To guarantee that a newly synthesized test is neither hallucinated nor overly broad (which would
falsely block legitimate programs), every synthesized test must pass the **Red-Green-Benign Triad**
inside `SandboxGuard` before activation:
1. Proof 1 (AST Safety): The test script itself must pass `audit_python_ast_source` (zero unsafe primitives).
2. Proof 2 (RED on Vulnerable Draft): Running `python3 <test_script> <vulnerable_file> adversarial`
   MUST exit non-zero (`returncode != 0`), proving the test genuinely catches the vulnerability.
3. Proof 3 (BENIGN-SAFE): Running `python3 <test_script> <vulnerable_file> benign` MUST exit zero
   (`returncode == 0`), proving the test does not reject normal, benign inputs (zero false positives).
4. Proof 4 (GREEN after Code Repair): Once the application file is repaired, running
   `python3 <test_script> <repaired_file> adversarial` MUST exit zero (`returncode == 0`).

Verified tests are bound strictly to the target file (`TIER3_TASK_SCOPED`) and can be promoted
to the reusable project catalog via Ring-1 `/promote-test <test_id>`.
"""

from __future__ import annotations

import os
import secrets
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from activesec.core.component import ComponentSecurityAssessment, SecureComponent
from activesec.core.exceptions import ActiveSecError, CodeSecurityVerificationError
from activesec.core.wiki_manager import audit_python_ast_source
from activesec.guards.code_verifier import CodeVerifier
from activesec.guards.sandbox_guard import SandboxGuard, SandboxPolicy
from activesec.harness.model_gateway import ChatMessage, ModelGateway, ModelResponse, ModelRole


TEST_SYNTHESIS_SYSTEM_PROMPT = (
    "You are an ActiveSecHarness Deterministic Security Test Synthesizer. "
    "Given a vulnerable Python module and the reviewer's vulnerability description, write a "
    "standalone deterministic Python probe script that takes `(sys.argv[1] = target_py_path, "
    "sys.argv[2] = mode)` where mode is `'benign'` or `'adversarial'`.\n"
    "- In `'benign'` mode, call the module with a normal safe input and exit 0.\n"
    "- In `'adversarial'` mode, pass an attack payload triggering the vulnerability: if the "
    "vulnerability occurs (e.g. path traversal escapes, injection succeeds, or unsafe output is "
    "returned without raising an exception), exit with non-zero code (e.g. `sys.exit(4)`). "
    "If the module properly blocks/rejects the attack, exit 0.\n"
    "Respond with ONLY the Python code for the test script."
)


@dataclass(frozen=True, slots=True)
class SynthesizedSecurityTest:
    """Immutable record of a synthesized and Red-Green-Benign verified deterministic security test."""

    test_id: str
    target_file_path: str
    test_script_path: str
    vulnerability_summary: str
    ast_safe: bool
    red_on_vulnerable_passed: bool
    benign_safe_passed: bool
    green_on_repaired_passed: bool
    promoted_to_catalog: bool = False

    @property
    def triad_verified(self) -> bool:
        return (
            self.ast_safe
            and self.red_on_vulnerable_passed
            and self.benign_safe_passed
        )


class SecurityTestSynthesizer(SecureComponent):
    """Ring-2 synthesizer and Red-Green-Benign verifier for task-scoped deterministic security tests."""

    def __init__(
        self,
        *,
        gateway: ModelGateway,
        code_verifier: Optional[CodeVerifier] = None,
        sandbox_guard: Optional[SandboxGuard] = None,
        synthesizer_provider: str = "openrouter",
        synthesizer_model: str = "qwen/qwen3-coder",
        fallback_local_model: str = "qwen3:4b",
        openrouter_key_available: bool = True,
    ) -> None:
        self._gateway: ModelGateway = gateway
        self._code_verifier: CodeVerifier = code_verifier or CodeVerifier()
        self._sandbox_guard: SandboxGuard = sandbox_guard or SandboxGuard(
            SandboxPolicy(
                allowed_binaries=frozenset({"python3", "pytest"}),
                allow_network=False,
                timeout_seconds=10.0,
            )
        )
        self._synthesizer_provider: str = synthesizer_provider
        self._synthesizer_model: str = synthesizer_model
        self._fallback_local_model: str = fallback_local_model
        self._openrouter_key_available: bool = openrouter_key_available
        self._synthesized_tests: Dict[str, SynthesizedSecurityTest] = {}

    @classmethod
    def security_assessment(cls) -> ComponentSecurityAssessment:
        return ComponentSecurityAssessment(
            component_id="test_synthesizer",
            title="Ring-2 Verified Security Test Synthesizer (Red-Green-Benign Triad)",
            ring_level=2,
            source_path="src/activesec/harness/test_synthesizer.py",
            security_test_path="tests/security/test_sec_test_synthesizer.py",
            threat_vectors=("A.1", "B.2", "F.1", "F.3"),
            summary=(
                "Develops new deterministic security probe scripts whenever the Reviewer Model "
                "identifies a vulnerability not yet covered by existing deterministic probes. "
                "Enforces the Red-Green-Benign Verification Triad inside SandboxGuard so "
                "hallucinated or overly broad tests are rejected, and scopes verified tests "
                "task-locally until promoted by Ring 1."
            ),
            enforced_invariants=(
                "Audits every synthesized test script with audit_python_ast_source() before execution.",
                "Enforces Proof 1 (RED): The synthesized test must fail (exit non-zero) against the vulnerable code draft.",
                "Enforces Proof 2 (BENIGN-SAFE): The synthesized test must pass (exit zero) on normal benign inputs to prevent false-positive over-blocking.",
                "Enforces Proof 3 (GREEN): After code repair, verify_green_on_repaired() confirms the fixed code passes the adversarial probe.",
                "Scopes synthesized tests task-locally (TIER3_TASK_SCOPED) by default; promotion to the global catalog requires explicit Ring-1 authorization.",
            ),
            residual_risks=(
                "If a weak local model fails to synthesize a valid Red+Benign probe within max_attempts, the synthesizer safely discards the candidate test rather than registering a broken test.",
            ),
        )

    @property
    def synthesized_tests(self) -> Tuple[SynthesizedSecurityTest, ...]:
        return tuple(self._synthesized_tests.values())

    def get_test(self, test_id: str) -> Optional[SynthesizedSecurityTest]:
        return self._synthesized_tests.get(test_id)

    def _select_route(self) -> Tuple[str, str]:
        if self._synthesizer_provider == "openrouter" and self._openrouter_key_available:
            return ("openrouter", self._synthesizer_model)
        if self._synthesizer_provider == "ollama":
            return ("ollama", self._synthesizer_model)
        return ("ollama", self._fallback_local_model)

    @staticmethod
    def _extract_script_text(resp: ModelResponse) -> str:
        if resp.tool_call is not None and resp.tool_call.arguments.get("content"):
            return str(resp.tool_call.arguments["content"]).strip() + "\n"
        raw = (resp.content or "").strip()
        if "```" in raw:
            parts = raw.split("```")
            if len(parts) >= 3:
                lines = parts[1].splitlines()
                if lines and lines[0].strip().lower() in ("python", "py"):
                    lines = lines[1:]
                return "\n".join(lines).strip() + "\n"
        return raw + "\n"

    def synthesize_and_verify_test(
        self,
        *,
        vulnerable_file_path: str,
        vulnerability_explanation: str,
        how_to_fix: str,
        workspace_dir: Optional[str] = None,
        max_attempts: int = 2,
    ) -> Optional[SynthesizedSecurityTest]:
        """Run a dedicated subtask to synthesize a deterministic test and verify the Red-Benign proofs."""
        real_vuln_file = os.path.realpath(vulnerable_file_path)
        if not os.path.isfile(real_vuln_file):
            raise CodeSecurityVerificationError(
                f"Vulnerable target file does not exist: '{vulnerable_file_path}'.",
                vector_id="A.1",
                component_id="test_synthesizer",
            )
        real_ws = os.path.realpath(workspace_dir) if workspace_dir else os.path.dirname(real_vuln_file)
        vuln_source = Path(real_vuln_file).read_text(encoding="utf-8", errors="replace")
        provider, model_id = self._select_route()

        tests_dir = Path(real_ws) / ".activesec_tests"
        tests_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(tests_dir, 0o700)

        feedback = ""
        for _attempt in range(1, max_attempts + 1):
            user_prompt = (
                f"Target Module: {os.path.basename(real_vuln_file)}\n"
                f"Vulnerability Identified by Reviewer: {vulnerability_explanation}\n"
                f"Remediation Goal: {how_to_fix}\n"
                f"{feedback}\n"
                f"Vulnerable Module Source:\n{vuln_source}\n"
            )
            try:
                resp = self._gateway.chat(
                    [
                        ChatMessage(role="system", content=TEST_SYNTHESIS_SYSTEM_PROMPT),
                        ChatMessage(role="user", content=user_prompt),
                    ],
                    role=ModelRole.CODING,
                    requested_model=model_id,
                    prefer_provider=provider,
                )
            except ActiveSecError:
                return None

            script_code = self._extract_script_text(resp)
            if not script_code.strip():
                feedback = "Previous attempt returned empty code. Return a complete Python probe script."
                continue

            # Proof 1: Static AST safety check of the test script itself
            ast_ok, ast_findings = audit_python_ast_source(script_code, filename="<synthesized_test.py>")
            if not ast_ok:
                feedback = f"Previous test script failed AST safety audit: {'; '.join(ast_findings)}."
                continue

            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".py",
                dir=str(tests_dir),
                delete=False,
                encoding="utf-8",
            ) as tmp_f:
                tmp_script_path = tmp_f.name
                tmp_f.write(script_code)
            os.chmod(tmp_script_path, 0o600)

            # Proof 2 (RED on vulnerable draft): adversarial mode MUST exit non-zero
            red_res = self._sandbox_guard.run_sandboxed(
                ["python3", tmp_script_path, real_vuln_file, "adversarial"],
                workspace_dir=real_ws,
            )
            red_passed = red_res.returncode != 0

            # Proof 3 (BENIGN-SAFE): benign mode MUST exit 0 (no false-positive crash)
            benign_res = self._sandbox_guard.run_sandboxed(
                ["python3", tmp_script_path, real_vuln_file, "benign"],
                workspace_dir=real_ws,
            )
            benign_passed = benign_res.returncode == 0

            if red_passed and benign_passed:
                stem = Path(real_vuln_file).stem
                test_id = f"syntest_{stem}_{secrets.token_hex(4)}"
                final_path = str(tests_dir / f"{test_id}.py")
                os.replace(tmp_script_path, final_path)
                os.chmod(final_path, 0o600)

                record = SynthesizedSecurityTest(
                    test_id=test_id,
                    target_file_path=real_vuln_file,
                    test_script_path=final_path,
                    vulnerability_summary=vulnerability_explanation,
                    ast_safe=True,
                    red_on_vulnerable_passed=True,
                    benign_safe_passed=True,
                    green_on_repaired_passed=False,
                    promoted_to_catalog=False,
                )
                self._synthesized_tests[test_id] = record
                self._code_verifier.register_task_local_test(real_vuln_file, final_path)
                return record

            try:
                os.unlink(tmp_script_path)
            except OSError:
                pass
            feedback = (
                f"Previous test failed Triad verification (red_on_vulnerable={red_passed}, "
                f"benign_safe={benign_passed}). Ensure 'adversarial' mode exits non-zero on the "
                "vulnerable draft and 'benign' mode exits 0."
            )

        return None

    def verify_green_on_repaired(
        self,
        test_id: str,
        repaired_file_path: str,
        *,
        workspace_dir: Optional[str] = None,
    ) -> SynthesizedSecurityTest:
        """Verify Proof 4 (GREEN): the repaired file passes both adversarial and benign modes of the synthesized test."""
        record = self._synthesized_tests.get(test_id)
        if record is None:
            raise CodeSecurityVerificationError(
                f"Unknown synthesized test_id '{test_id}'.",
                vector_id="A.1",
                component_id="test_synthesizer",
            )
        real_repaired = os.path.realpath(repaired_file_path)
        real_ws = os.path.realpath(workspace_dir) if workspace_dir else os.path.dirname(real_repaired)

        adv_res = self._sandbox_guard.run_sandboxed(
            ["python3", record.test_script_path, real_repaired, "adversarial"],
            workspace_dir=real_ws,
        )
        ben_res = self._sandbox_guard.run_sandboxed(
            ["python3", record.test_script_path, real_repaired, "benign"],
            workspace_dir=real_ws,
        )
        green_ok = (adv_res.returncode == 0) and (ben_res.returncode == 0)

        updated = SynthesizedSecurityTest(
            test_id=record.test_id,
            target_file_path=record.target_file_path,
            test_script_path=record.test_script_path,
            vulnerability_summary=record.vulnerability_summary,
            ast_safe=record.ast_safe,
            red_on_vulnerable_passed=record.red_on_vulnerable_passed,
            benign_safe_passed=record.benign_safe_passed,
            green_on_repaired_passed=green_ok,
            promoted_to_catalog=record.promoted_to_catalog,
        )
        self._synthesized_tests[test_id] = updated
        return updated

    def promote_verified_test(self, test_id: str, *, authorized_by_ring: int = 1) -> SynthesizedSecurityTest:
        """Promote a fully Red-Green-Benign verified test into the project catalog (Ring 1 required)."""
        record = self._synthesized_tests.get(test_id)
        if record is None:
            raise CodeSecurityVerificationError(
                f"Cannot promote unknown synthesized test '{test_id}'.",
                vector_id="A.1",
                component_id="test_synthesizer",
            )
        if not (record.triad_verified and record.green_on_repaired_passed):
            raise CodeSecurityVerificationError(
                f"Test '{test_id}' has not completed full Red-Green-Benign verification and cannot be promoted.",
                vector_id="A.1",
                component_id="test_synthesizer",
            )
        self._code_verifier.promote_test_to_catalog(
            record.test_script_path,
            authorized_by_ring=authorized_by_ring,
        )
        promoted = SynthesizedSecurityTest(
            test_id=record.test_id,
            target_file_path=record.target_file_path,
            test_script_path=record.test_script_path,
            vulnerability_summary=record.vulnerability_summary,
            ast_safe=record.ast_safe,
            red_on_vulnerable_passed=record.red_on_vulnerable_passed,
            benign_safe_passed=record.benign_safe_passed,
            green_on_repaired_passed=record.green_on_repaired_passed,
            promoted_to_catalog=True,
        )
        self._synthesized_tests[test_id] = promoted
        return promoted
