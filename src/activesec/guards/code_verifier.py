"""Ring-0 CodeVerifier: 3-Tier Context-Sensitive Verification, ContextWaiver & SoD Sandbox Test Runner.

Enforces deterministic, LLM-independent security verification on generated application code
without causing false-positive over-blocking across three distinct tiers:
1. Tier 1 (`TIER1_UNIVERSAL` — Always Enforced):
   - Trojan Source invisible Unicode characters (CVE-2021-42574), syntax integrity,
     `eval()`, `exec()`, `os.system()`, `subprocess(..., shell=True)`, and `pickle`/`marshal`.
2. Tier 2 (`TIER2_CONTEXTUAL` — Dataflow & Trust-Boundary Sensitive):
   - Evaluates primitives like `zf.extractall()` in context rather than blindly banning them:
     - BLOCKED when invoked on unvalidated external archives.
     - PERMITTED when the enclosing function pre-validates `infolist()`/`namelist()` entries
       with canonical path checks (`os.path.realpath` / `.resolve()`) and size/ratio bounds, OR
       when the archive was locally created in the same trusted scope (`ZipFile(..., "w")`), OR
       when an explicit Ring-1 `ContextWaiver` has been granted and logged for that file + rule.
3. Tier 3 (`TIER3_TASK_SCOPED` — Task-Local & Promoted Domain Probes):
   - Executes adversarial probes inside an isolated Separation-of-Duties (SoD) `test-runner`
     sub-agent (`SandboxGuard`), including task-local tests synthesized by `SecurityTestSynthesizer`.
"""

from __future__ import annotations

import ast
import enum
import os
import tempfile
import textwrap
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

from activesec.core.capability_token import CapabilityCaveat, CapabilityEngine
from activesec.core.component import ComponentSecurityAssessment, SecureComponent
from activesec.core.exceptions import CodeSecurityVerificationError
from activesec.core.tool_registry import CertifiedToolRegistry
from activesec.guards.sandbox_guard import SandboxGuard, SandboxPolicy
from activesec.harness.model_gateway import ToolCallRequest
from activesec.sovereign.deobfuscator import TROJAN_SOURCE_UNICODE_CHARS


class VerificationTier(str, enum.Enum):
    """Three-tier scoping classification preventing false-positive test inflation."""

    TIER1_UNIVERSAL = "TIER1_UNIVERSAL"
    TIER2_CONTEXTUAL = "TIER2_CONTEXTUAL"
    TIER3_TASK_SCOPED = "TIER3_TASK_SCOPED"


@dataclass(frozen=True, slots=True)
class ContextWaiver:
    """Ring-1 operator waiver authorizing a specific Tier-2 contextual rule for one canonical file."""

    waiver_id: str
    canonical_file_path: str
    rule_id: str
    justification: str
    granted_by_ring: int
    created_at_unix: float


@dataclass(frozen=True, slots=True)
class CodeVulnerabilityFinding:
    """Immutable deterministic security finding in generated application code."""

    rule_id: str
    vector_id: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM"
    line_number: int
    title: str
    plain_explanation: str
    remediation_hint: str
    topic_slug: str
    tier: VerificationTier = VerificationTier.TIER1_UNIVERSAL


@dataclass(frozen=True, slots=True)
class SandboxProbeOutcome:
    """Immutable result of an adversarial security probe executed by the SoD test-runner sub-agent."""

    probe_name: str
    vector_id: str
    passed: bool
    sub_agent_id: str
    attenuated_token_id: str
    details: str
    tier: VerificationTier = VerificationTier.TIER2_CONTEXTUAL


@dataclass(frozen=True, slots=True)
class DeterministicVerificationReport:
    """Complete deterministic verification verdict for a generated source file."""

    file_path: str
    approved_for_execution: bool
    ast_findings: Tuple[CodeVulnerabilityFinding, ...]
    probe_outcomes: Tuple[SandboxProbeOutcome, ...]
    sod_sub_agent_id: str
    active_waivers: Tuple[ContextWaiver, ...] = ()

    @property
    def primary_topic_slug(self) -> str:
        if self.ast_findings:
            return self.ast_findings[0].topic_slug
        for probe in self.probe_outcomes:
            if not probe.passed and "zip" in probe.probe_name.lower():
                return "zip_slip_and_zip_bombs"
        return "secure_coding_fundamentals"


class CodeVerifier(SecureComponent):
    """Ring-0 deterministic application code verifier with 3-tier contextual scoping and SoD test runner."""

    FORBIDDEN_APP_CALLS: FrozenSet[str] = frozenset(
        {"eval", "exec", "extractall", "system", "popen"}
    )
    UNSAFE_DESERIALIZATION_MODULES: FrozenSet[str] = frozenset({"pickle", "marshal"})

    def __init__(
        self,
        *,
        sandbox_guard: Optional[SandboxGuard] = None,
        capability_engine: Optional[CapabilityEngine] = None,
        tool_registry: Optional[CertifiedToolRegistry] = None,
    ) -> None:
        self._sandbox_guard: SandboxGuard = sandbox_guard or SandboxGuard(
            SandboxPolicy(
                allowed_binaries=frozenset({"python3", "pytest"}),
                allow_network=False,
                timeout_seconds=10.0,
            )
        )
        self._capability_engine: CapabilityEngine = capability_engine or CapabilityEngine()
        if tool_registry is not None:
            self._tool_registry = tool_registry
        else:
            self._tool_registry = CertifiedToolRegistry()
            self._tool_registry.register_default_kernel_tools()

        # Keyed by canonical_file_path -> list of ContextWaiver
        self._waivers: Dict[str, List[ContextWaiver]] = {}
        # Keyed by canonical_file_path -> list of task-local pytest/probe script paths
        self._task_local_tests: Dict[str, List[str]] = {}
        # Promoted domain-wide test scripts (after Ring-1 promotion)
        self._promoted_catalog_tests: List[str] = []

    @classmethod
    def security_assessment(cls) -> ComponentSecurityAssessment:
        return ComponentSecurityAssessment(
            component_id="code_verifier",
            title="Ring-0 3-Tier Context-Sensitive Code Verifier & SoD Sandbox Test Runner",
            ring_level=0,
            source_path="src/activesec/guards/code_verifier.py",
            security_test_path="tests/security/test_sec_code_verifier.py",
            threat_vectors=("A.1", "B.1", "B.2", "B.4", "D.1", "D.3", "E.1", "F.3"),
            summary=(
                "Provides LLM-independent deterministic security verification across a 3-Tier "
                "scoping model (Tier 1 Universal Invariants, Tier 2 Context/Dataflow-Sensitive "
                "Rules such as permitting extractall() after pre-validated infolist checks or "
                "on self-created archives or Ring-1 ContextWaivers, and Tier 3 Task-Scoped "
                "Synthesized Probes) executed by an isolated Separation-of-Duties (SoD) "
                "test-runner sub-agent inside SandboxGuard."
            ),
            enforced_invariants=(
                "Tier 1 Universal: Always blocks eval(), exec(), os.system(), subprocess(..., shell=True), pickle/marshal, and Trojan Source Unicode.",
                "Tier 2 Contextual: Blocks unvalidated extractall(), but permits extractall() when AST dataflow proves prior infolist()/namelist() path+quota validation, self-created local archives, or a Ring-1 ContextWaiver.",
                "Tier 3 Task-Scoped: Executes synthesized regression tests strictly against their target file unless explicitly promoted to the domain catalog.",
                "Isolates all dynamic test execution into a dedicated SoD sub-agent holding an attenuated shell:exec token with zero network access.",
            ),
            residual_risks=(
                "Complex domain-specific business logic flaws not yet covered by a Tier-3 probe (mitigated by Stage-B DualModelReviewer + automatic SecurityTestSynthesizer).",
            ),
        )

    def grant_context_waiver(
        self,
        *,
        file_path: str,
        rule_id: str,
        justification: str,
        granted_by_ring: int = 1,
    ) -> ContextWaiver:
        """Grant a Ring-1 context waiver for a Tier-2 contextual rule on a specific file."""
        if granted_by_ring != 1:
            raise CodeSecurityVerificationError(
                "Context waivers can only be granted by Ring 1 (human operator).",
                vector_id="A.3",
                component_id="code_verifier",
            )
        if not justification.strip():
            raise CodeSecurityVerificationError(
                "Context waiver requires a non-empty justification.",
                vector_id="A.3",
                component_id="code_verifier",
            )
        real_file = os.path.realpath(file_path)
        waiver = ContextWaiver(
            waiver_id=f"waiver_{int(time.time() * 1000)}",
            canonical_file_path=real_file,
            rule_id=rule_id.strip().upper(),
            justification=justification.strip(),
            granted_by_ring=1,
            created_at_unix=time.time(),
        )
        self._waivers.setdefault(real_file, []).append(waiver)
        return waiver

    def get_waivers_for_file(self, file_path: str) -> Tuple[ContextWaiver, ...]:
        real_file = os.path.realpath(file_path)
        return tuple(self._waivers.get(real_file, ()))

    def register_task_local_test(self, target_file_path: str, test_script_path: str) -> None:
        """Attach a verified Tier-3 deterministic test script strictly to `target_file_path`."""
        real_target = os.path.realpath(target_file_path)
        real_test = os.path.realpath(test_script_path)
        bucket = self._task_local_tests.setdefault(real_target, [])
        if real_test not in bucket:
            bucket.append(real_test)

    def promote_test_to_catalog(self, test_script_path: str, *, authorized_by_ring: int = 1) -> None:
        """Promote a verified task-local test into the reusable project catalog (requires Ring 1)."""
        if authorized_by_ring != 1:
            raise CodeSecurityVerificationError(
                "Promoting a task-local test to the project catalog requires Ring-1 authorization.",
                vector_id="A.3",
                component_id="code_verifier",
            )
        real_test = os.path.realpath(test_script_path)
        if not os.path.isfile(real_test):
            raise CodeSecurityVerificationError(
                f"Cannot promote non-existent test script: '{test_script_path}'.",
                vector_id="A.1",
                component_id="code_verifier",
            )
        if real_test not in self._promoted_catalog_tests:
            self._promoted_catalog_tests.append(real_test)

    @staticmethod
    def _scope_prevalidates_archive_or_is_self_created(scope_node: ast.AST) -> Tuple[bool, bool]:
        """Inspect a function or module AST scope to determine if archive extraction is contextually safe.

        Returns `(has_canonical_path_check, has_size_or_self_created_safety)`:
        - `pre_validated_infolist`: True if the scope iterates over `infolist()`/`namelist()` and checks
          both `realpath`/`resolve` AND size/ratio limits (`file_size`, `compress_size`, `max_`, `ratio`).
        - `self_created_trusted_zip`: True if the scope only opens `ZipFile(..., "w")` to write a local
          archive and never takes an external untrusted path parameter into `extractall()` without creating it.
        """
        has_path_check = False
        has_quota_check = False
        inspects_members = False
        writes_zip_in_scope = False
        has_external_params = False

        if isinstance(scope_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            has_external_params = len(scope_node.args.args) > 0

        for node in ast.walk(scope_node):
            if isinstance(node, ast.Call):
                fn = ""
                if isinstance(node.func, ast.Name):
                    fn = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    fn = node.func.attr

                if fn in ("realpath", "resolve"):
                    has_path_check = True
                if fn in ("infolist", "namelist", "getmembers"):
                    inspects_members = True
                if fn == "ZipFile" and len(node.args) >= 2:
                    mode_arg = node.args[1]
                    if isinstance(mode_arg, ast.Constant) and str(mode_arg.value).startswith("w"):
                        writes_zip_in_scope = True

            elif isinstance(node, ast.Attribute):
                if node.attr in ("file_size", "compress_size", "external_attr"):
                    inspects_members = True

            elif isinstance(node, ast.Compare):
                seg = ast.unparse(node).lower()
                if any(k in seg for k in ("max_", "size", "bytes", "ratio", "limit", "quota", "file_size")):
                    has_quota_check = True

        self_created_only = writes_zip_in_scope and not has_external_params
        if self_created_only:
            return (True, True)
        if inspects_members and has_path_check and has_quota_check:
            return (True, True)
        return (has_path_check, has_quota_check)

    def analyze_python_source(
        self,
        source_text: str,
        *,
        filename: str = "<generated.py>",
        waived_rule_ids: FrozenSet[str] = frozenset(),
    ) -> Tuple[CodeVulnerabilityFinding, ...]:
        """Statically inspect Python code across Tier-1 (Universal) and Tier-2 (Contextual) rules."""
        findings: List[CodeVulnerabilityFinding] = []

        # Tier 1: Trojan Source Unicode check (Never waivable)
        for line_no, line in enumerate(source_text.splitlines(), start=1):
            for ch in line:
                cp = ord(ch)
                if cp in TROJAN_SOURCE_UNICODE_CHARS:
                    findings.append(
                        CodeVulnerabilityFinding(
                            rule_id="AST_TROJAN_UNICODE",
                            vector_id="B.4",
                            severity="CRITICAL",
                            line_number=line_no,
                            title=f"Invisible Trojan Source Unicode character U+{cp:04X}",
                            plain_explanation=(
                                "The code contains invisible directional or zero-width Unicode characters "
                                "that make the code look different to human eyes than to the Python interpreter."
                            ),
                            remediation_hint="Remove all bidirectional override and zero-width Unicode control characters.",
                            topic_slug="trojan_source_and_obfuscation",
                            tier=VerificationTier.TIER1_UNIVERSAL,
                        )
                    )

        try:
            tree = ast.parse(source_text, filename=filename)
        except SyntaxError as exc:
            findings.append(
                CodeVulnerabilityFinding(
                    rule_id="AST_SYNTAX_ERROR",
                    vector_id="A.1",
                    severity="HIGH",
                    line_number=exc.lineno or 1,
                    title=f"Python SyntaxError: {exc.msg}",
                    plain_explanation="The generated program contains invalid Python syntax and cannot be safely analyzed or executed.",
                    remediation_hint="Fix the syntax error so the AST can be deterministically verified.",
                    topic_slug="secure_coding_fundamentals",
                    tier=VerificationTier.TIER1_UNIVERSAL,
                )
            )
            return tuple(findings)

        imports_archive_module = False
        imports_random_module = False

        # Map each Call node to its enclosing function (or module) for contextual dataflow analysis
        parent_scope_map: Dict[ast.AST, ast.AST] = {}
        for scope in [tree, *[n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]]:
            for child in ast.iter_child_nodes(scope):
                for desc in ast.walk(child):
                    if not isinstance(desc, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        parent_scope_map[desc] = scope

        has_any_archive_extraction = False
        module_path_safe, module_quota_safe = self._scope_prevalidates_archive_or_is_self_created(tree)

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_mod = alias.name.split(".")[0]
                    if root_mod in ("zipfile", "tarfile"):
                        imports_archive_module = True
                    if root_mod == "random":
                        imports_random_module = True
                    if root_mod in self.UNSAFE_DESERIALIZATION_MODULES:
                        findings.append(
                            CodeVulnerabilityFinding(
                                rule_id="AST_UNSAFE_DESERIALIZATION",
                                vector_id="B.3",
                                severity="CRITICAL",
                                line_number=node.lineno,
                                title=f"Unsafe deserialization module '{root_mod}' imported",
                                plain_explanation=(
                                    f"The '{root_mod}' module allows arbitrary code execution when loading untrusted data. "
                                    "An attacker can craft a file that immediately takes over the program on load."
                                ),
                                remediation_hint="Use safe data formats such as json or yaml.safe_load instead of pickle/marshal.",
                                topic_slug="unsafe_deserialization_and_code_execution",
                                tier=VerificationTier.TIER1_UNIVERSAL,
                            )
                        )
            elif isinstance(node, ast.ImportFrom):
                root_mod = (node.module or "").split(".")[0]
                if root_mod in ("zipfile", "tarfile"):
                    imports_archive_module = True
                if root_mod == "random":
                    imports_random_module = True
                if root_mod in self.UNSAFE_DESERIALIZATION_MODULES:
                    findings.append(
                        CodeVulnerabilityFinding(
                            rule_id="AST_UNSAFE_DESERIALIZATION",
                            vector_id="B.3",
                            severity="CRITICAL",
                            line_number=node.lineno,
                            title=f"Unsafe deserialization import from '{root_mod}'",
                            plain_explanation=(
                                f"Importing from '{root_mod}' enables arbitrary code execution during deserialization."
                            ),
                            remediation_hint="Use json or strict schema validation instead of pickle/marshal.",
                            topic_slug="unsafe_deserialization_and_code_execution",
                            tier=VerificationTier.TIER1_UNIVERSAL,
                        )
                    )

            elif isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                if func_name in ("extractall", "extract", "open") and imports_archive_module:
                    has_any_archive_extraction = True

                if func_name == "extractall":
                    enclosing = parent_scope_map.get(node, tree)
                    scope_path_ok, scope_quota_ok = self._scope_prevalidates_archive_or_is_self_created(enclosing)
                    contextually_safe = scope_path_ok and scope_quota_ok

                    if not contextually_safe and "AST_ARCHIVE_EXTRACTALL" not in waived_rule_ids:
                        findings.append(
                            CodeVulnerabilityFinding(
                                rule_id="AST_ARCHIVE_EXTRACTALL",
                                vector_id="B.1",
                                severity="CRITICAL",
                                line_number=node.lineno,
                                title="Unvalidated archive extraction via extractall() (Contextual Tier-2)",
                                plain_explanation=(
                                    "Calling extractall() without prior infolist() path and size validation blindly unpacks "
                                    "every entry in the archive. This is only safe on self-created trusted archives or after "
                                    "verifying every member's canonical path (realpath) and uncompressed byte quota."
                                ),
                                remediation_hint=(
                                    "Either pre-validate all zf.infolist() entries (checking os.path.realpath() containment, "
                                    "rejecting symlinks, and enforcing a total file_size/ratio cap before extractall), or "
                                    "stream-extract in bounded 64 KB chunks."
                                ),
                                topic_slug="zip_slip_and_zip_bombs",
                                tier=VerificationTier.TIER2_CONTEXTUAL,
                            )
                        )
                elif func_name in ("eval", "exec"):
                    findings.append(
                        CodeVulnerabilityFinding(
                            rule_id="AST_DYNAMIC_CODE_EXEC",
                            vector_id="A.1",
                            severity="CRITICAL",
                            line_number=node.lineno,
                            title=f"Arbitrary code execution primitive '{func_name}()'",
                            plain_explanation=(
                                f"'{func_name}()' executes arbitrary strings as live Python code. If any part of "
                                "the input comes from a user, file, or network request, an attacker can run any command."
                            ),
                            remediation_hint="Replace eval()/exec() with ast.literal_eval(), json.loads(), or explicit dispatch tables.",
                            topic_slug="command_injection_and_code_execution",
                            tier=VerificationTier.TIER1_UNIVERSAL,
                        )
                    )
                elif func_name in ("system", "popen"):
                    findings.append(
                        CodeVulnerabilityFinding(
                            rule_id="AST_OS_SYSTEM_SHELL",
                            vector_id="A.1",
                            severity="CRITICAL",
                            line_number=node.lineno,
                            title=f"Unsafe shell execution via '{func_name}()'",
                            plain_explanation=(
                                f"Calling os.{func_name}() passes a command string through the system shell. "
                                "Attackers can chain malicious commands using ';', '&&', or '$(...)'."
                            ),
                            remediation_hint="Use subprocess.run([...], shell=False) with an explicit argument list.",
                            topic_slug="command_injection_and_code_execution",
                            tier=VerificationTier.TIER1_UNIVERSAL,
                        )
                    )

                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        findings.append(
                            CodeVulnerabilityFinding(
                                rule_id="AST_SUBPROCESS_SHELL_TRUE",
                                vector_id="A.1",
                                severity="CRITICAL",
                                line_number=node.lineno,
                                title="Unsafe subprocess invocation with shell=True",
                                plain_explanation=(
                                    "Running subprocess with shell=True invokes a shell interpreter on the command string, "
                                    "allowing shell metacharacter injection (`; rm -rf ...`, backticks, pipes)."
                                ),
                                remediation_hint="Pass a list of arguments to subprocess.run(['cmd', 'arg1'], shell=False).",
                                topic_slug="command_injection_and_code_execution",
                                tier=VerificationTier.TIER1_UNIVERSAL,
                            )
                        )

        # Tier-2 Contextual check 1: Archive extraction without canonical path check or size limit
        if imports_archive_module and has_any_archive_extraction:
            if not module_path_safe and "AST_ARCHIVE_MISSING_REALPATH" not in waived_rule_ids and "AST_ARCHIVE_EXTRACTALL" not in waived_rule_ids:
                findings.append(
                    CodeVulnerabilityFinding(
                        rule_id="AST_ARCHIVE_MISSING_REALPATH",
                        vector_id="B.2",
                        severity="HIGH",
                        line_number=1,
                        title="Archive extraction without canonical path validation (Zip-Slip risk)",
                        plain_explanation=(
                            "The program extracts archives (zipfile/tarfile) without verifying canonical target paths "
                            "via os.path.realpath() or Path.resolve(). Relative paths like '../../evil.sh' can escape "
                            "the destination directory."
                        ),
                        remediation_hint=(
                            "Resolve the target directory and each entry path with os.path.realpath() and assert "
                            "that dest_path.startswith(real_target_dir + os.sep)."
                        ),
                        topic_slug="zip_slip_and_zip_bombs",
                        tier=VerificationTier.TIER2_CONTEXTUAL,
                    )
                )
            if not module_quota_safe and "AST_ARCHIVE_MISSING_QUOTA" not in waived_rule_ids and "AST_ARCHIVE_EXTRACTALL" not in waived_rule_ids:
                findings.append(
                    CodeVulnerabilityFinding(
                        rule_id="AST_ARCHIVE_MISSING_QUOTA",
                        vector_id="B.1",
                        severity="HIGH",
                        line_number=1,
                        title="Archive extraction without decompression size/ratio quota (ZipBomb risk)",
                        plain_explanation=(
                            "The program extracts archive streams without enforcing a maximum byte limit or "
                            "compression ratio check. A tiny ZipBomb can exhaust disk space or memory."
                        ),
                        remediation_hint=(
                            "Check total uncompressed size/ratio across zf.infolist() or read archive entries in "
                            "fixed 64 KB chunks while enforcing max_bytes and max_ratio."
                        ),
                        topic_slug="zip_slip_and_zip_bombs",
                        tier=VerificationTier.TIER2_CONTEXTUAL,
                    )
                )

        # Tier-2 Contextual check 2: Using weak `random` module around password/token/secret logic
        lower_source = source_text.lower()
        if (
            imports_random_module
            and any(w in lower_source for w in ("password", "token", "secret", "key", "salt"))
            and "AST_WEAK_RANDOM_FOR_SECRET" not in waived_rule_ids
        ):
            findings.append(
                CodeVulnerabilityFinding(
                    rule_id="AST_WEAK_RANDOM_FOR_SECRET",
                    vector_id="D.3",
                    severity="HIGH",
                    line_number=1,
                    title="Predictable 'random' module used in security/secret context",
                    plain_explanation=(
                        "Python's standard 'random' module uses a predictable Mersenne Twister generator. "
                        "An attacker who observes a few outputs can predict all future passwords or tokens."
                    ),
                    remediation_hint="Use Python's cryptographic 'secrets' module (e.g. secrets.token_urlsafe(32)).",
                    topic_slug="password_entropy_and_dictionaries",
                    tier=VerificationTier.TIER2_CONTEXTUAL,
                )
            )

        return tuple(findings)

    def _allocate_sod_test_runner(self, workspace_dir: str) -> Tuple[str, str]:
        """Partition a workflow across isolated SoD sub-agents and return the test-runner agent & token ID."""
        real_ws = os.path.realpath(workspace_dir)
        parent_caveat = CapabilityCaveat(
            allowed_tools=frozenset({"fs:read", "fs:write", "shell:exec"}),
            path_prefixes=(real_ws,),
            allowed_binaries=frozenset({"python3", "pytest"}),
            max_calls=10,
            expires_at_unix=time.time() + 300.0,
        )
        parent_token = self._capability_engine.issue_root_token(
            subject_agent_id="verifier-orchestrator",
            task_purpose="Coordinate SoD code verification and sandbox test runner",
            caveat=parent_caveat,
        )
        planned = (
            ToolCallRequest(tool_name="fs:read", target_path=real_ws),
            ToolCallRequest(tool_name="shell:exec", raw_command="python3 -V", binary_name="python3"),
        )
        assignments = self._tool_registry.partition_tool_plan_across_agents(
            parent_agent_id="verifier-orchestrator",
            parent_token=parent_token,
            capability_engine=self._capability_engine,
            planned_requests=planned,
        )
        exec_stage = next(a for a in assignments if "shell:exec" in a.allowed_tools)
        self._capability_engine.verify_tool_call(
            token=exec_stage.attenuated_token,
            agent_id=exec_stage.sub_agent_id,
            tool_name="shell:exec",
            binary_name="python3",
        )
        return (exec_stage.sub_agent_id, exec_stage.attenuated_token.token_id)

    def _run_archive_adversarial_probes_in_sandbox(
        self,
        file_path: str,
        *,
        workspace_dir: str,
        sub_agent_id: str,
        token_id: str,
    ) -> Tuple[SandboxProbeOutcome, ...]:
        """Execute live Zip-Slip and ZipBomb attack probes against an archive extraction module inside SandboxGuard."""
        harness_script = textwrap.dedent(
            """
            import importlib.util
            import inspect
            import os
            import sys
            import tempfile
            import zipfile

            target_py = sys.argv[1]
            probe_kind = sys.argv[2]

            spec = importlib.util.spec_from_file_location("candidate_mod", target_py)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

            # Discover extraction callable accepting (zip_path, dest_dir)
            extract_fn = None
            for name, obj in inspect.getmembers(mod, inspect.isfunction):
                sig = inspect.signature(obj)
                params = [
                    p for p in sig.parameters.values()
                    if p.default is inspect.Parameter.empty
                    and p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
                ]
                if len(params) >= 2:
                    extract_fn = obj
                    break

            if extract_fn is None:
                # Module has no 2-arg external extractor function (e.g. self-contained trusted archive script)
                print("NO_EXTERNAL_EXTRACTOR_FUNCTION")
                sys.exit(0)

            with tempfile.TemporaryDirectory() as tmp:
                dest_dir = os.path.join(tmp, "unpacked")
                os.makedirs(dest_dir, exist_ok=True)
                zip_file = os.path.join(tmp, "probe.zip")

                if probe_kind == "benign":
                    with zipfile.ZipFile(zip_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                        zf.writestr("hello.txt", "safe_content_123")
                    extract_fn(zip_file, dest_dir)
                    expected = os.path.join(dest_dir, "hello.txt")
                    if not os.path.isfile(expected):
                        print("BENIGN_FILE_NOT_EXTRACTED")
                        sys.exit(3)
                    print("PROBE_BENIGN_OK")
                    sys.exit(0)

                if probe_kind == "zip_slip":
                    outside_file = os.path.join(tmp, "escaped_pwn.txt")
                    with zipfile.ZipFile(zip_file, "w") as zf:
                        zf.writestr("../escaped_pwn.txt", "pwned")
                    symlink_zip = os.path.join(tmp, "symlink_probe.zip")
                    import stat as _stat
                    with zipfile.ZipFile(symlink_zip, "w") as szf:
                        sinfo = zipfile.ZipInfo("evil_link")
                        sinfo.external_attr = (_stat.S_IFLNK | 0o777) << 16
                        szf.writestr(sinfo, outside_file)
                    try:
                        extract_fn(zip_file, dest_dir)
                    except Exception:
                        pass
                    if os.path.exists(outside_file):
                        print("ZIP_SLIP_ESCAPED_OUTSIDE_TARGET")
                        sys.exit(4)
                    symlink_accepted = False
                    try:
                        extract_fn(symlink_zip, dest_dir)
                        if os.path.exists(os.path.join(dest_dir, "evil_link")):
                            symlink_accepted = True
                    except Exception:
                        symlink_accepted = False
                    if symlink_accepted:
                        print("ZIP_SYMLINK_EXTRACTED_UNCHECKED")
                        sys.exit(4)
                    print("PROBE_ZIP_SLIP_BLOCKED_OK")
                    sys.exit(0)

                if probe_kind == "zip_bomb":
                    with zipfile.ZipFile(zip_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                        zf.writestr("bomb.bin", b"\\x00" * (3 * 1024 * 1024))
                    blocked = False
                    try:
                        extract_fn(zip_file, dest_dir)
                    except Exception:
                        blocked = True
                    bomb_out = os.path.join(dest_dir, "bomb.bin")
                    if not blocked and os.path.exists(bomb_out) and os.path.getsize(bomb_out) >= 2 * 1024 * 1024:
                        print("ZIP_BOMB_EXPANDED_UNCHECKED")
                        sys.exit(5)
                    print("PROBE_ZIP_BOMB_BLOCKED_OK")
                    sys.exit(0)
            """
        ).strip()

        outcomes: List[SandboxProbeOutcome] = []
        with tempfile.TemporaryDirectory(dir=workspace_dir, prefix=".sod_probe_") as probe_dir:
            runner_path = os.path.join(probe_dir, "_run_probe.py")
            with open(runner_path, "w", encoding="utf-8") as fh:
                fh.write(harness_script)

            probes = (
                ("probe_benign_archive_extract", "B.1", "benign"),
                ("probe_adversarial_zip_slip_traversal", "B.2", "zip_slip"),
                ("probe_adversarial_zip_bomb_ratio", "B.1", "zip_bomb"),
            )
            for probe_name, vec_id, kind in probes:
                exec_res = self._sandbox_guard.run_sandboxed(
                    ["python3", runner_path, file_path, kind],
                    workspace_dir=workspace_dir,
                )
                passed = exec_res.returncode == 0
                out_detail = (exec_res.stdout + " " + exec_res.stderr).strip()
                outcomes.append(
                    SandboxProbeOutcome(
                        probe_name=probe_name,
                        vector_id=vec_id,
                        passed=passed,
                        sub_agent_id=sub_agent_id,
                        attenuated_token_id=token_id,
                        details=out_detail or f"returncode={exec_res.returncode}",
                        tier=VerificationTier.TIER2_CONTEXTUAL,
                    )
                )
        return tuple(outcomes)

    def _run_tier3_synthesized_tests(
        self,
        file_path: str,
        *,
        workspace_dir: str,
        sub_agent_id: str,
        token_id: str,
    ) -> Tuple[SandboxProbeOutcome, ...]:
        """Run any Tier-3 task-local tests bound to `file_path` plus promoted catalog tests."""
        real_file = os.path.realpath(file_path)
        scripts: List[str] = []
        for s in self._task_local_tests.get(real_file, ()):
            if os.path.isfile(s) and s not in scripts:
                scripts.append(s)
        for s in self._promoted_catalog_tests:
            if os.path.isfile(s) and s not in scripts:
                scripts.append(s)

        outcomes: List[SandboxProbeOutcome] = []
        for script_path in scripts:
            exec_res = self._sandbox_guard.run_sandboxed(
                ["python3", script_path, real_file, "adversarial"],
                workspace_dir=workspace_dir,
            )
            passed = exec_res.returncode == 0
            detail = (exec_res.stdout + " " + exec_res.stderr).strip()
            outcomes.append(
                SandboxProbeOutcome(
                    probe_name=f"tier3_test:{os.path.basename(script_path)}",
                    vector_id="A.1",
                    passed=passed,
                    sub_agent_id=sub_agent_id,
                    attenuated_token_id=token_id,
                    details=detail or f"returncode={exec_res.returncode}",
                    tier=VerificationTier.TIER3_TASK_SCOPED,
                )
            )
        return tuple(outcomes)

    def verify_python_file(
        self,
        file_path: str,
        *,
        workspace_dir: Optional[str] = None,
        run_sandbox_probes: bool = True,
        fail_closed: bool = False,
    ) -> DeterministicVerificationReport:
        """Deterministically verify a Python file across Tier 1, Tier 2 (contextual), and Tier 3 (task-scoped)."""
        real_file = os.path.realpath(file_path)
        if not os.path.isfile(real_file):
            raise CodeSecurityVerificationError(
                f"Target Python file for verification does not exist: '{file_path}'.",
                vector_id="A.1",
                component_id="code_verifier",
            )
        real_ws = os.path.realpath(workspace_dir) if workspace_dir else os.path.dirname(real_file)
        source_text = Path(real_file).read_text(encoding="utf-8", errors="replace")

        active_waivers = self.get_waivers_for_file(real_file)
        waived_rules: Set[str] = {w.rule_id for w in active_waivers}
        if "EXTRACTALL" in waived_rules:
            waived_rules.update({"AST_ARCHIVE_EXTRACTALL", "AST_ARCHIVE_MISSING_REALPATH", "AST_ARCHIVE_MISSING_QUOTA"})

        ast_findings = self.analyze_python_source(
            source_text,
            filename=os.path.basename(real_file),
            waived_rule_ids=frozenset(waived_rules),
        )
        sub_agent_id, token_id = self._allocate_sod_test_runner(real_ws)

        probe_outcomes: List[SandboxProbeOutcome] = []
        if run_sandbox_probes:
            if "zipfile" in source_text and "AST_ARCHIVE_EXTRACTALL" not in waived_rules:
                probe_outcomes.extend(
                    self._run_archive_adversarial_probes_in_sandbox(
                        real_file,
                        workspace_dir=real_ws,
                        sub_agent_id=sub_agent_id,
                        token_id=token_id,
                    )
                )
            else:
                exec_res = self._sandbox_guard.run_sandboxed(
                    ["python3", "-m", "py_compile", real_file],
                    workspace_dir=real_ws,
                )
                probe_outcomes.append(
                    SandboxProbeOutcome(
                        probe_name="probe_sandbox_bytecode_compile",
                        vector_id="A.1",
                        passed=(exec_res.returncode == 0),
                        sub_agent_id=sub_agent_id,
                        attenuated_token_id=token_id,
                        details=(exec_res.stdout + " " + exec_res.stderr).strip() or "py_compile OK",
                        tier=VerificationTier.TIER1_UNIVERSAL,
                    )
                )

            probe_outcomes.extend(
                self._run_tier3_synthesized_tests(
                    real_file,
                    workspace_dir=real_ws,
                    sub_agent_id=sub_agent_id,
                    token_id=token_id,
                )
            )

        all_probes_passed = all(p.passed for p in probe_outcomes)
        approved = (len(ast_findings) == 0) and all_probes_passed

        report = DeterministicVerificationReport(
            file_path=real_file,
            approved_for_execution=approved,
            ast_findings=ast_findings,
            probe_outcomes=tuple(probe_outcomes),
            sod_sub_agent_id=sub_agent_id,
            active_waivers=active_waivers,
        )

        if fail_closed and not approved:
            reasons: List[str] = [f"{f.rule_id}: {f.title}" for f in ast_findings]
            reasons.extend(
                f"{p.probe_name} FAILED ({p.details})" for p in probe_outcomes if not p.passed
            )
            primary_vec = ast_findings[0].vector_id if ast_findings else "B.1"
            raise CodeSecurityVerificationError(
                f"Code verification blocked execution of '{os.path.basename(real_file)}': {'; '.join(reasons)}",
                vector_id=primary_vec,
                component_id="code_verifier",
            )

        return report

    def run_workspace_pytest_via_sod(
        self,
        workspace_dir: str,
        *,
        target_args: Sequence[str] = (),
    ) -> SandboxProbeOutcome:
        """Execute pytest inside the workspace using an isolated SoD test-runner sub-agent."""
        real_ws = os.path.realpath(workspace_dir)
        sub_agent_id, token_id = self._allocate_sod_test_runner(real_ws)
        argv = ["python3", "-m", "pytest", "-q", *target_args]
        res = self._sandbox_guard.run_sandboxed(argv, workspace_dir=real_ws)
        out = (res.stdout + "\n" + res.stderr).strip()
        return SandboxProbeOutcome(
            probe_name="workspace_pytest_suite",
            vector_id="A.1",
            passed=(res.returncode == 0),
            sub_agent_id=sub_agent_id,
            attenuated_token_id=token_id,
            details=out or f"pytest exit code {res.returncode}",
        )
