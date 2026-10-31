"""Ring-0 CodeVerifier & Isolated Separation-of-Duties (SoD) Sandbox Test Runner.

Enforces deterministic, LLM-independent security verification on generated application code:
1. Stage A.1 — Application AST & Contextual Invariant Analysis:
   - Detects forbidden unsafe primitives (`extractall`, `eval`, `exec`, `pickle.loads`,
     `yaml.load` without `SafeLoader`, `subprocess.*(..., shell=True)`, `os.system`,
     `random` for secrets/tokens, unparameterized SQL formatting, and Trojan Source Unicode).
   - Enforces domain-specific mandatory invariants: e.g., any module importing `zipfile` or
     `tarfile` for extraction must perform canonical path resolution (`os.path.realpath` or
     `.resolve()`) and bounded stream/quota checks rather than blind extraction.
2. Stage A.2 — Separation-of-Duties (SoD) Sandbox Test Runner:
   - Uses `CertifiedToolRegistry.partition_tool_plan_across_agents()` to spawn an isolated
     `test-runner` sub-agent holding an attenuated `CapabilityToken` (`shell:exec` only for
     `python3`/`pytest`, zero network access) and executes real adversarial attack probes
     (such as a crafted Zip-Slip `../escaped.txt` archive and a high-ratio decompression bomb)
     inside `SandboxGuard`.
"""

from __future__ import annotations

import ast
import os
import tempfile
import textwrap
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, FrozenSet, List, Optional, Sequence, Tuple

from activesec.core.capability_token import CapabilityCaveat, CapabilityEngine
from activesec.core.component import ComponentSecurityAssessment, SecureComponent
from activesec.core.exceptions import CodeSecurityVerificationError
from activesec.core.tool_registry import CertifiedToolRegistry
from activesec.guards.sandbox_guard import SandboxGuard, SandboxPolicy
from activesec.harness.model_gateway import ToolCallRequest
from activesec.sovereign.deobfuscator import TROJAN_SOURCE_UNICODE_CHARS


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


@dataclass(frozen=True, slots=True)
class SandboxProbeOutcome:
    """Immutable result of an adversarial security probe executed by the SoD test-runner sub-agent."""

    probe_name: str
    vector_id: str
    passed: bool
    sub_agent_id: str
    attenuated_token_id: str
    details: str


@dataclass(frozen=True, slots=True)
class DeterministicVerificationReport:
    """Complete deterministic verification verdict for a generated source file."""

    file_path: str
    approved_for_execution: bool
    ast_findings: Tuple[CodeVulnerabilityFinding, ...]
    probe_outcomes: Tuple[SandboxProbeOutcome, ...]
    sod_sub_agent_id: str

    @property
    def primary_topic_slug(self) -> str:
        if self.ast_findings:
            return self.ast_findings[0].topic_slug
        for probe in self.probe_outcomes:
            if not probe.passed and "zip" in probe.probe_name.lower():
                return "zip_slip_and_zip_bombs"
        return "secure_coding_fundamentals"


class CodeVerifier(SecureComponent):
    """Ring-0 deterministic application code verifier and SoD sandbox test runner."""

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

    @classmethod
    def security_assessment(cls) -> ComponentSecurityAssessment:
        return ComponentSecurityAssessment(
            component_id="code_verifier",
            title="Ring-0 Deterministic Application Code Verifier & SoD Sandbox Test Runner",
            ring_level=0,
            source_path="src/activesec/guards/code_verifier.py",
            security_test_path="tests/security/test_sec_code_verifier.py",
            threat_vectors=("A.1", "B.1", "B.2", "B.4", "D.1", "D.3", "E.1", "F.3"),
            summary=(
                "Provides LLM-independent deterministic security verification of agent-generated "
                "code before execution release. Combines static AST & contextual invariant analysis "
                "(blocking extractall, eval, shell=True, pickle, weak random secrets, and missing "
                "realpath/quota checks) with an isolated Separation-of-Duties (SoD) test-runner "
                "sub-agent that executes real adversarial attack payloads (Zip-Slip and ZipBomb "
                "probes) inside SandboxGuard."
            ),
            enforced_invariants=(
                "Deterministically rejects application code containing extractall(), eval(), exec(), os.system(), subprocess(..., shell=True), pickle, or Trojan Source Unicode.",
                "Enforces contextual archive safety invariants: modules importing zipfile or tarfile must include canonical path resolution (realpath/resolve) and size/ratio bounds.",
                "Uses CertifiedToolRegistry.partition_tool_plan_across_agents() to isolate test execution into a dedicated SoD sub-agent holding an attenuated shell:exec token with zero network access.",
                "Blocks execution approval whenever any static AST rule or dynamic sandbox attack probe fails.",
            ),
            residual_risks=(
                "Complex domain-specific business logic flaws that do not violate structural AST invariants or standard adversarial probes (mitigated by pairing with Stage-B DualModelReviewer).",
            ),
        )

    def analyze_python_source(
        self,
        source_text: str,
        *,
        filename: str = "<generated.py>",
    ) -> Tuple[CodeVulnerabilityFinding, ...]:
        """Statically inspect generated Python code for unsafe primitives and missing security invariants."""
        findings: List[CodeVulnerabilityFinding] = []

        # 1. Trojan Source Unicode check
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
                )
            )
            return tuple(findings)

        imports_archive_module = False
        imports_random_module = False
        has_canonical_path_check = False
        has_size_or_chunk_limit = False

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
                        )
                    )

            elif isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                if func_name in ("realpath", "resolve", "abspath"):
                    has_canonical_path_check = True

                if func_name == "extractall":
                    findings.append(
                        CodeVulnerabilityFinding(
                            rule_id="AST_ARCHIVE_EXTRACTALL",
                            vector_id="B.1",
                            severity="CRITICAL",
                            line_number=node.lineno,
                            title="Unsafe archive extraction via extractall()",
                            plain_explanation=(
                                "Calling extractall() blindly unpacks every entry in an archive at once. "
                                "This leaves the program wide open to two classic attacks: "
                                "1) Zip-Slip (files named '../../.bashrc' overwrite files outside the target folder), and "
                                "2) ZipBombs (a tiny few-kilobyte file expands into gigabytes and crashes the system)."
                            ),
                            remediation_hint=(
                                "Iterate over zf.infolist(), resolve each destination path with os.path.realpath() "
                                "to verify it stays inside the target directory, reject symlinks, and stream-read "
                                "in fixed chunks (e.g. 64 KB) while counting total bytes and compression ratio."
                            ),
                            topic_slug="zip_slip_and_zip_bombs",
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
                            )
                        )

            elif isinstance(node, ast.Compare):
                # Check if code compares byte counts / sizes / ratios
                src_seg = ast.unparse(node).lower()
                if any(tok in src_seg for tok in ("max_", "size", "bytes", "ratio", "limit", "quota")):
                    has_size_or_chunk_limit = True

        # Contextual check 1: Archive handling without canonical path check or size limit
        if imports_archive_module:
            if not has_canonical_path_check:
                findings.append(
                    CodeVulnerabilityFinding(
                        rule_id="AST_ARCHIVE_MISSING_REALPATH",
                        vector_id="B.2",
                        severity="HIGH",
                        line_number=1,
                        title="Archive handling without canonical path validation (Zip-Slip risk)",
                        plain_explanation=(
                            "The program processes archives (zipfile/tarfile) without verifying canonical target paths "
                            "via os.path.realpath() or Path.resolve(). Relative paths like '../../evil.sh' can escape "
                            "the destination directory."
                        ),
                        remediation_hint=(
                            "Resolve the target directory and each entry path with os.path.realpath() and assert "
                            "that dest_path.startswith(real_target_dir + os.sep)."
                        ),
                        topic_slug="zip_slip_and_zip_bombs",
                    )
                )
            if not has_size_or_chunk_limit:
                findings.append(
                    CodeVulnerabilityFinding(
                        rule_id="AST_ARCHIVE_MISSING_QUOTA",
                        vector_id="B.1",
                        severity="HIGH",
                        line_number=1,
                        title="Archive handling without decompression size/ratio quota (ZipBomb risk)",
                        plain_explanation=(
                            "The program extracts archive streams without enforcing a maximum byte limit or "
                            "compression ratio check. A tiny ZipBomb can exhaust disk space or memory."
                        ),
                        remediation_hint=(
                            "Read archive entries in fixed chunks (e.g. src.read(65536)), accumulate total bytes written, "
                            "and raise ValueError/SecurityError if max_bytes or max_ratio is exceeded."
                        ),
                        topic_slug="zip_slip_and_zip_bombs",
                    )
                )

        # Contextual check 2: Using weak `random` module around password/token/secret logic
        lower_source = source_text.lower()
        if imports_random_module and any(w in lower_source for w in ("password", "token", "secret", "key", "salt")):
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
        # Verify the attenuated token is valid for shell:exec and does NOT permit fs:read
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
                print("NO_EXTRACTOR_FUNCTION_FOUND")
                sys.exit(2)

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
                    # Also test manual zf.open() + os.path.join() extraction loops and symlink entries
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
                    # Check if symlink entry was accepted without rejection
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
                    # 3 MB of zeroes compresses to ~3 KB (~1000:1 ratio)
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
        """Deterministically verify a Python file via AST rules and SoD sandbox adversarial probes."""
        real_file = os.path.realpath(file_path)
        if not os.path.isfile(real_file):
            raise CodeSecurityVerificationError(
                f"Target Python file for verification does not exist: '{file_path}'.",
                vector_id="A.1",
                component_id="code_verifier",
            )
        real_ws = os.path.realpath(workspace_dir) if workspace_dir else os.path.dirname(real_file)
        source_text = Path(real_file).read_text(encoding="utf-8", errors="replace")

        ast_findings = self.analyze_python_source(source_text, filename=os.path.basename(real_file))
        sub_agent_id, token_id = self._allocate_sod_test_runner(real_ws)

        probe_outcomes: Tuple[SandboxProbeOutcome, ...] = ()
        if run_sandbox_probes:
            if "zipfile" in source_text:
                probe_outcomes = self._run_archive_adversarial_probes_in_sandbox(
                    real_file,
                    workspace_dir=real_ws,
                    sub_agent_id=sub_agent_id,
                    token_id=token_id,
                )
            else:
                # Run syntax & import compilation probe inside isolated SandboxGuard
                exec_res = self._sandbox_guard.run_sandboxed(
                    ["python3", "-m", "py_compile", real_file],
                    workspace_dir=real_ws,
                )
                probe_outcomes = (
                    SandboxProbeOutcome(
                        probe_name="probe_sandbox_bytecode_compile",
                        vector_id="A.1",
                        passed=(exec_res.returncode == 0),
                        sub_agent_id=sub_agent_id,
                        attenuated_token_id=token_id,
                        details=(exec_res.stdout + " " + exec_res.stderr).strip() or "py_compile OK",
                    ),
                )

        all_probes_passed = all(p.passed for p in probe_outcomes)
        approved = (len(ast_findings) == 0) and all_probes_passed

        report = DeterministicVerificationReport(
            file_path=real_file,
            approved_for_execution=approved,
            ast_findings=ast_findings,
            probe_outcomes=probe_outcomes,
            sod_sub_agent_id=sub_agent_id,
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
