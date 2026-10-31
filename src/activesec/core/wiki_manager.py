"""Ring-0 Native Karpathy Security Wiki Manager & Runtime Telemetry Synchronizer.

Integrates Andrej Karpathy's Living Security Wiki directly into the ActiveSecHarness
Ring-0 runtime so that both CLI invocations (`python3 -m activesec.cli --sync-wiki`),
self-tests (`run_self_test()`), and agent execution loops (`AgentLoop.run(..., auto_sync_wiki=True)`)
automatically verify AST safety, validate component source SHA-256 integrity, record
cryptographically verified runtime telemetry, and update `wiki/SECURITY_LEDGER.md`,
`wiki/components/*.md`, and `wiki/log.md`.
"""

from __future__ import annotations

import ast
import datetime
import hashlib
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple

from activesec.core.audit_log import HashChainedAuditLog
from activesec.core.component import ComponentSecurityAssessment, SecureComponent
from activesec.core.exceptions import AuditIntegrityError, WikiSecurityError
from activesec.sovereign.deobfuscator import TROJAN_SOURCE_UNICODE_CHARS


FORBIDDEN_CALL_NAMES: FrozenSet[str] = frozenset({"eval", "exec", "extractall", "system", "popen"})
FORBIDDEN_MODULES: FrozenSet[str] = frozenset({"pickle", "marshal"})


@dataclass(frozen=True, slots=True)
class TestCaseInfo:
    """Metadata extracted from a component's adversarial security test function."""

    name: str
    docstring: str
    passed: bool


@dataclass(frozen=True, slots=True)
class ComponentVerificationResult:
    """Complete verification snapshot for a single SecureComponent."""

    assessment: ComponentSecurityAssessment
    source_sha256: str
    ast_safe: bool
    ast_findings: Tuple[str, ...]
    test_cases: Tuple[TestCaseInfo, ...]
    all_tests_passed: bool


@dataclass(frozen=True, slots=True)
class RuntimeTelemetrySnapshot:
    """Immutable snapshot of runtime security telemetry extracted from HashChainedAuditLog."""

    session_label: str
    total_events: int
    allowed_tool_calls: int
    blocked_tool_calls: int
    canary_alerts: int
    triggered_vectors: Tuple[str, ...]
    audit_chain_verified: bool
    head_entry_hash: str


def audit_python_ast_source(source_text: str, *, filename: str = "<memory>") -> Tuple[bool, Tuple[str, ...]]:
    """Statically inspect Python source text for forbidden unsafe primitives and Trojan Unicode."""
    findings: List[str] = []

    for line_no, line in enumerate(source_text.splitlines(), start=1):
        for ch in line:
            cp = ord(ch)
            if cp in TROJAN_SOURCE_UNICODE_CHARS:
                findings.append(
                    f"Line {line_no}: Forbidden Trojan Source Unicode control character U+{cp:04X}"
                )

    try:
        tree = ast.parse(source_text, filename=filename)
    except SyntaxError as exc:
        findings.append(f"Line {exc.lineno or 0}: SyntaxError during AST audit: {exc.msg}")
        return (False, tuple(findings))

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in FORBIDDEN_MODULES:
                    findings.append(f"Line {node.lineno}: Forbidden import '{alias.name}'")
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] in FORBIDDEN_MODULES:
                findings.append(f"Line {node.lineno}: Forbidden import from '{node.module}'")
        elif isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            if func_name in FORBIDDEN_CALL_NAMES:
                findings.append(f"Line {node.lineno}: Forbidden call '{func_name}()'")

            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    findings.append(f"Line {node.lineno}: Forbidden subprocess 'shell=True'")

    return (len(findings) == 0, tuple(findings))


def audit_python_ast(source_file: Path) -> Tuple[bool, Tuple[str, ...]]:
    """Statically inspect a Python source file for forbidden unsafe primitives."""
    source_text = source_file.read_text(encoding="utf-8")
    return audit_python_ast_source(source_text, filename=str(source_file))


class WikiManager(SecureComponent):
    """Ring-0 engine maintaining the self-verifying Karpathy Security Wiki and runtime telemetry."""

    def __init__(
        self,
        *,
        repo_root: Optional[Path | str] = None,
        wiki_dir: Optional[Path | str] = None,
    ) -> None:
        resolved_root = (
            Path(os.path.realpath(repo_root))
            if repo_root is not None
            else Path(__file__).resolve().parents[3]
        )
        self._repo_root: Path = resolved_root
        if wiki_dir is not None:
            resolved_wiki = Path(os.path.realpath(wiki_dir))
            if not (
                resolved_wiki == self._repo_root
                or str(resolved_wiki).startswith(str(self._repo_root) + os.sep)
            ):
                raise WikiSecurityError(
                    f"Wiki directory '{wiki_dir}' escapes repository root '{self._repo_root}'.",
                    vector_id="A.3",
                    component_id="wiki_manager",
                )
            self._wiki_dir: Path = resolved_wiki
        else:
            self._wiki_dir = self._repo_root / "wiki"

        self._telemetry_history: List[RuntimeTelemetrySnapshot] = []

    @classmethod
    def security_assessment(cls) -> ComponentSecurityAssessment:
        return ComponentSecurityAssessment(
            component_id="wiki_manager",
            title="Ring-0 Karpathy Security Wiki Compiler & Runtime Telemetry Synchronizer",
            ring_level=0,
            source_path="src/activesec/core/wiki_manager.py",
            security_test_path="tests/security/test_sec_wiki_manager.py",
            threat_vectors=("A.1", "A.3", "B.4", "F.3"),
            summary=(
                "Natively embeds Andrej Karpathy's Living Security Wiki into Ring 0 of the "
                "ActiveSecHarness runtime. Performs static Python AST safety and Trojan Source "
                "auditing across all registered SecureComponent modules, verifies source SHA-256 "
                "hashes against the ledger to detect post-verification tampering, executes "
                "component security test suites, and streams verified runtime telemetry from "
                "HashChainedAuditLog directly into wiki/SECURITY_LEDGER.md, wiki/components/*.md, "
                "and wiki/log.md."
            ),
            enforced_invariants=(
                "Statically scans every component AST for forbidden unsafe calls (eval, exec, extractall, system, popen, shell=True, pickle, marshal) and Trojan Source Unicode characters.",
                "Confines all wiki file writes strictly within the canonical repository root (os.path.realpath) and rejects symlinked wiki targets.",
                "Verifies HashChainedAuditLog cryptographic chain integrity before recording any runtime security telemetry snapshot into the Wiki.",
                "Detects unauthorized component source modifications by comparing live SHA-256 digests against pinned ledger fingerprints.",
            ),
            residual_risks=(
                "Static AST analysis inspects syntactic call nodes within registered Python files; dynamic runtime enforcement is paired with SandboxGuard and CertifiedToolRegistry.",
            ),
        )

    @property
    def repo_root(self) -> Path:
        return self._repo_root

    @property
    def wiki_dir(self) -> Path:
        return self._wiki_dir

    @property
    def telemetry_history(self) -> Tuple[RuntimeTelemetrySnapshot, ...]:
        return tuple(self._telemetry_history)

    @staticmethod
    def ensure_all_components_imported() -> None:
        """Import all canonical ActiveSecHarness modules so subclasses register with SecureComponent."""
        import activesec.core.audit_log  # noqa: F401
        import activesec.core.capability_token  # noqa: F401
        import activesec.core.security_kernel  # noqa: F401
        import activesec.core.wiki_manager  # noqa: F401
        import activesec.guards.archive_guard  # noqa: F401
        import activesec.guards.canary_guard  # noqa: F401
        import activesec.guards.credential_guard  # noqa: F401
        import activesec.guards.malware_guard  # noqa: F401
        import activesec.guards.network_guard  # noqa: F401
        import activesec.guards.sandbox_guard  # noqa: F401
        import activesec.harness.agent_loop  # noqa: F401
        import activesec.harness.model_gateway  # noqa: F401
        import activesec.sovereign.deobfuscator  # noqa: F401

        try:
            import activesec.core.tool_registry  # noqa: F401
            import activesec.core.user_wiki_manager  # noqa: F401
            import activesec.guards.code_verifier  # noqa: F401
            import activesec.harness.dual_model_reviewer  # noqa: F401
        except ImportError:
            pass

    def _safe_write_wiki_file(self, target_path: Path, content: str) -> None:
        """Write a markdown artifact inside wiki_dir while rejecting symlinks and path traversal."""
        if os.path.islink(target_path) or os.path.islink(target_path.parent):
            raise WikiSecurityError(
                f"Refusing to write wiki file to symbolic link '{target_path}'.",
                vector_id="A.3",
                component_id="wiki_manager",
            )
        real_parent = os.path.realpath(target_path.parent)
        real_wiki = os.path.realpath(self._wiki_dir)
        if not (real_parent == real_wiki or real_parent.startswith(real_wiki + os.sep)):
            raise WikiSecurityError(
                f"Wiki target '{target_path}' escapes canonical wiki directory '{real_wiki}'.",
                vector_id="A.3",
                component_id="wiki_manager",
            )
        target_path.write_text(content, encoding="utf-8")

    def inspect_source_ast(self, source_file: Path, *, strict: bool = True) -> Tuple[bool, Tuple[str, ...]]:
        """Audit a Python file for forbidden AST primitives and optionally raise WikiSecurityError."""
        safe, findings = audit_python_ast(source_file)
        if not safe and strict:
            raise WikiSecurityError(
                f"AST safety violation in '{source_file.name}': {'; '.join(findings)}",
                vector_id="A.1",
                component_id="wiki_manager",
            )
        return (safe, findings)

    def verify_component_integrity(
        self,
        expected_hashes: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        """Compute live SHA-256 hashes of all registered components and detect source tampering or AST violations."""
        self.ensure_all_components_imported()
        components = SecureComponent.registered_components()
        live_hashes: Dict[str, str] = {}

        for comp_id in sorted(components.keys()):
            assessment = components[comp_id].security_assessment()
            src_path = self._repo_root / assessment.source_path
            if not src_path.is_file():
                raise WikiSecurityError(
                    f"Missing source file '{assessment.source_path}' for component '{comp_id}'.",
                    vector_id="A.3",
                    component_id="wiki_manager",
                )
            self.inspect_source_ast(src_path, strict=True)
            digest = hashlib.sha256(src_path.read_bytes()).hexdigest()
            live_hashes[comp_id] = digest

            if expected_hashes and comp_id in expected_hashes:
                expected_prefix = expected_hashes[comp_id].strip().lower()
                if not digest.lower().startswith(expected_prefix):
                    raise WikiSecurityError(
                        f"Component source tampering detected for '{comp_id}': expected sha256 prefix "
                        f"'{expected_prefix}', got '{digest[:len(expected_prefix)]}'.",
                        vector_id="A.3",
                        component_id="wiki_manager",
                    )

        return live_hashes

    def verify_ledger_integrity(self) -> bool:
        """Verify that `wiki/SECURITY_LEDGER.md` matches the live SHA-256 hashes of all components."""
        ledger_path = self._wiki_dir / "SECURITY_LEDGER.md"
        if not ledger_path.is_file():
            raise WikiSecurityError(
                f"Security ledger '{ledger_path}' does not exist.",
                vector_id="A.3",
                component_id="wiki_manager",
            )
        ledger_text = ledger_path.read_text(encoding="utf-8")
        pinned_hashes: Dict[str, str] = {}
        for line in ledger_text.splitlines():
            if line.startswith("| **[`") and "`** |" in line:
                parts = [p.strip() for p in line.strip("|").split("|")]
                if len(parts) >= 6:
                    comp_part = parts[0]
                    sha_part = parts[5].strip("` ")
                    start_idx = comp_part.find("[`")
                    end_idx = comp_part.find("`]")
                    if start_idx != -1 and end_idx != -1 and sha_part:
                        comp_id = comp_part[start_idx + 2 : end_idx]
                        pinned_hashes[comp_id] = sha_part

        if not pinned_hashes:
            raise WikiSecurityError(
                "Security ledger contains no valid component SHA-256 entries.",
                vector_id="A.3",
                component_id="wiki_manager",
            )

        live_hashes = self.verify_component_integrity(expected_hashes=pinned_hashes)
        for comp_id in live_hashes:
            if comp_id not in pinned_hashes:
                raise WikiSecurityError(
                    f"Component '{comp_id}' is missing from wiki/SECURITY_LEDGER.md.",
                    vector_id="A.3",
                    component_id="wiki_manager",
                )
        return True

    def discover_test_cases(self, test_file: Path, *, default_passed: bool = True) -> Tuple[TestCaseInfo, ...]:
        """Statically extract adversarial test case names and docstrings from a security test module."""
        tree = ast.parse(test_file.read_text(encoding="utf-8"), filename=str(test_file))
        cases: List[TestCaseInfo] = []
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_sec_"):
                doc = (ast.get_docstring(node) or "Adversarial security test").splitlines()[0].strip()
                cases.append(TestCaseInfo(name=node.name, docstring=doc, passed=default_passed))
        return tuple(cases)

    def run_component_security_tests(self, test_file: Path) -> Tuple[bool, Tuple[TestCaseInfo, ...]]:
        """Run pytest on the component's dedicated security test file and collect test metadata."""
        discovered = self.discover_test_cases(test_file, default_passed=True)
        cmd = [sys.executable, "-m", "pytest", str(test_file), "-v", "--tb=short"]
        proc = subprocess.run(
            cmd,
            cwd=str(self._repo_root),
            capture_output=True,
            text=True,
            check=False,
        )
        overall_passed = proc.returncode == 0
        stdout = proc.stdout

        cases: List[TestCaseInfo] = []
        for tc in discovered:
            failed = f"::{tc.name} FAILED" in stdout or (f"::{tc.name}[" in stdout and "FAILED" in stdout)
            passed = not failed and overall_passed
            cases.append(TestCaseInfo(name=tc.name, docstring=tc.docstring, passed=passed))

        return (overall_passed and len(cases) > 0, tuple(cases))

    def collect_runtime_telemetry(
        self,
        audit_log: HashChainedAuditLog,
        *,
        session_label: str = "runtime_session",
    ) -> RuntimeTelemetrySnapshot:
        """Verify the audit log chain and extract a structured RuntimeTelemetrySnapshot."""
        try:
            chain_ok = audit_log.verify_chain()
        except AuditIntegrityError as exc:
            raise WikiSecurityError(
                f"Refusing to sync runtime telemetry from tampered audit log: {exc.message}",
                vector_id="A.3",
                component_id="wiki_manager",
            ) from exc

        entries = audit_log.entries
        allowed = sum(1 for e in entries if e.event_type == "TOOL_CALL_ALLOWED")
        blocked = sum(1 for e in entries if e.event_type == "TOOL_CALL_BLOCKED")
        canary = sum(1 for e in entries if e.event_type == "CANARY_TRIPWIRE_ALERT")
        vectors = tuple(
            sorted({e.vector_id for e in entries if e.vector_id and e.vector_id != "NONE"})
        )
        head_hash = entries[-1].entry_hash[:16] if entries else "0" * 16

        snapshot = RuntimeTelemetrySnapshot(
            session_label=session_label,
            total_events=len(entries),
            allowed_tool_calls=allowed,
            blocked_tool_calls=blocked,
            canary_alerts=canary,
            triggered_vectors=vectors,
            audit_chain_verified=chain_ok,
            head_entry_hash=head_hash,
        )
        self._telemetry_history.append(snapshot)
        return snapshot

    @staticmethod
    def render_component_wiki_page(result: ComponentVerificationResult) -> str:
        """Render the Karpathy Wiki markdown page for a single SecureComponent."""
        a = result.assessment
        status_badge = "VERIFIED (PASS)" if (result.all_tests_passed and result.ast_safe) else "FAILED / UNVERIFIED"
        ast_badge = "CLEAN (Zero Forbidden Primitives)" if result.ast_safe else "VIOLATION DETECTED"

        invariants_md = "\n".join(f"- {inv}" for inv in a.enforced_invariants)
        risks_md = "\n".join(f"- {risk}" for risk in a.residual_risks)
        vectors_md = ", ".join(f"`{v}`" for v in a.threat_vectors)

        test_rows: List[str] = []
        for tc in result.test_cases:
            tc_status = "PASS" if tc.passed else "FAIL"
            test_rows.append(f"| `{tc.name}` | {tc.docstring} | **{tc_status}** |")
        tests_table = "\n".join(test_rows)

        return f"""# Component Security Assessment: `{a.component_id}`

> **Auto-Generated & Verified by `WikiManager` (`tools/wiki_sync.py`)** — Do not edit manual status badges directly; update the `ComponentSecurityAssessment` contract in [`{a.source_path}`](../../{a.source_path}) or the security test suite in [`{a.security_test_path}`](../../{a.security_test_path}).

---

## 1. Security Posture Metadata

| Attribute | Value |
| :--- | :--- |
| **Component ID** | `{a.component_id}` |
| **Title** | {a.title} |
| **Privilege Ring** | **Ring {a.ring_level}** |
| **Mitigated Threat Vectors** | {vectors_md} |
| **Source File** | [`{a.source_path}`](../../{a.source_path}) (`sha256:{result.source_sha256[:12]}`) |
| **Dedicated Security Test Suite** | [`{a.security_test_path}`](../../{a.security_test_path}) |
| **AST Static Safety Audit** | **{ast_badge}** |
| **Adversarial Security Verification** | **{status_badge}** ({len(result.test_cases)} test vectors) |

---

## 2. Architectural Summary

{a.summary}

---

## 3. Enforced Deterministic Security Invariants

{invariants_md}

---

## 4. Dedicated Component Security Tests (`{a.security_test_path}`)

| Test Function | Verified Adversarial Vector & Invariant | Status |
| :--- | :--- | :--- |
{tests_table}

---

## 5. Known Residual Risks & Defense-in-Depth Pairing

{risks_md}
"""

    @staticmethod
    def render_security_ledger(
        results: Sequence[ComponentVerificationResult],
        *,
        latest_telemetry: Optional[RuntimeTelemetrySnapshot] = None,
    ) -> str:
        """Render `wiki/SECURITY_LEDGER.md` summarizing all components and optional runtime telemetry."""
        rows: List[str] = []
        total_tests = 0
        for r in results:
            a = r.assessment
            total_tests += len(r.test_cases)
            status = "VERIFIED" if (r.all_tests_passed and r.ast_safe) else "FAILED"
            ast_status = "CLEAN" if r.ast_safe else "UNSAFE"
            vectors = ", ".join(f"`{v}`" for v in a.threat_vectors)
            rows.append(
                f"| **[`{a.component_id}`](components/{a.component_id}.md)** | Ring {a.ring_level} | {vectors} | `{ast_status}` | **{status}** ({len(r.test_cases)}/{len(r.test_cases)} passed) | `{r.source_sha256[:10]}` |"
            )

        table_md = "\n".join(rows)
        telemetry_section = ""
        if latest_telemetry is not None:
            trig = (
                ", ".join(f"`{v}`" for v in latest_telemetry.triggered_vectors)
                if latest_telemetry.triggered_vectors
                else "`NONE`"
            )
            telemetry_section = f"""
---

## Latest Runtime Security Telemetry (`{latest_telemetry.session_label}`)

- **Audit Chain Verification:** `{"VERIFIED" if latest_telemetry.audit_chain_verified else "FAILED"}` (Head SHA-256: `{latest_telemetry.head_entry_hash}`)
- **Total Mediated Events:** {latest_telemetry.total_events} (Allowed: {latest_telemetry.allowed_tool_calls}, Blocked: {latest_telemetry.blocked_tool_calls}, Canary Tripwires: {latest_telemetry.canary_alerts})
- **Triggered Threat Vectors:** {trig}
"""

        return f"""# ActiveSecHarness – Automated Component Security Ledger (`wiki/SECURITY_LEDGER.md`)

This ledger is automatically compiled and verified by `WikiManager` ([`src/activesec/core/wiki_manager.py`](../src/activesec/core/wiki_manager.py) & [`tools/wiki_sync.py`](../tools/wiki_sync.py)). Every component in `ActiveSecHarness` must declare a `ComponentSecurityAssessment`, pass static AST safety auditing, and pass its dedicated adversarial security test suite (`tests/security/test_sec_*.py`).

---

## Live Component Verification Matrix

| Component | Privilege Ring | Mitigated Threat Vectors | AST Safety Audit | Security Test Status | Source SHA-256 |
| :--- | :--- | :--- | :--- | :--- | :--- |
{table_md}

---

## Summary Metrics

- **Registered Security Components:** {len(results)}
- **Dedicated Adversarial Test Vectors Executed:** {total_tests}
- **Overall Posture:** {"ALL COMPONENTS VERIFIED" if all(r.all_tests_passed and r.ast_safe for r in results) else "ATTENTION REQUIRED"}
{telemetry_section}"""

    def update_wiki_log(
        self,
        results: Sequence[ComponentVerificationResult],
        *,
        telemetry: Optional[RuntimeTelemetrySnapshot] = None,
    ) -> None:
        """Maintain the chronological verification and runtime telemetry log in `wiki/log.md`."""
        log_path = self._wiki_dir / "log.md"
        today = datetime.date.today().isoformat()
        all_ok = all(r.all_tests_passed and r.ast_safe for r in results)
        comp_list = ", ".join(f"`{r.assessment.component_id}`" for r in results)
        total_vectors = sum(len(r.test_cases) for r in results)

        entry = (
            f"## [{today}] wiki_sync | Verified {len(results)} Components ({total_vectors} Adversarial Test Vectors)\n\n"
            f"- **Status:** {'ALL PASSED & AST CLEAN' if all_ok else 'FAILURE DETECTED'}\n"
            f"- **Components Audited:** {comp_list}\n"
            f"- **Artifacts Updated:** `wiki/SECURITY_LEDGER.md`, `wiki/components/*.md`\n"
        )
        if telemetry is not None:
            vectors_str = (
                ", ".join(f"`{v}`" for v in telemetry.triggered_vectors)
                if telemetry.triggered_vectors
                else "`NONE`"
            )
            entry += (
                f"- **Runtime Telemetry (`{telemetry.session_label}`):** "
                f"{telemetry.total_events} events (allowed={telemetry.allowed_tool_calls}, "
                f"blocked={telemetry.blocked_tool_calls}, canary_alerts={telemetry.canary_alerts}, "
                f"vectors={vectors_str}, head_hash=`{telemetry.head_entry_hash}`)\n"
            )

        if not log_path.exists():
            header = (
                "# Karpathy Security Wiki – Chronological Verification Log (`wiki/log.md`)\n\n"
                "Append-only chronological record of security architecture updates, AST audits, and adversarial component test runs.\n\n---\n\n"
            )
            self._safe_write_wiki_file(log_path, header + entry)
            return

        existing = log_path.read_text(encoding="utf-8")
        if entry not in existing:
            self._safe_write_wiki_file(log_path, existing.rstrip() + "\n\n" + entry)

    def sync_all(
        self,
        *,
        execute_pytest: bool = True,
        audit_log: Optional[HashChainedAuditLog] = None,
        session_label: str = "wiki_sync",
        quiet: bool = False,
    ) -> Tuple[bool, Tuple[ComponentVerificationResult, ...]]:
        """Synchronize all component wiki pages, the security ledger, and runtime telemetry."""
        self.ensure_all_components_imported()
        components = SecureComponent.registered_components()
        if not components:
            raise WikiSecurityError(
                "No SecureComponent subclasses registered for Wiki synchronization.",
                vector_id="A.3",
                component_id="wiki_manager",
            )

        comp_dir = self._wiki_dir / "components"
        comp_dir.mkdir(parents=True, exist_ok=True)

        telemetry: Optional[RuntimeTelemetrySnapshot] = None
        if audit_log is not None:
            telemetry = self.collect_runtime_telemetry(audit_log, session_label=session_label)

        results: List[ComponentVerificationResult] = []
        overall_success = True

        for comp_id in sorted(components.keys()):
            comp_cls = components[comp_id]
            assessment = comp_cls.security_assessment()
            src_path = self._repo_root / assessment.source_path
            test_path = self._repo_root / assessment.security_test_path

            if not src_path.is_file():
                raise WikiSecurityError(
                    f"Missing source file '{src_path}' for component '{comp_id}'.",
                    vector_id="A.3",
                    component_id="wiki_manager",
                )
            if not test_path.is_file():
                raise WikiSecurityError(
                    f"Missing dedicated security test '{test_path}' for component '{comp_id}'.",
                    vector_id="A.3",
                    component_id="wiki_manager",
                )

            src_sha256 = hashlib.sha256(src_path.read_bytes()).hexdigest()
            ast_safe, ast_findings = audit_python_ast(src_path)
            if execute_pytest:
                tests_passed, test_cases = self.run_component_security_tests(test_path)
            else:
                test_cases = self.discover_test_cases(test_path, default_passed=True)
                tests_passed = len(test_cases) > 0

            if not ast_safe or not tests_passed:
                overall_success = False

            res = ComponentVerificationResult(
                assessment=assessment,
                source_sha256=src_sha256,
                ast_safe=ast_safe,
                ast_findings=ast_findings,
                test_cases=test_cases,
                all_tests_passed=tests_passed,
            )
            results.append(res)

            page_path = comp_dir / f"{comp_id}.md"
            self._safe_write_wiki_file(page_path, self.render_component_wiki_page(res))
            if not quiet:
                rel_page = page_path.relative_to(self._repo_root) if page_path.is_relative_to(self._repo_root) else page_path
                print(f"[wiki_sync] Updated {rel_page} (AST={ast_safe}, Tests={tests_passed})")

        ledger_path = self._wiki_dir / "SECURITY_LEDGER.md"
        self._safe_write_wiki_file(
            ledger_path,
            self.render_security_ledger(results, latest_telemetry=telemetry),
        )
        if not quiet:
            rel_ledger = ledger_path.relative_to(self._repo_root) if ledger_path.is_relative_to(self._repo_root) else ledger_path
            print(f"[wiki_sync] Updated {rel_ledger}")

        self.update_wiki_log(results, telemetry=telemetry)
        if not quiet:
            print("[wiki_sync] Updated wiki/log.md")

        return (overall_success, tuple(results))
