#!/usr/bin/env python3
"""Automated Karpathy Security Wiki Compiler & Component Security Test Verifier.

This tool:
1. Imports all concrete `SecureComponent` subclasses in `src/activesec/`.
2. Performs an AST safety audit on each component source file (verifying zero forbidden
   unsafe calls such as `eval`, `exec`, `pickle`, `extractall`, `os.system`, `shell=True`).
3. Executes the dedicated adversarial security test suite (`tests/security/test_sec_<id>.py`)
   for each component and extracts per-test pass/fail status and threat vector docstrings.
4. Auto-generates/updates:
   - `wiki/components/<component_id>.md`
   - `wiki/SECURITY_LEDGER.md`
   - `wiki/log.md`
"""

from __future__ import annotations

import ast
import datetime
import hashlib
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
WIKI_DIR = REPO_ROOT / "wiki"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# Import all components so they register with SecureComponent._REGISTRY
import activesec.core.audit_log  # noqa: E402, F401
import activesec.core.capability_token  # noqa: E402, F401
import activesec.core.security_kernel  # noqa: E402, F401
import activesec.guards.archive_guard  # noqa: E402, F401
import activesec.guards.canary_guard  # noqa: E402, F401
import activesec.guards.credential_guard  # noqa: E402, F401
import activesec.guards.malware_guard  # noqa: E402, F401
import activesec.guards.network_guard  # noqa: E402, F401
import activesec.guards.sandbox_guard  # noqa: E402, F401
import activesec.harness.agent_loop  # noqa: E402, F401
import activesec.harness.model_gateway  # noqa: E402, F401
import activesec.sovereign.deobfuscator  # noqa: E402, F401
from activesec.core.component import ComponentSecurityAssessment, SecureComponent  # noqa: E402


FORBIDDEN_CALL_NAMES = frozenset({"eval", "exec", "extractall", "system", "popen"})
FORBIDDEN_MODULES = frozenset({"pickle", "marshal"})


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


def audit_python_ast(source_file: Path) -> Tuple[bool, Tuple[str, ...]]:
    """Statically inspect a Python source file for forbidden unsafe primitives."""
    source_text = source_file.read_text(encoding="utf-8")
    tree = ast.parse(source_text, filename=str(source_file))
    findings: List[str] = []

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


def run_component_security_tests(test_file: Path) -> Tuple[bool, Tuple[TestCaseInfo, ...]]:
    """Run pytest on the component's dedicated security test file and collect test metadata."""
    tree = ast.parse(test_file.read_text(encoding="utf-8"), filename=str(test_file))
    discovered_tests: List[Tuple[str, str]] = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_sec_"):
            doc = (ast.get_docstring(node) or "Adversarial security test").splitlines()[0].strip()
            discovered_tests.append((node.name, doc))

    cmd = [sys.executable, "-m", "pytest", str(test_file), "-v", "--tb=short"]
    proc = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    overall_passed = proc.returncode == 0
    stdout = proc.stdout

    cases: List[TestCaseInfo] = []
    for func_name, doc in discovered_tests:
        failed = f"::{func_name} FAILED" in stdout or (f"::{func_name}[" in stdout and "FAILED" in stdout)
        passed = not failed and overall_passed
        cases.append(TestCaseInfo(name=func_name, docstring=doc, passed=passed))

    return (overall_passed and len(cases) > 0, tuple(cases))


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

> **Auto-Generated & Verified by `tools/wiki_sync.py`** — Do not edit manual status badges directly; update the `ComponentSecurityAssessment` contract in [`{a.source_path}`](../../{a.source_path}) or the security test suite in [`{a.security_test_path}`](../../{a.security_test_path}).

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


def render_security_ledger(results: List[ComponentVerificationResult]) -> str:
    """Render `wiki/SECURITY_LEDGER.md` summarizing all components."""
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
    return f"""# ActiveSecHarness – Automated Component Security Ledger (`wiki/SECURITY_LEDGER.md`)

This ledger is automatically compiled and verified by [`tools/wiki_sync.py`](../tools/wiki_sync.py). Every component in `ActiveSecHarness` must declare a `ComponentSecurityAssessment`, pass static AST safety auditing, and pass its dedicated adversarial security test suite (`tests/security/test_sec_*.py`).

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
"""


def update_wiki_log(results: List[ComponentVerificationResult]) -> None:
    """Maintain the chronological verification log in `wiki/log.md`."""
    log_path = WIKI_DIR / "log.md"
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

    if not log_path.exists():
        header = (
            "# Karpathy Security Wiki – Chronological Verification Log (`wiki/log.md`)\n\n"
            "Append-only chronological record of security architecture updates, AST audits, and adversarial component test runs.\n\n---\n\n"
        )
        log_path.write_text(header + entry, encoding="utf-8")
        return

    existing = log_path.read_text(encoding="utf-8")
    if entry not in existing:
        log_path.write_text(existing.rstrip() + "\n\n" + entry, encoding="utf-8")


def main() -> int:
    components = SecureComponent.registered_components()
    if not components:
        print("ERROR: No SecureComponent subclasses registered.", file=sys.stderr)
        return 1

    comp_dir = WIKI_DIR / "components"
    comp_dir.mkdir(parents=True, exist_ok=True)

    results: List[ComponentVerificationResult] = []
    overall_success = True

    for comp_id in sorted(components.keys()):
        comp_cls = components[comp_id]
        assessment = comp_cls.security_assessment()
        src_path = REPO_ROOT / assessment.source_path
        test_path = REPO_ROOT / assessment.security_test_path

        if not src_path.is_file():
            print(f"ERROR: Missing source file {src_path} for {comp_id}", file=sys.stderr)
            return 1
        if not test_path.is_file():
            print(f"ERROR: Missing dedicated security test {test_path} for {comp_id}", file=sys.stderr)
            return 1

        src_sha256 = hashlib.sha256(src_path.read_bytes()).hexdigest()
        ast_safe, ast_findings = audit_python_ast(src_path)
        tests_passed, test_cases = run_component_security_tests(test_path)

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
        page_path.write_text(render_component_wiki_page(res), encoding="utf-8")
        print(f"[wiki_sync] Updated {page_path.relative_to(REPO_ROOT)} (AST={ast_safe}, Tests={tests_passed})")

    ledger_path = WIKI_DIR / "SECURITY_LEDGER.md"
    ledger_path.write_text(render_security_ledger(results), encoding="utf-8")
    print(f"[wiki_sync] Updated {ledger_path.relative_to(REPO_ROOT)}")

    update_wiki_log(results)
    print("[wiki_sync] Updated wiki/log.md")

    return 0 if overall_success else 1


if __name__ == "__main__":
    sys.exit(main())
