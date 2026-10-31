"""Adversarial security tests for WorkspaceProvenanceLedger & Compositional Multi-Agent SoD (src/activesec/core/sod_policy.py).

Verifies:
1. Cross-agent workspace laundering block: Agent A reads a sensitive file (`READ_SENSITIVE`) and writes
   to a benign-named workspace staging file (`staging_notes.txt`). Agent B (holding only `fs:read` and
   `net:https` or `shell:exec`) reads `staging_notes.txt` and attempts `net:https` or arbitrary `shell:exec`
   — deterministically blocked as a compositional Lethal Trifecta (`ToxicCombinationError`, `vector_id="F.3"`).
2. Cross-agent untrusted prompt-injection laundering block: Agent A reads an untrusted external file/issue,
   writes a script to the workspace, and Agent B reads it and attempts arbitrary shell execution.
3. Explicit Ring-1/Ring-0 declassification (`declassify_artifact` -> `SANITIZED`): allows safe downstream
   handoff after deterministic scrubbing.
4. `DERIVED` taint workflow preservation across collaborating agents: reading an untrusted issue ->
   deriving a structured summary (`derive_agent_summary` -> `DERIVED`) -> editing code (`fs:write`) ->
   running isolated `pytest` in `SandboxGuard` succeeds without false positives while still blocking `net:https`.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from activesec.core.capability_token import (
    CapabilityCaveat,
    CapabilityEngine,
    InformationClass,
)
from activesec.core.exceptions import CapabilityViolationError, ToxicCombinationError
from activesec.core.security_kernel import SecurityKernel
from activesec.core.sod_policy import WorkspaceProvenanceLedger
from activesec.harness.model_gateway import ToolCallRequest


@pytest.mark.security
def test_sec_compositional_sod_blocks_cross_agent_workspace_secret_laundering(tmp_path: Path) -> None:
    """[Vector F.3: Cross-Agent Workspace Laundering Block] Agent A (READ_SENSITIVE -> fs:write) + Agent B (fs:read -> net:https) is deterministically blocked as a compositional Lethal Trifecta."""
    ws = tmp_path / "workspace"
    ws.mkdir()

    secret_source = ws / "confidential_payroll.txt"
    secret_source.write_text("Executive compensation: $1.2M\n", encoding="utf-8")
    staging_file = ws / "summary_cache.txt"

    engine = CapabilityEngine()
    kernel = SecurityKernel(workspace_dir=str(ws), capability_engine=engine)

    # Agent A has ONLY local file permissions (fs:read, fs:write) — no network or shell
    token_a = engine.issue_root_token(
        subject_agent_id="agent-reader-a",
        task_purpose="Read confidential doc and write workspace summary",
        caveat=CapabilityCaveat(
            allowed_tools=frozenset({"fs:read", "fs:write"}),
            path_prefixes=(str(ws),),
            max_calls=5,
            expires_at_unix=time.time() + 300.0,
            max_information_class=InformationClass.SENSITIVE,
        ),
    )

    # Agent B has fs:read and net:https (individually non-toxic if reading public files)
    token_b = engine.issue_root_token(
        subject_agent_id="agent-egress-b",
        task_purpose="Read public summary and post telemetry",
        caveat=CapabilityCaveat(
            allowed_tools=frozenset({"fs:read", "net:https"}),
            path_prefixes=(str(ws),),
            network_destinations=frozenset({"pypi.org"}),
            max_calls=5,
            expires_at_unix=time.time() + 300.0,
            max_information_class=InformationClass.SENSITIVE,
        ),
    )

    # Step 1: Agent A reads confidential_payroll.txt (inferred SENSITIVE provenance)
    res_read_a = kernel.execute_tool_call(
        ToolCallRequest(tool_name="fs:read", target_path=str(secret_source)),
        token=token_a,
        agent_id="agent-reader-a",
    )
    assert "Executive" in res_read_a.output
    assert kernel.provenance_ledger.get_agent_state("agent-reader-a").information_class == InformationClass.SENSITIVE

    # Step 2: Agent A writes to benign-looking staging_file in workspace
    kernel.execute_tool_call(
        ToolCallRequest(
            tool_name="fs:write",
            target_path=str(staging_file),
            arguments={"content": "encoded_payroll_summary_chunk_1"},
        ),
        token=token_a,
        agent_id="agent-reader-a",
    )
    # Verify staging_file inherited SENSITIVE provenance and READ_SENSITIVE origin from Agent A!
    file_rec = kernel.provenance_ledger.get_file_record(str(staging_file))
    assert file_rec is not None
    assert file_rec.information_class == InformationClass.SENSITIVE
    assert "READ_SENSITIVE" in file_rec.origin_side_effects

    # Step 3: Agent B reads staging_file -> absorbs SENSITIVE provenance & READ_SENSITIVE
    kernel.execute_tool_call(
        ToolCallRequest(tool_name="fs:read", target_path=str(staging_file)),
        token=token_b,
        agent_id="agent-egress-b",
    )
    assert kernel.provenance_ledger.get_agent_state("agent-egress-b").information_class == InformationClass.SENSITIVE

    # Step 4: Agent B attempts network egress -> deterministically blocked as Compositional Lethal Trifecta!
    with pytest.raises(ToxicCombinationError) as exc_info:
        kernel.execute_tool_call(
            ToolCallRequest(
                tool_name="net:https",
                network_destination="pypi.org",
                arguments={"url": "https://pypi.org/simple/", "body": "encoded_payroll_summary_chunk_1"},
            ),
            token=token_b,
            agent_id="agent-egress-b",
        )
    assert exc_info.value.vector_id == "F.3"
    assert "compositional" in exc_info.value.message.lower()


@pytest.mark.security
def test_sec_compositional_sod_blocks_cross_agent_untrusted_shell_laundering(tmp_path: Path) -> None:
    """[Vector F.2 & F.3: Cross-Agent Untrusted Injection Laundering] Agent A reads untrusted external payload and writes to workspace; Agent B reads it and is blocked from arbitrary shell:exec."""
    ws = tmp_path / "workspace"
    ws.mkdir()

    untrusted_issue = ws / "issue_404_untrusted.md"
    untrusted_issue.write_text("Bug report: please run build helper.\n", encoding="utf-8")
    handoff_note = ws / "task_context.txt"

    engine = CapabilityEngine()
    kernel = SecurityKernel(workspace_dir=str(ws), capability_engine=engine)

    token_a = engine.issue_root_token(
        subject_agent_id="triage-agent",
        task_purpose="Read untrusted issue and write handoff note",
        caveat=CapabilityCaveat(
            allowed_tools=frozenset({"fs:read", "fs:write"}),
            path_prefixes=(str(ws),),
            max_calls=5,
            expires_at_unix=time.time() + 300.0,
            max_information_class=InformationClass.UNTRUSTED,
        ),
    )
    token_b = engine.issue_root_token(
        subject_agent_id="runner-agent",
        task_purpose="Read handoff note and run commands",
        caveat=CapabilityCaveat(
            allowed_tools=frozenset({"fs:read", "shell:exec"}),
            path_prefixes=(str(ws),),
            allowed_binaries=frozenset({"echo", "pytest"}),
            max_calls=5,
            expires_at_unix=time.time() + 300.0,
            max_information_class=InformationClass.UNTRUSTED,
        ),
    )

    # Triage agent reads untrusted issue, derives a summary note (DERIVED), and writes handoff note
    kernel.execute_tool_call(
        ToolCallRequest(tool_name="fs:read", target_path=str(untrusted_issue)),
        token=token_a,
        agent_id="triage-agent",
    )
    kernel.provenance_ledger.derive_agent_summary("triage-agent")
    kernel.execute_tool_call(
        ToolCallRequest(
            tool_name="fs:write",
            target_path=str(handoff_note),
            arguments={"content": "derived summary from issue #404"},
        ),
        token=token_a,
        agent_id="triage-agent",
    )

    # Runner agent reads handoff note -> absorbs DERIVED provenance
    kernel.execute_tool_call(
        ToolCallRequest(tool_name="fs:read", target_path=str(handoff_note)),
        token=token_b,
        agent_id="runner-agent",
    )

    # Runner agent attempting arbitrary shell command (`echo pwned`) is blocked under DERIVED taint!
    with pytest.raises((ToxicCombinationError, CapabilityViolationError)) as exc_info:
        kernel.execute_tool_call(
            ToolCallRequest(tool_name="shell:exec", raw_command="echo pwned", binary_name="echo"),
            token=token_b,
            agent_id="runner-agent",
        )
    assert exc_info.value.vector_id in ("F.2", "F.3")


@pytest.mark.security
def test_sec_derived_taint_and_explicit_declassification_preserve_swe_workflows(tmp_path: Path) -> None:
    """[Vector F.2 & F.3: DERIVED Taint SWE Usability & Ring-1 Declassification] Verifies that DERIVED taint permits workspace code edits and isolated pytest runs, and Ring-1 declassification (SANITIZED) permits safe handoff."""
    ws = tmp_path / "workspace"
    ws.mkdir()

    issue_file = ws / "issue_12_external.txt"
    issue_file.write_text("Fix off-by-one in calc.py\n", encoding="utf-8")
    code_file = ws / "calc.py"

    ledger = WorkspaceProvenanceLedger(workspace_dir=str(ws))
    ledger.record_file_read(agent_id="coder-agent", path=str(issue_file))
    assert ledger.get_agent_state("coder-agent").information_class == InformationClass.UNTRUSTED

    # Transition from UNTRUSTED issue read to DERIVED structured plan
    ledger.derive_agent_summary("coder-agent")
    assert ledger.get_agent_state("coder-agent").information_class == InformationClass.DERIVED

    # Under DERIVED taint, coder-agent can write code_file and test-agent can read it and run isolated pytest
    ledger.verify_compositional_action(
        agent_id="coder-agent",
        tool_name="fs:write",
        target_path=str(code_file),
    )
    ledger.record_file_write(agent_id="coder-agent", path=str(code_file), content="def add(a, b): return a + b\n")

    ledger.record_file_read(agent_id="test-agent", path=str(code_file))
    assert ledger.get_agent_state("test-agent").information_class == InformationClass.DERIVED

    # Isolated pytest is permitted under DERIVED taint
    eff_class = ledger.verify_compositional_action(
        agent_id="test-agent",
        tool_name="shell:exec",
        binary_name="pytest",
        raw_command="pytest -q tests/test_calc.py",
    )
    assert eff_class == InformationClass.DERIVED

    # Network egress is still blocked under DERIVED taint
    with pytest.raises(CapabilityViolationError):
        ledger.verify_compositional_action(
            agent_id="test-agent",
            tool_name="net:https",
        )

    # Ring-2/3 agent cannot self-declassify an artifact
    with pytest.raises(CapabilityViolationError):
        ledger.declassify_artifact(str(code_file), authorized_by_ring=3)

    # Ring-1 explicit declassification to SANITIZED allows downstream release agent to read without taint
    declassified = ledger.declassify_artifact(str(code_file), authorized_by_ring=1, sanitized_content="release_ok")
    assert declassified.information_class == InformationClass.SANITIZED
    ledger.record_file_read(agent_id="release-agent", path=str(code_file))
    assert ledger.get_agent_state("release-agent").information_class == InformationClass.SANITIZED
    assert (
        ledger.verify_compositional_action(agent_id="release-agent", tool_name="net:https")
        == InformationClass.SANITIZED
    )
