"""Security-focused offline tests for the interactive CLI chat REPL.

Uses mock ModelGateway transport only — no live network or Ollama required.
"""

from __future__ import annotations

import json
import ssl
from io import StringIO
from pathlib import Path
from typing import Mapping, Optional

import pytest

from activesec.cli import (
    parse_repl_line,
    run_scripted_chat,
    select_coding_model,
)
from activesec.core.exceptions import ModelSecurityError
from tests.security.test_sec_dual_model_reviewer import HARDENED_EXTRACTOR_CODE


@pytest.mark.security
def test_sec_cli_chat_parser_commands() -> None:
    """[Vector E.2: CLI Control Surface] REPL parser recognizes slash commands (/status, /models, /test, /learn, /wiki, /quit) and tasks."""
    assert parse_repl_line("").kind == "empty"
    assert parse_repl_line("  /quit ").kind == "quit"
    assert parse_repl_line("/status").kind == "status"
    assert parse_repl_line("/wiki").kind == "wiki"
    assert parse_repl_line("/learn").kind == "learn"
    assert parse_repl_line("/test").kind == "test"
    assert parse_repl_line("/waive f.py EXTRACTALL trusted").kind == "waive"
    assert parse_repl_line("/promote-test syntest_123").kind == "promote_test"
    assert parse_repl_line("/models").kind == "models"
    assert parse_repl_line("/model reviewer openrouter/qwen/qwen3-coder").kind == "models"
    assert parse_repl_line("/nope").kind == "unknown"
    task = parse_repl_line("Create hello.txt with text ActiveSecHarness")
    assert task.kind == "task"
    assert "hello.txt" in task.payload


@pytest.mark.security
def test_sec_cli_chat_model_selection_skips_embeddings() -> None:
    """[Vector C.3: Model Allowlist Alignment] Prefer coding models and reject missing overrides."""
    selected = select_coding_model(
        ["all-minilm:latest", "qwen3:4b", "phi4-mini-reasoning:latest"],
        requested=None,
        fallback="fallback",
    )
    assert selected == "qwen3:4b"

    with pytest.raises(ModelSecurityError) as exc:
        select_coding_model(["qwen3:4b"], requested="missing:model", fallback="x")
    assert exc.value.vector_id == "C.3"


@pytest.mark.security
def test_sec_cli_chat_scripted_repl_step_offline(tmp_path: Path) -> None:
    """[Vector A.1/F.2: Kernel-Mediated Chat] One scripted REPL task writes via SecurityKernel using mock transport."""
    workspace = tmp_path / "workspace_live"
    workspace.mkdir()
    hello_path = workspace / "hello.txt"
    call_counter = {"n": 0}

    def _mock_transport(
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        tls_context: Optional[ssl.SSLContext],
        timeout: float,
        max_response_bytes: int,
    ) -> bytes:
        call_counter["n"] += 1
        if call_counter["n"] == 1:
            payload = {
                "model": "qwen/qwen3-coder",
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "tool_name": "fs:write",
                                    "target_path": str(hello_path),
                                    "arguments": {"content": "ActiveSecHarness live test."},
                                }
                            ),
                        }
                    }
                ],
            }
        else:
            payload = {
                "model": "qwen/qwen3-coder",
                "choices": [{"message": {"content": "File created successfully."}}],
            }
        return json.dumps(payload).encode("utf-8")

    out = StringIO()
    rc = run_scripted_chat(
        [
            "/status",
            "Create a file hello.txt with the text ActiveSecHarness live test.",
            "/quit",
        ],
        workspace_dir=str(workspace),
        provider="openrouter",
        model="qwen/qwen3-coder",
        user_wiki_dir=str(tmp_path / "wiki_user"),
        transport_func=_mock_transport,
        api_key="offline-test-key",
        output_stream=out,
    )
    assert rc == 0
    text = out.getvalue()
    assert "provider=openrouter" in text
    assert "model=qwen/qwen3-coder" in text
    assert hello_path.is_file()
    assert hello_path.read_text(encoding="utf-8") == "ActiveSecHarness live test."
    assert "File created successfully." in text
    assert call_counter["n"] >= 2


@pytest.mark.security
def test_sec_cli_chat_dual_reviewer_and_learn_test_commands(tmp_path: Path) -> None:
    """[Vector B.1, B.2 & F.1: End-to-End Chat Review, Repair & User Academy Wiki] Verifies /models, automatic dual-model repair of unsafe extractall(), /test, and /learn."""
    workspace = tmp_path / "workspace_live"
    workspace.mkdir()
    user_wiki_dir = tmp_path / "wiki_user"
    py_target = workspace / "safe_extract.py"
    step = {"n": 0}

    def _mock_transport(
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        tls_context: Optional[ssl.SSLContext],
        timeout: float,
        max_response_bytes: int,
    ) -> bytes:
        req = json.loads(body.decode("utf-8"))
        msgs = req.get("messages", [])
        sys_msg = msgs[0]["content"] if msgs else ""

        if "Independent Security Reviewer" in sys_msg:
            user_msg = msgs[-1]["content"]
            if "extractall" in user_msg:
                verdict = {
                    "approved": False,
                    "plain_explanation": "extractall() allows Zip-Slip and ZipBombs.",
                    "how_to_fix": "Use os.path.realpath() and chunked streaming.",
                    "recommended_model": "openrouter/qwen/qwen3-coder",
                }
            else:
                verdict = {
                    "approved": True,
                    "plain_explanation": "Safe streaming extractor verified.",
                    "how_to_fix": "None.",
                    "recommended_model": "",
                }
            return json.dumps({"model": "qwen/qwen3-coder", "choices": [{"message": {"content": json.dumps(verdict)}}]}).encode("utf-8")

        if "Secure Code Repair Agent" in sys_msg:
            tc = {
                "tool_name": "fs:write",
                "target_path": str(py_target),
                "arguments": {"content": HARDENED_EXTRACTOR_CODE},
            }
            return json.dumps({"model": "qwen/qwen3-coder", "choices": [{"message": {"content": "Fixed.", "tool_call": tc}}]}).encode("utf-8")

        step["n"] += 1
        if step["n"] == 1:
            tc = {
                "tool_name": "fs:write",
                "target_path": str(py_target),
                "arguments": {
                    "content": "import zipfile\ndef unpack(z, d):\n    with zipfile.ZipFile(z) as zf:\n        zf.extractall(d)\n"
                },
            }
            return json.dumps({"model": "qwen3:4b", "choices": [{"message": {"content": json.dumps(tc)}}]}).encode("utf-8")

        return json.dumps({"model": "qwen3:4b", "choices": [{"message": {"content": "Wrote safe_extract.py."}}]}).encode("utf-8")

    out = StringIO()
    rc = run_scripted_chat(
        [
            "/models",
            "Write safe_extract.py to unpack ZIP files.",
            "/test",
            "/learn",
            "/quit",
        ],
        workspace_dir=str(workspace),
        provider="openrouter",
        model="qwen/qwen3-coder",
        user_wiki_dir=str(user_wiki_dir),
        transport_func=_mock_transport,
        api_key="offline-test-key",
        output_stream=out,
    )
    assert rc == 0
    text = out.getvalue()
    assert "EXECUTION BLOCKED BY SECURITY GATE" in text
    assert "Auto-Repair Loop: Ran 1 repair iteration(s)" in text
    assert "[test:safe_extract.py] APPROVED (SAFE)" in text
    assert "User Security Academy Wiki (`wiki_user/`)" in text


@pytest.mark.security
def test_sec_cli_chat_continues_after_security_block(tmp_path: Path) -> None:
    """[Vector F.2: Canary Continuity] REPL catches canary blocks, refreshes token, and continues."""
    workspace = tmp_path / "ws"
    workspace.mkdir()
    honey = workspace / ".aws_prod_credentials.canary"
    call_counter = {"n": 0}

    def _mock_transport(
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        tls_context: Optional[ssl.SSLContext],
        timeout: float,
        max_response_bytes: int,
    ) -> bytes:
        call_counter["n"] += 1
        if call_counter["n"] == 1:
            honey_paths = list(workspace.glob("*.canary"))
            target = str(honey_paths[0]) if honey_paths else str(honey)
            payload = {
                "model": "qwen/qwen3-coder",
                "choices": [
                    {
                        "message": {
                            "content": "Harvesting.",
                            "tool_call": {"tool_name": "fs:read", "target_path": target},
                        }
                    }
                ],
            }
        else:
            payload = {
                "model": "qwen/qwen3-coder",
                "choices": [{"message": {"content": "Recovered and ready."}}],
            }
        return json.dumps(payload).encode("utf-8")

    out = StringIO()
    rc = run_scripted_chat(
        [
            "Read the secret credentials file.",
            "Say ready.",
            "/quit",
        ],
        workspace_dir=str(workspace),
        provider="openrouter",
        model="qwen/qwen3-coder",
        user_wiki_dir=str(tmp_path / "wiki_user"),
        transport_func=_mock_transport,
        api_key="offline-test-key",
        output_stream=out,
    )
    assert rc == 0
    text = out.getvalue()
    assert "SECURITY_BLOCK" in text
    assert "Recovered and ready." in text


@pytest.mark.security
def test_sec_cli_chat_truncated_ollama_json_and_test_triggers_repair(tmp_path: Path) -> None:
    """[Vector B.1, B.2 & F.2: Truncated Local JSON Recovery & /test Self-Healing] Reproduces terminal 4: recovers missing-brace fs:write JSON and verifies /test triggers the full repair loop on existing unsafe files."""
    workspace = tmp_path / "workspace_live"
    workspace.mkdir()
    user_wiki_dir = tmp_path / "wiki_user"

    # Pre-existing unsafe file in workspace_live (as in terminal 4)
    legacy_unsafe = workspace / "safe_extract.py"
    legacy_unsafe.write_text(
        "import zipfile\ndef safe_extract(zp, dest):\n    with zipfile.ZipFile(zp, 'r') as zf:\n        zf.extractall(dest)\n",
        encoding="utf-8",
    )

    new_target = workspace / "safe_zip_extractor.py"
    step = {"n": 0}

    def _mock_transport(
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        tls_context: Optional[ssl.SSLContext],
        timeout: float,
        max_response_bytes: int,
    ) -> bytes:
        req = json.loads(body.decode("utf-8"))
        msgs = req.get("messages", [])
        sys_msg = msgs[0]["content"] if msgs else ""

        if "Independent Security Reviewer" in sys_msg:
            user_msg = msgs[-1]["content"]
            if "extractall" in user_msg:
                verdict = {
                    "approved": False,
                    "plain_explanation": "extractall() allows Zip-Slip and ZipBombs.",
                    "how_to_fix": "Use os.path.realpath() and chunked streaming.",
                    "recommended_model": "openrouter/qwen/qwen3-coder",
                }
            else:
                verdict = {
                    "approved": True,
                    "plain_explanation": "Safe streaming extractor verified.",
                    "how_to_fix": "None.",
                    "recommended_model": "",
                }
            return json.dumps({"model": "qwen3:4b", "message": {"content": json.dumps(verdict)}}).encode("utf-8")

        if "Secure Code Repair Agent" in sys_msg:
            tc = {
                "tool_name": "fs:write",
                "target_path": str(new_target),
                "arguments": {"content": HARDENED_EXTRACTOR_CODE},
            }
            return json.dumps({"model": "qwen3:4b", "message": {"content": json.dumps(tc)}}).encode("utf-8")

        step["n"] += 1
        if step["n"] == 1:
            # Exact bug from terminal 4: missing final '}' at the end of the JSON string
            truncated_json = (
                '{"tool_name":"fs:write","target_path":"'
                + str(new_target)
                + '","arguments":{"content":"import zipfile\\ndef safe_extract_zip(zp, dest):\\n    with zipfile.ZipFile(zp) as zf:\\n        zf.extractall(dest)\\n"}'
            )
            return json.dumps({"model": "qwen3:4b", "message": {"content": truncated_json}}).encode("utf-8")

        return json.dumps({"model": "qwen3:4b", "message": {"content": "Done."}}).encode("utf-8")

    out = StringIO()
    rc = run_scripted_chat(
        [
            "Write a save ZIP extructor that is aware of Zip Slip and Zip Bombs.",
            "/test",
            "/learn",
            "/quit",
        ],
        workspace_dir=str(workspace),
        provider="ollama",
        model="qwen3:4b",
        user_wiki_dir=str(user_wiki_dir),
        transport_func=_mock_transport,
        api_key=None,
        output_stream=out,
    )
    assert rc == 0
    text = out.getvalue()
    assert new_target.is_file()
    assert "Auto-Repair Loop:" in text
    assert "[test:safe_extract.py:post-repair] APPROVED (SAFE)" in text
    assert "Cases Completed: 2" in text or "Cases Completed: 1" in text


@pytest.mark.security
def test_sec_cli_chat_waive_command_permits_trusted_internal_extractall(tmp_path: Path) -> None:
    """[Vector A.3 & B.1: Ring-1 ContextWaiver in Chat] Verifies /waive grants a logged Ring-1 waiver for a specific file."""
    workspace = tmp_path / "workspace_live"
    workspace.mkdir()
    internal_zip = workspace / "trusted_fixture_unpack.py"
    internal_zip.write_text(
        "import zipfile\ndef unpack_fixture(z, d):\n    with zipfile.ZipFile(z) as zf:\n        zf.extractall(d)\n",
        encoding="utf-8",
    )

    out = StringIO()
    rc = run_scripted_chat(
        [
            "/waive trusted_fixture_unpack.py EXTRACTALL Internal SHA256-verified build fixture",
            "/test",
            "/quit",
        ],
        workspace_dir=str(workspace),
        provider="openrouter",
        model="qwen/qwen3-coder",
        user_wiki_dir=str(tmp_path / "wiki_user"),
        transport_func=lambda *_a, **_kw: b"{}",
        api_key="offline-test-key",
        output_stream=out,
    )
    assert rc == 0
    text = out.getvalue()
    assert "Granted Ring-1 ContextWaiver" in text
    assert "[test:trusted_fixture_unpack.py] APPROVED (SAFE)" in text

