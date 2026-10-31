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


@pytest.mark.security
def test_sec_cli_chat_parser_commands() -> None:
    """[Vector E.2: CLI Control Surface] REPL parser recognizes slash commands and tasks."""
    assert parse_repl_line("").kind == "empty"
    assert parse_repl_line("  /quit ").kind == "quit"
    assert parse_repl_line("/status").kind == "status"
    assert parse_repl_line("/wiki").kind == "wiki"
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
def test_sec_cli_chat_continues_after_security_block(tmp_path: Path) -> None:
    """[Vector F.2: Canary Continuity] REPL catches canary blocks, refreshes token, and continues."""
    workspace = tmp_path / "ws"
    workspace.mkdir()
    honey = workspace / ".aws_prod_credentials.canary"
    # Canaries are deployed by build_chat_runtime; we target the default honeyfile name after deploy.
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
        # First task: attempt canary read. Second task: benign finish.
        if call_counter["n"] == 1:
            # Discover honeyfile path from deployed canaries by scanning workspace.
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
        transport_func=_mock_transport,
        api_key="offline-test-key",
        output_stream=out,
    )
    assert rc == 0
    text = out.getvalue()
    assert "SECURITY_BLOCK" in text
    assert "Recovered and ready." in text
