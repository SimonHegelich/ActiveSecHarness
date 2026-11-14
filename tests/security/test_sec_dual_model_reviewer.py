"""Adversarial security tests for DualModelReviewer (src/activesec/harness/dual_model_reviewer.py).

Verifies:
1. Unsafe code (`extractall()`) is strictly blocked from execution (`approved_for_execution=False`),
   produces a plain-language explanation for non-experts, and recommends a stronger OpenRouter model.
2. The self-healing Fix-Test-Verify loop escalates to the stronger model, rewrites the code with
   `os.path.realpath()` and streaming byte/ratio limits, verifies it in the SoD sandbox, and
   updates the didactic User Security Academy Wiki (`wiki_user/`).
"""

from __future__ import annotations

import json
import os
import ssl
import textwrap
from pathlib import Path
from typing import Mapping, Optional

import pytest

from activesec.core.user_wiki_manager import UserWikiManager
from activesec.guards.code_verifier import CodeVerifier
from activesec.harness.dual_model_reviewer import DualModelReviewer
from activesec.harness.model_gateway import ModelGateway, OllamaLocalConfig, OpenRouterConfig


HARDENED_EXTRACTOR_CODE = textwrap.dedent(
    """
    import os
    import stat
    import zipfile

    MAX_TOTAL_BYTES = 1024 * 1024
    MAX_RATIO = 20.0

    def safe_extract_zip(zip_path: str, target_dir: str) -> list[str]:
        real_target = os.path.realpath(target_dir)
        os.makedirs(real_target, mode=0o700, exist_ok=True)
        total_written = 0
        extracted = []

        with zipfile.ZipFile(zip_path, "r") as zf:
            for info in zf.infolist():
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise ValueError("Symlinks forbidden")
                dest = os.path.realpath(os.path.join(real_target, info.filename))
                if not (dest == real_target or dest.startswith(real_target + os.sep)):
                    raise ValueError("Zip-Slip traversal detected")
                if info.is_dir():
                    os.makedirs(dest, mode=0o700, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
                comp_size = max(1, info.compress_size)
                file_written = 0
                with zf.open(info, "r") as src, open(dest, "wb") as dst:
                    while True:
                        chunk = src.read(65536)
                        if not chunk:
                            break
                        file_written += len(chunk)
                        total_written += len(chunk)
                        if total_written > MAX_TOTAL_BYTES:
                            raise ValueError("ZipBomb size quota exceeded")
                        if file_written > 32768 and (file_written / comp_size) > MAX_RATIO:
                            raise ValueError("ZipBomb ratio exceeded")
                        dst.write(chunk)
                extracted.append(dest)
        return extracted
    """
).strip()


@pytest.mark.security
def test_sec_dual_model_reviewer_blocks_unsafe_code_and_self_heals(tmp_path: os.PathLike[str]) -> None:
    """[Vector B.1, B.2 & F.1: Dual-Model Review & Self-Healing Loop] Blocks unsafe extractall(), explains in plain language, escalates to OpenRouter fixer, and updates wiki_user/."""
    repo_root = Path(str(tmp_path))
    workspace = repo_root / "workspace_live"
    workspace.mkdir(parents=True, exist_ok=True)
    target_py = workspace / "safe_extract.py"

    # Initial vulnerable draft written by a weak local model (e.g. qwen2.5 / qwen3:4b)
    target_py.write_text(
        "import zipfile\ndef extract(zp, out):\n    with zipfile.ZipFile(zp) as zf:\n        zf.extractall(out)\n",
        encoding="utf-8",
    )

    call_log: list[str] = []

    def _mock_transport(
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        tls_context: Optional[ssl.SSLContext],
        timeout: float,
        max_response_bytes: int,
    ) -> bytes:
        req_data = json.loads(body.decode("utf-8"))
        call_log.append(f"{url}:{req_data.get('model')}")
        messages = req_data.get("messages", [])
        sys_msg = messages[0]["content"] if messages else ""

        if "Independent Security Reviewer" in sys_msg:
            user_msg = messages[-1]["content"]
            if "zf.extractall" in user_msg:
                verdict_json = json.dumps(
                    {
                        "approved": False,
                        "plain_explanation": (
                            "Your ZIP script uses extractall(), which blindly trusts filenames and sizes inside the archive. "
                            "An attacker can overwrite files outside the folder (Zip-Slip) or crash your computer with a ZipBomb."
                        ),
                        "how_to_fix": (
                            "Check every entry path with os.path.realpath() and stream-read in 64 KB chunks with a maximum size and ratio limit."
                        ),
                        "recommended_model": "openrouter/qwen/qwen3-coder",
                    }
                )
            else:
                verdict_json = json.dumps(
                    {
                        "approved": True,
                        "plain_explanation": "The repaired script properly checks canonical paths and enforces streaming byte and ratio limits.",
                        "how_to_fix": "None.",
                        "recommended_model": "",
                    }
                )
            return json.dumps({"model": "qwen/qwen3-coder", "choices": [{"message": {"content": verdict_json}}]}).encode("utf-8")

        # Repair agent call on OpenRouter
        tool_call = {
            "tool_name": "fs:write",
            "target_path": str(target_py),
            "arguments": {"content": HARDENED_EXTRACTOR_CODE},
        }
        return json.dumps(
            {
                "model": "qwen/qwen3-coder",
                "choices": [{"message": {"content": "Repaired safe_extract.py.", "tool_call": tool_call}}],
            }
        ).encode("utf-8")

    gateway = ModelGateway(
        openrouter_config=OpenRouterConfig(),
        ollama_config=OllamaLocalConfig(),
        transport_func=_mock_transport,
        api_key="test-openrouter-key",
    )
    user_wiki = UserWikiManager(repo_root=repo_root, user_wiki_dir=repo_root / "wiki_user")
    reviewer = DualModelReviewer(
        gateway=gateway,
        code_verifier=CodeVerifier(),
        user_wiki_manager=user_wiki,
        reviewer_provider="openrouter",
        reviewer_model="qwen/qwen3-coder",
        openrouter_key_available=True,
    )

    # 1. Verify review_file alone blocks execution and provides plain-language explanation + model recommendation
    verdict_only = reviewer.review_file(
        str(target_py),
        workspace_dir=str(workspace),
        coder_provider="ollama",
        coder_model="qwen3:4b",
    )
    assert verdict_only.approved_for_execution is False
    assert "Zip-Slip" in verdict_only.plain_language_explanation
    assert verdict_only.recommended_fixer_model == "openrouter/qwen/qwen3-coder"
    assert "EXECUTION BLOCKED" in verdict_only.execution_status_banner

    # 2. Run the full self-healing Fix-Test-Verify loop
    loop_res = reviewer.run_verified_coding_loop(
        str(target_py),
        task_description="Write a program to safely extract ZIP files.",
        workspace_dir=str(workspace),
        coder_provider="ollama",
        coder_model="qwen3:4b",
        auto_repair=True,
    )
    assert loop_res.initial_verdict.approved_for_execution is False
    assert loop_res.approved_for_execution is True
    assert loop_res.iterations_run == 1
    assert loop_res.repair_history[0].fixer_provider == "openrouter"
    assert loop_res.repair_history[0].fixer_model == "qwen/qwen3-coder"

    # 3. Verify the User Security Academy Wiki was populated with the lesson and before/after code
    assert loop_res.user_wiki_lesson_path is not None
    lesson_text = Path(loop_res.user_wiki_lesson_path).read_text(encoding="utf-8")
    assert "zf.extractall" in lesson_text
    assert "os.path.realpath" in lesson_text
    assert "openrouter/qwen/qwen3-coder" in lesson_text


@pytest.mark.security
def test_sec_dual_model_reviewer_offline_ollama_fallback_and_reference_remediation(tmp_path: os.PathLike[str]) -> None:
    """[Vector B.1, B.2 & F.1: Air-Gapped Local Ollama Repair Fallback] When OpenRouter is unavailable and weak local model fails to fix extractall(), certified reference remediation heals the file and updates wiki_user/."""
    repo_root = Path(str(tmp_path))
    workspace = repo_root / "workspace_live"
    workspace.mkdir(parents=True, exist_ok=True)
    target_py = workspace / "safe_extract.py"

    target_py.write_text(
        "import zipfile\ndef safe_extract(zp, out):\n    with zipfile.ZipFile(zp) as zf:\n        zf.extractall(out)\n",
        encoding="utf-8",
    )

    def _weak_local_ollama_transport(
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        tls_context: Optional[ssl.SSLContext],
        timeout: float,
        max_response_bytes: int,
    ) -> bytes:
        # Simulate weak local qwen3:4b still outputting unsafe extractall() or truncated JSON
        truncated = (
            '{"tool_name":"fs:write","target_path":"'
            + str(target_py)
            + '","arguments":{"content":"import zipfile\\ndef safe_extract(zp, out):\\n    with zipfile.ZipFile(zp) as zf:\\n        zf.extractall(out)\\n"}'
        )
        return json.dumps({"model": "qwen3:4b", "message": {"content": truncated}}).encode("utf-8")

    gateway = ModelGateway(
        openrouter_config=OpenRouterConfig(),
        ollama_config=OllamaLocalConfig(),
        transport_func=_weak_local_ollama_transport,
        api_key=None,
    )
    user_wiki = UserWikiManager(repo_root=repo_root, user_wiki_dir=repo_root / "wiki_user")
    reviewer = DualModelReviewer(
        gateway=gateway,
        code_verifier=CodeVerifier(),
        user_wiki_manager=user_wiki,
        reviewer_provider="openrouter",
        reviewer_model="qwen/qwen3-coder",
        openrouter_key_available=False,
    )

    loop_res = reviewer.run_verified_coding_loop(
        str(target_py),
        task_description="Write a safe ZIP extractor that is aware of Zip Slip and Zip Bombs.",
        workspace_dir=str(workspace),
        coder_provider="ollama",
        coder_model="qwen3:4b",
        auto_repair=True,
    )
    assert loop_res.initial_verdict.approved_for_execution is False
    assert loop_res.approved_for_execution is True
    assert loop_res.repair_history[-1].fixer_provider == "ring0-reference"
    assert loop_res.user_wiki_lesson_path is not None
    assert Path(loop_res.user_wiki_lesson_path).is_file()


class _ScriptedGateway:
    """Minimal stand-in for ModelGateway: returns a fixed reviewer answer and a fixed repair answer."""

    def __init__(self, *, review: object, repair: str = "") -> None:
        self._review = review
        self._repair = repair

    def chat(self, messages, **_kwargs):  # type: ignore[no-untyped-def]
        from activesec.harness.model_gateway import ModelResponse

        is_repair = "fs:write" in messages[0].content
        answer = self._repair if is_repair else self._review
        if isinstance(answer, Exception):
            raise answer
        return ModelResponse(content=str(answer), tool_call=None, model_id="scripted", provider_name="scripted")


@pytest.mark.security
def test_sec_reviewer_does_not_claim_a_stage_b_review_that_did_not_happen(tmp_path: Path) -> None:
    """[Vector F.1: Review Integrity] Without an explicit Stage-B verdict the result says the approval rests on Stage A only."""
    from activesec.core.exceptions import ModelSecurityError

    safe_file = tmp_path / "add.py"
    safe_file.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    unusable_answers: list[object] = [
        "I think it is probably fine.",
        json.dumps({"plain_explanation": "looks fine"}),
        ModelSecurityError("reviewer offline", vector_id="C.1", component_id="model_gateway"),
    ]
    for answer in unusable_answers:
        reviewer = DualModelReviewer(gateway=_ScriptedGateway(review=answer), openrouter_key_available=False)  # type: ignore[arg-type]
        verdict = reviewer.review_file(str(safe_file), workspace_dir=str(tmp_path))
        assert verdict.approved_for_execution is True
        assert "STAGE A ONLY" in verdict.execution_status_banner
        assert "rests on Stage A only" in verdict.plain_language_explanation
        assert "Both deterministic" not in verdict.plain_language_explanation

    reviewer = DualModelReviewer(gateway=_ScriptedGateway(review=json.dumps({"approved": True})), openrouter_key_available=False)  # type: ignore[arg-type]
    verdict = reviewer.review_file(str(safe_file), workspace_dir=str(tmp_path))
    assert verdict.approved_for_execution is True
    assert "Stage-B review" in verdict.execution_status_banner and "STAGE A ONLY" not in verdict.execution_status_banner


@pytest.mark.security
def test_sec_repair_loop_never_persists_a_secret_from_the_model(tmp_path: Path) -> None:
    """[Vector D.2: Secret DLP] A model-generated repair that embeds a cleartext secret is not written to disk."""
    target = tmp_path / "calc.py"
    original = "def calc(expr):\n    return eval(expr)\n"
    target.write_text(original, encoding="utf-8")
    access_key = "AKI" + "A" + "ABCDEFGHIJKLMNOP"
    leaking_repair = "```python\nAWS_ACCESS_KEY_ID = '" + access_key + "'\n\ndef calc(expr):\n    return float(expr)\n```"

    reviewer = DualModelReviewer(
        gateway=_ScriptedGateway(review=json.dumps({"approved": True}), repair=leaking_repair),  # type: ignore[arg-type]
        openrouter_key_available=False,
    )
    result = reviewer.run_verified_coding_loop(str(target), task_description="demo", workspace_dir=str(tmp_path))
    assert access_key not in target.read_text(encoding="utf-8")
    assert result.approved_for_execution is False


