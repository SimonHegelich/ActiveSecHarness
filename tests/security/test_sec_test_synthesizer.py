"""Adversarial security tests for SecurityTestSynthesizer (src/activesec/harness/test_synthesizer.py).

Verifies:
1. When a novel vulnerability (e.g. path traversal in a custom file reader) is flagged by the reviewer,
   SecurityTestSynthesizer generates a deterministic probe script and validates the Red-Green-Benign Triad.
2. Broken or overly broad hallucinated tests (that fail on benign inputs or pass on vulnerable code)
   are deterministically rejected by the Triad gate.
3. Synthesized tests are scoped task-locally (TIER3_TASK_SCOPED) so they do not break unrelated files,
   and can be promoted to the catalog only after full Red-Green-Benign verification and Ring-1 approval.
"""

from __future__ import annotations

import json
import os
import ssl
import textwrap
from pathlib import Path
from typing import Mapping, Optional

import pytest

from activesec.core.exceptions import CodeSecurityVerificationError
from activesec.guards.code_verifier import CodeVerifier
from activesec.harness.model_gateway import ModelGateway, OllamaLocalConfig, OpenRouterConfig
from activesec.harness.test_synthesizer import SecurityTestSynthesizer


SYNTHESIZED_PATH_TRAVERSAL_PROBE = textwrap.dedent(
    """
    import importlib.util
    import os
    import sys
    import tempfile

    target_py = sys.argv[1]
    mode = sys.argv[2]

    spec = importlib.util.spec_from_file_location("mod", target_py)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    with tempfile.TemporaryDirectory() as tmp:
        base_dir = os.path.join(tmp, "docs")
        os.makedirs(base_dir, exist_ok=True)
        safe_doc = os.path.join(base_dir, "note.txt")
        with open(safe_doc, "w", encoding="utf-8") as fh:
            fh.write("hello_safe")

        secret_outside = os.path.join(tmp, "secret.txt")
        with open(secret_outside, "w", encoding="utf-8") as fh:
            fh.write("TOP_SECRET_LEAK")

        if mode == "benign":
            out = mod.read_user_doc(base_dir, "note.txt")
            if out != "hello_safe":
                sys.exit(3)
            sys.exit(0)

        if mode == "adversarial":
            try:
                leaked = mod.read_user_doc(base_dir, "../secret.txt")
            except Exception:
                sys.exit(0)
            if "TOP_SECRET_LEAK" in str(leaked):
                sys.exit(4)
            sys.exit(0)
    """
).strip()


@pytest.mark.security
def test_sec_synthesizer_enforces_red_green_benign_triad_and_task_scope(tmp_path: os.PathLike[str]) -> None:
    """[Vector B.2 & F.3: Red-Green-Benign Test Synthesis] Synthesizes a deterministic probe, verifies Red+Benign+Green, and scopes it to the target file."""
    ws = Path(str(tmp_path))
    vuln_doc_reader = ws / "doc_reader.py"
    other_unrelated_file = ws / "math_helper.py"

    # Vulnerable custom file reader (passes basic py_compile, but has a ../ path traversal bug)
    vuln_doc_reader.write_text(
        textwrap.dedent(
            """
            import os

            def read_user_doc(base_dir: str, relative_name: str) -> str:
                full = os.path.join(base_dir, relative_name)
                with open(full, "r", encoding="utf-8") as fh:
                    return fh.read()
            """
        ).strip(),
        encoding="utf-8",
    )
    other_unrelated_file.write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")

    def _mock_transport(
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        tls_context: Optional[ssl.SSLContext],
        timeout: float,
        max_response_bytes: int,
    ) -> bytes:
        resp = {
            "model": "qwen/qwen3-coder",
            "choices": [{"message": {"content": f"```python\n{SYNTHESIZED_PATH_TRAVERSAL_PROBE}\n```"}}],
        }
        return json.dumps(resp).encode("utf-8")

    gateway = ModelGateway(
        openrouter_config=OpenRouterConfig(),
        ollama_config=OllamaLocalConfig(),
        transport_func=_mock_transport,
        api_key="test-key",
    )
    verifier = CodeVerifier()
    synthesizer = SecurityTestSynthesizer(gateway=gateway, code_verifier=verifier)

    # 1. Synthesize test and verify Proof 1 (AST), Proof 2 (RED on vulnerable), Proof 3 (BENIGN-SAFE)
    syn_test = synthesizer.synthesize_and_verify_test(
        vulnerable_file_path=str(vuln_doc_reader),
        vulnerability_explanation="os.path.join without os.path.realpath allows ../ path traversal.",
        how_to_fix="Resolve paths with os.path.realpath and check prefix containment.",
        workspace_dir=str(ws),
    )
    assert syn_test is not None
    assert syn_test.triad_verified is True
    assert syn_test.red_on_vulnerable_passed is True
    assert syn_test.benign_safe_passed is True
    assert syn_test.green_on_repaired_passed is False

    # 2. Because the synthesized test is now registered on doc_reader.py, CodeVerifier deterministically blocks the vulnerable file!
    rep_vuln = verifier.verify_python_file(str(vuln_doc_reader), workspace_dir=str(ws))
    assert rep_vuln.approved_for_execution is False

    # 3. Task-Scope Isolation: The unrelated math_helper.py is NOT affected by doc_reader's Tier-3 test!
    rep_other = verifier.verify_python_file(str(other_unrelated_file), workspace_dir=str(ws))
    assert rep_other.approved_for_execution is True

    # 4. Repair doc_reader.py and verify Proof 4 (GREEN on repaired)
    vuln_doc_reader.write_text(
        textwrap.dedent(
            """
            import os

            def read_user_doc(base_dir: str, relative_name: str) -> str:
                real_base = os.path.realpath(base_dir)
                real_target = os.path.realpath(os.path.join(real_base, relative_name))
                if not (real_target == real_base or real_target.startswith(real_base + os.sep)):
                    raise ValueError("Path traversal blocked")
                with open(real_target, "r", encoding="utf-8") as fh:
                    return fh.read()
            """
        ).strip(),
        encoding="utf-8",
    )
    green_rec = synthesizer.verify_green_on_repaired(
        syn_test.test_id,
        str(vuln_doc_reader),
        workspace_dir=str(ws),
    )
    assert green_rec.green_on_repaired_passed is True

    # Now CodeVerifier approves doc_reader.py
    rep_fixed = verifier.verify_python_file(str(vuln_doc_reader), workspace_dir=str(ws))
    assert rep_fixed.approved_for_execution is True

    # 5. Promote to catalog requires Ring 1
    with pytest.raises(CodeSecurityVerificationError):
        synthesizer.promote_verified_test(syn_test.test_id, authorized_by_ring=3)

    promoted = synthesizer.promote_verified_test(syn_test.test_id, authorized_by_ring=1)
    assert promoted.promoted_to_catalog is True


@pytest.mark.security
def test_sec_synthesizer_rejects_broken_or_always_failing_tests(tmp_path: os.PathLike[str]) -> None:
    """[Vector A.1: Anti-Hallucination Gate] Rejects synthesized tests that fail on benign inputs or use unsafe AST primitives."""
    ws = Path(str(tmp_path))
    target = ws / "app.py"
    target.write_text("def greet(name: str) -> str:\n    return 'Hello ' + name\n", encoding="utf-8")

    # Test script that always exits 1 even in benign mode (would break every program if accepted!)
    always_failing_test = "import sys\nsys.exit(1)\n"

    def _mock_transport(
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        tls_context: Optional[ssl.SSLContext],
        timeout: float,
        max_response_bytes: int,
    ) -> bytes:
        resp = {
            "model": "qwen/qwen3-coder",
            "choices": [{"message": {"content": always_failing_test}}],
        }
        return json.dumps(resp).encode("utf-8")

    gateway = ModelGateway(
        openrouter_config=OpenRouterConfig(),
        ollama_config=OllamaLocalConfig(),
        transport_func=_mock_transport,
        api_key="test-key",
    )
    synthesizer = SecurityTestSynthesizer(gateway=gateway)
    res = synthesizer.synthesize_and_verify_test(
        vulnerable_file_path=str(target),
        vulnerability_explanation="Hypothetical flaw",
        how_to_fix="Fix",
        workspace_dir=str(ws),
        max_attempts=1,
    )
    assert res is None
