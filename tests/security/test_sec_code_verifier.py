"""Adversarial security tests for CodeVerifier (src/activesec/guards/code_verifier.py).

Verifies that:
1. Unsafe generated code (such as `safe_extract.py` calling `zf.extractall()` on unvalidated input)
   is deterministically caught by both AST analysis and live Zip-Slip / ZipBomb probes.
2. Context-sensitive `extractall()` (when preceded by `infolist()` canonical path + quota checks,
   on a self-created local archive, or with an explicit Ring-1 `ContextWaiver`) is PERMITTED without
   false-positive over-blocking.
3. Unsafe `eval()`, `subprocess(..., shell=True)`, `pickle`, and `random` secret generation are blocked.
4. Properly hardened streaming extraction code passes all probes.
"""

from __future__ import annotations

import os
import textwrap

import pytest

from activesec.core.exceptions import CodeSecurityVerificationError
from activesec.guards.code_verifier import CodeVerifier


@pytest.mark.security
def test_sec_code_verifier_blocks_unsafe_extractall_live_case(tmp_path: os.PathLike[str]) -> None:
    """[Vector B.1 & B.2: Unsafe Generated Zip Extractor] Blocks unvalidated extractall() via AST rules and live Zip-Slip/ZipBomb sandbox probes."""
    unsafe_script = os.path.join(str(tmp_path), "safe_extract.py")
    with open(unsafe_script, "w", encoding="utf-8") as fh:
        fh.write(
            textwrap.dedent(
                """
                import zipfile

                def extract_zip(zip_path: str, extract_to: str) -> None:
                    with zipfile.ZipFile(zip_path, "r") as zf:
                        zf.extractall(extract_to)
                """
            ).strip()
        )

    verifier = CodeVerifier()
    report = verifier.verify_python_file(unsafe_script, workspace_dir=str(tmp_path))

    assert report.approved_for_execution is False
    rule_ids = {f.rule_id for f in report.ast_findings}
    assert "AST_ARCHIVE_EXTRACTALL" in rule_ids
    assert "AST_ARCHIVE_MISSING_REALPATH" in rule_ids
    assert "AST_ARCHIVE_MISSING_QUOTA" in rule_ids

    failed_probes = {p.probe_name for p in report.probe_outcomes if not p.passed}
    assert "probe_adversarial_zip_slip_traversal" in failed_probes
    assert "probe_adversarial_zip_bomb_ratio" in failed_probes
    assert ":sod-stage-" in report.sod_sub_agent_id

    with pytest.raises(CodeSecurityVerificationError):
        verifier.verify_python_file(unsafe_script, workspace_dir=str(tmp_path), fail_closed=True)


@pytest.mark.security
def test_sec_code_verifier_permits_contextually_safe_extractall_and_waivers(tmp_path: os.PathLike[str]) -> None:
    """[Vector B.1 & B.2: Contextual Tier-2 Scoping] Permits extractall() when pre-validated with infolist+realpath+quota or Ring-1 waiver."""
    prevalidated_script = os.path.join(str(tmp_path), "prevalidated_extract.py")
    with open(prevalidated_script, "w", encoding="utf-8") as fh:
        fh.write(
            textwrap.dedent(
                """
                import os
                import stat
                import zipfile

                MAX_BYTES = 1024 * 1024

                def extract_prevalidated(zip_path: str, target_dir: str) -> None:
                    real_target = os.path.realpath(target_dir)
                    os.makedirs(real_target, exist_ok=True)
                    total_size = 0
                    with zipfile.ZipFile(zip_path, "r") as zf:
                        for info in zf.infolist():
                            if stat.S_ISLNK(info.external_attr >> 16):
                                raise ValueError("Symlink blocked")
                            dest = os.path.realpath(os.path.join(real_target, info.filename))
                            if not (dest == real_target or dest.startswith(real_target + os.sep)):
                                raise ValueError("Zip-Slip blocked")
                            total_size += info.file_size
                            if total_size > MAX_BYTES:
                                raise ValueError("Quota exceeded")
                        zf.extractall(real_target)
                """
            ).strip()
        )

    verifier = CodeVerifier()
    rep = verifier.verify_python_file(prevalidated_script, workspace_dir=str(tmp_path), fail_closed=True)
    assert rep.approved_for_execution is True
    assert len(rep.ast_findings) == 0

    # Also verify Ring-1 ContextWaiver on an internal build helper using extractall()
    internal_script = os.path.join(str(tmp_path), "internal_fixture.py")
    with open(internal_script, "w", encoding="utf-8") as fh:
        fh.write(
            "import zipfile\ndef unpack_trusted_fixture(z, d):\n    with zipfile.ZipFile(z) as zf:\n        zf.extractall(d)\n"
        )
    verifier.grant_context_waiver(
        file_path=internal_script,
        rule_id="EXTRACTALL",
        justification="Trusted internal build artifact verified by SHA-256",
        granted_by_ring=1,
    )
    rep_waived = verifier.verify_python_file(internal_script, workspace_dir=str(tmp_path), fail_closed=True)
    assert rep_waived.approved_for_execution is True
    assert len(rep_waived.active_waivers) == 1


@pytest.mark.security
def test_sec_code_verifier_approves_hardened_streaming_zip_extractor(tmp_path: os.PathLike[str]) -> None:
    """[Vector B.1 & B.2: Verified Safe Extractor] Approves streaming extractor that enforces realpath and ratio/byte quotas."""
    safe_script = os.path.join(str(tmp_path), "hardened_extract.py")
    with open(safe_script, "w", encoding="utf-8") as fh:
        fh.write(
            textwrap.dedent(
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
        )

    verifier = CodeVerifier()
    report = verifier.verify_python_file(safe_script, workspace_dir=str(tmp_path), fail_closed=True)
    assert report.approved_for_execution is True
    assert len(report.ast_findings) == 0
    assert all(p.passed for p in report.probe_outcomes)


@pytest.mark.security
def test_sec_code_verifier_detects_eval_shell_true_pickle_and_weak_random(tmp_path: os.PathLike[str]) -> None:
    """[Vector A.1, B.3 & D.3: Unsafe Primitives] Detects eval, shell=True, pickle, and random password generation."""
    bad_file = os.path.join(str(tmp_path), "bad_app.py")
    with open(bad_file, "w", encoding="utf-8") as fh:
        fh.write(
            textwrap.dedent(
                """
                import pickle
                import random
                import subprocess

                def generate_password() -> str:
                    return str(random.randint(1000, 9999))

                def run_cmd(user_input: str) -> None:
                    eval(user_input)
                    subprocess.run(user_input, shell=True)
                """
            ).strip()
        )

    verifier = CodeVerifier()
    report = verifier.verify_python_file(bad_file, workspace_dir=str(tmp_path), run_sandbox_probes=False)
    assert report.approved_for_execution is False
    rules = {f.rule_id for f in report.ast_findings}
    assert "AST_UNSAFE_DESERIALIZATION" in rules
    assert "AST_DYNAMIC_CODE_EXEC" in rules
    assert "AST_SUBPROCESS_SHELL_TRUE" in rules
    assert "AST_WEAK_RANDOM_FOR_SECRET" in rules
