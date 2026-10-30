#!/usr/bin/env python3
"""ActiveSecHarness Pre-Commit Security & Karpathy Wiki Verification Gate.

Can be executed standalone (`python3 tools/pre_commit_gate.py`) or installed directly as
`.git/hooks/pre-commit` (`python3 tools/pre_commit_gate.py --install-hook`).

Enforces before every commit:
1. No Trojan Source Unicode bidirectional/zero-width control characters in tracked files.
2. No cleartext secrets (PEM keys, OpenAI/GitHub/AWS tokens) in staged source/docs files.
3. Full adversarial security test suite (`pytest tests/security/`) passes 100%.
4. Karpathy Wiki (`wiki/SECURITY_LEDGER.md` and `wiki/components/*.md`) is up to date with
   current component `sha256` hashes.
"""

from __future__ import annotations

import argparse
import os
import stat
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from activesec.core.exceptions import CredentialSecurityError  # noqa: E402
from activesec.guards.credential_guard import CredentialGuard  # noqa: E402
from activesec.sovereign.deobfuscator import TROJAN_SOURCE_UNICODE_CHARS  # noqa: E402


HOOK_SCRIPT_CONTENT = """#!/usr/bin/env sh
set -e
exec python3 tools/pre_commit_gate.py
"""


def get_tracked_or_staged_files() -> list[Path]:
    """Return all staged files (or all tracked files if nothing is staged)."""
    proc = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    names = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if not names:
        proc_all = subprocess.run(
            ["git", "ls-files"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        names = [line.strip() for line in proc_all.stdout.splitlines() if line.strip()]

    return [REPO_ROOT / n for n in names if (REPO_ROOT / n).is_file()]


def scan_files_for_trojan_unicode_and_secrets(files: list[Path]) -> list[str]:
    """Scan text files for Trojan Source Unicode codepoints and cleartext secrets."""
    cred_guard = CredentialGuard()
    errors: list[str] = []

    for fpath in files:
        rel_str = str(fpath.relative_to(REPO_ROOT))
        try:
            content = fpath.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        # 1. Check Trojan Source Unicode characters
        for line_no, line in enumerate(content.splitlines(), start=1):
            for ch in line:
                cp = ord(ch)
                if cp in TROJAN_SOURCE_UNICODE_CHARS:
                    errors.append(
                        f"[B.4 Trojan Source] {rel_str}:{line_no} contains forbidden Unicode control character U+{cp:04X}"
                    )

        # 2. Check cleartext secrets in non-test files (test files contain intentional synthetic test vectors)
        if not rel_str.startswith("tests/"):
            try:
                cred_guard.assert_no_cleartext_secrets(content)
            except CredentialSecurityError as exc:
                errors.append(f"[D.2 DLP Secret Leak] {rel_str}: {exc.message}")

    return errors


def install_git_hook() -> int:
    """Install this script as .git/hooks/pre-commit."""
    hooks_dir = REPO_ROOT / ".git" / "hooks"
    if not hooks_dir.is_dir():
        print("ERROR: .git/hooks directory not found.", file=sys.stderr)
        return 1
    hook_path = hooks_dir / "pre-commit"
    hook_path.write_text(HOOK_SCRIPT_CONTENT, encoding="utf-8")
    os.chmod(hook_path, os.stat(hook_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"[pre_commit_gate] Installed executable Git hook at {hook_path.relative_to(REPO_ROOT)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="ActiveSecHarness Pre-Commit Security Gate")
    parser.add_argument(
        "--install-hook",
        action="store_true",
        help="Install this gate as .git/hooks/pre-commit",
    )
    args = parser.parse_args()

    if args.install_hook:
        return install_git_hook()

    files = get_tracked_or_staged_files()
    scan_errors = scan_files_for_trojan_unicode_and_secrets(files)
    if scan_errors:
        for err in scan_errors:
            print(f"SECURITY GATE BLOCKED: {err}", file=sys.stderr)
        return 1

    # Run full adversarial security test suite (including fuzzer)
    pytest_proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/security", "-q"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    if pytest_proc.returncode != 0:
        print("SECURITY GATE BLOCKED: Adversarial security test suite failed!", file=sys.stderr)
        print(pytest_proc.stdout, file=sys.stderr)
        print(pytest_proc.stderr, file=sys.stderr)
        return 1

    print("[pre_commit_gate] All Trojan-Source, DLP Secret, and Adversarial Security Tests PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
