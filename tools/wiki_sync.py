#!/usr/bin/env python3
"""Automated Karpathy Security Wiki Compiler & Component Security Test Verifier.

Delegates directly to the Ring-0 `WikiManager` (`src/activesec/core/wiki_manager.py`)
so that both CLI invocations (`python3 tools/wiki_sync.py`) and the live `ActiveSecHarness`
runtime execute the exact same AST safety auditor, test verifier, and ledger compiler.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
WIKI_DIR = REPO_ROOT / "wiki"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from activesec.core.wiki_manager import (  # noqa: E402
    FORBIDDEN_CALL_NAMES,
    FORBIDDEN_MODULES,
    ComponentVerificationResult,
    RuntimeTelemetrySnapshot,
    TestCaseInfo,
    WikiManager,
    audit_python_ast,
    audit_python_ast_source,
)

__all__ = [
    "FORBIDDEN_CALL_NAMES",
    "FORBIDDEN_MODULES",
    "ComponentVerificationResult",
    "RuntimeTelemetrySnapshot",
    "TestCaseInfo",
    "WikiManager",
    "audit_python_ast",
    "audit_python_ast_source",
    "main",
]


def main() -> int:
    manager = WikiManager(repo_root=REPO_ROOT, wiki_dir=WIKI_DIR)
    overall_success, _ = manager.sync_all(execute_pytest=True, quiet=False)
    return 0 if overall_success else 1


if __name__ == "__main__":
    sys.exit(main())
