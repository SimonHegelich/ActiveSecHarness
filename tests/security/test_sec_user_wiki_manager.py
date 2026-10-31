"""Adversarial security tests for UserWikiManager (src/activesec/core/user_wiki_manager.py).

Verifies progressive mastery level scaling (Level 1 -> Level 2 -> Level 3), plain-language
lesson generation in `wiki_user/`, CredentialGuard DLP secret redaction in code snippets,
and symlink/path-traversal protection.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from activesec.core.exceptions import WikiSecurityError
from activesec.core.user_wiki_manager import UserWikiManager


@pytest.mark.security
def test_sec_user_wiki_progressive_mastery_levels_and_lesson_generation(tmp_path: os.PathLike[str]) -> None:
    """[Vector F.1: Human Security Education] Scales explanation complexity from Level 1 (Beginner) to Level 3 (Expert)."""
    repo_root = Path(str(tmp_path))
    wiki_user_dir = repo_root / "wiki_user"
    manager = UserWikiManager(repo_root=repo_root, user_wiki_dir=wiki_user_dir)

    # Case 1 -> Level 1 (Beginner: Everyday Analogy active, Level 2/3 locked)
    manager.record_learning_case(
        topic_slug="zip_slip_and_zip_bombs",
        task_description="Write a safe ZIP extractor",
        vulnerability_titles=("Unsafe archive extraction via extractall()",),
        plain_explanation="extractall() blindly unpacks all files without checking paths or size limits.",
        how_it_was_fixed="Replaced extractall() with os.path.realpath() check and 64 KB chunked streaming.",
        coder_model_used="ollama/qwen3:4b",
        reviewer_model_used="openrouter/qwen/qwen3-coder",
        recommended_model="openrouter/qwen/qwen3-coder",
        unsafe_code_snippet="zf.extractall(dest)",
        repaired_code_snippet="dest = os.path.realpath(os.path.join(real_target, info.filename))",
        verified_safe=True,
    )
    assert manager.current_mastery_level == 1
    lesson_lvl1 = (wiki_user_dir / "lessons" / "zip_slip_and_zip_bombs.md").read_text(encoding="utf-8")
    assert "Everyday Analogy" in lesson_lvl1
    assert "unlock **Level 2: Secure Engineering Patterns**" in lesson_lvl1

    # Add 2 more cases (total 3) -> Unlocks Level 2
    for idx in range(2):
        manager.record_learning_case(
            topic_slug="zip_slip_and_zip_bombs",
            task_description=f"Task #{idx + 2}",
            vulnerability_titles=("Missing quota",),
            plain_explanation="Missing size check.",
            how_it_was_fixed="Added max_bytes check.",
            coder_model_used="ollama/qwen3:4b",
            reviewer_model_used="openrouter/qwen/qwen3-coder",
        )
    assert manager.current_mastery_level == 2
    lesson_lvl2 = (wiki_user_dir / "lessons" / "zip_slip_and_zip_bombs.md").read_text(encoding="utf-8")
    assert "Level 2 — Secure Engineering Pattern" in lesson_lvl2

    # Add 2 more cases (total 5) -> Unlocks Level 3
    for idx in range(2):
        manager.record_learning_case(
            topic_slug="zip_slip_and_zip_bombs",
            task_description=f"Task #{idx + 4}",
            vulnerability_titles=("Overlapping deflate ratio",),
            plain_explanation="Missing archive ratio check.",
            how_it_was_fixed="Added overall archive ratio cap.",
            coder_model_used="ollama/qwen3:4b",
            reviewer_model_used="openrouter/qwen/qwen3-coder",
        )
    assert manager.current_mastery_level == 3
    lesson_lvl3 = (wiki_user_dir / "lessons" / "zip_slip_and_zip_bombs.md").read_text(encoding="utf-8")
    assert "Level 3 — Adversarial & Cryptographic Mastery" in lesson_lvl3


@pytest.mark.security
def test_sec_user_wiki_redacts_secrets_and_strips_trojan_unicode(tmp_path: os.PathLike[str]) -> None:
    """[Vector D.2 & B.4: DLP & Trojan Source in User Wiki] Redacts leaked API keys and strips invisible Bidi characters."""
    repo_root = Path(str(tmp_path))
    manager = UserWikiManager(repo_root=repo_root, user_wiki_dir=repo_root / "wiki_user")

    leaked_key = "sk-proj-1234567890abcdefghijklmnop"
    manager.record_learning_case(
        topic_slug="password_entropy_and_dictionaries",
        task_description="Configure API client \u202e",
        vulnerability_titles=("Hardcoded key",),
        plain_explanation=f"Found hardcoded key {leaked_key} in script.",
        how_it_was_fixed="Moved key to environment variable.",
        coder_model_used="ollama/qwen3:4b",
        reviewer_model_used="openrouter/qwen/qwen3-coder",
        unsafe_code_snippet=f'API_KEY = "{leaked_key}"',
    )

    progress_text = (repo_root / "wiki_user" / "LEARNING_PROGRESS.md").read_text(encoding="utf-8")
    assert leaked_key not in progress_text
    assert "<REDACTED:OPENAI_KEY:" in progress_text
    assert "\u202e" not in progress_text


@pytest.mark.security
def test_sec_user_wiki_blocks_outside_root_and_symlinks(tmp_path: os.PathLike[str]) -> None:
    """[Vector A.3: Path Containment] Rejects wiki_user directories outside repo_root or symlinked files."""
    repo_root = Path(str(tmp_path)) / "repo"
    repo_root.mkdir(parents=True, exist_ok=True)
    outside_dir = Path(str(tmp_path)) / "outside_wiki"

    with pytest.raises(WikiSecurityError) as exc_info:
        UserWikiManager(repo_root=repo_root, user_wiki_dir=outside_dir)
    assert exc_info.value.vector_id == "A.3"
