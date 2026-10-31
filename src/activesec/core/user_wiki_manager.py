"""Ring-1 UserWikiManager: Didactic User Security Academy Wiki (`wiki_user/`).

Maintains a second, human-centric security knowledge base (`wiki_user/`) designed to turn
the user step-by-step from a non-expert into a cybersecurity expert while using the harness:
- Starts at a deliberately low, accessible complexity level (`Level 1: Foundations & Everyday Analogies`)
  and unlocks deeper architectural and adversarial layers (`Level 2: Secure Engineering Patterns`,
  `Level 3: Adversarial & Cryptographic Mastery`) as the user encounters and resolves security cases.
- Systematizes discovered vulnerabilities in plain language, explains how attackers and social
  engineers exploit them, compares the unsafe draft vs. verified safe code, and provides a
  practical checklist.
- Enforces strict path confinement, symlink rejection, and CredentialGuard DLP secret redaction
  before writing any markdown file to `wiki_user/`.
"""

from __future__ import annotations

import datetime
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from activesec.core.component import ComponentSecurityAssessment, SecureComponent
from activesec.core.exceptions import WikiSecurityError
from activesec.guards.credential_guard import CredentialGuard
from activesec.sovereign.deobfuscator import TROJAN_SOURCE_UNICODE_CHARS


@dataclass(frozen=True, slots=True)
class TopicPedagogyTemplate:
    """Curriculum template for a security topic across progressive mastery levels."""

    topic_slug: str
    title: str
    vector_ids: Tuple[str, ...]
    everyday_analogy: str
    plain_explanation: str
    social_engineering_angle: str
    level2_engineering_deep_dive: str
    level3_adversarial_mastery: str
    user_checklist: Tuple[str, ...]


DEFAULT_CURRICULUM: Mapping[str, TopicPedagogyTemplate] = {
    "zip_slip_and_zip_bombs": TopicPedagogyTemplate(
        topic_slug="zip_slip_and_zip_bombs",
        title="Archive Safety: Zip-Slip Path Traversal & Decompression Bombs (ZipBombs)",
        vector_ids=("B.1", "B.2"),
        everyday_analogy=(
            "Imagine receiving a small moving box labeled 'Office Supplies'. When you open it, "
            " two things can go wrong: 1) An item inside has an address label saying 'Put this directly "
            "into the home safe in the bedroom' (Zip-Slip), or 2) The box contains a compressed inflatable "
            "raft that instantly expands to fill your entire house until the walls burst (ZipBomb)."
        ),
        plain_explanation=(
            "Standard archive helpers like Python's `zipfile.extractall()` trust the filenames and sizes "
            "stored inside the ZIP file. However, an attacker controls those filenames and headers! "
            "A filename like `../../.bashrc` can escape the destination folder and overwrite startup scripts "
            "(Zip-Slip), and a 40 KB file of compressed zeroes can expand into gigabytes of data that freeze "
            "your computer (ZipBomb)."
        ),
        social_engineering_angle=(
            "Attackers often share 'helpful test fixtures', 'dataset.zip', or 'starter templates' in GitHub "
            "issues or forums and ask you (or your AI coding assistant) to unpack them. Even small local AI "
            "models frequently write `zf.extractall()` because it is the shortest code snippet in their training data."
        ),
        level2_engineering_deep_dive=(
            "**Level 2 — Secure Engineering Pattern:**\n"
            "1. **Canonical Path Check (`os.path.realpath`):** Resolve the target directory and each archive member's "
            "full destination path via `os.path.realpath()`. Verify `dest.startswith(real_target + os.sep)` before opening any file.\n"
            "2. **Reject Symlinks & Special Files:** Inspect `info.external_attr >> 16` with `stat.S_ISLNK` so an attacker "
            "cannot plant a symlink pointing outside the folder.\n"
            "3. **Chunked Streaming Quota:** Never trust `info.file_size` in the header. Read the stream in 64 KB chunks "
            "(`src.read(65536)`), count actual bytes written, and abort immediately if total bytes or compression ratio (`written / compress_size`) exceed your quota."
        ),
        level3_adversarial_mastery=(
            "**Level 3 — Adversarial & Cryptographic Mastery:**\n"
            "- **Overlapping Deflate Streams (`zbsm.zip`):** Advanced non-recursive ZipBombs reuse the same compressed "
            "byte blocks across thousands of local file headers so the overall archive ratio explodes even if single files look moderate. "
            "Therefore, track **both** per-entry ratio and cumulative `total_written / archive_file_size`.\n"
            "- **Two-Stage Symlink Race (TOCTOU):** Extract into an isolated `0700` quarantine directory on a `noexec,nosuid,nodev` mount "
            "and enforce `0600` permissions on extracted files."
        ),
        user_checklist=(
            "Never accept `zf.extractall()` or `tar.extractall()` in generated code.",
            "Always check that `os.path.realpath()` is used to lock files inside the target folder.",
            "Verify that archive extraction reads in bounded chunks with a maximum byte and ratio limit.",
        ),
    ),
    "command_injection_and_code_execution": TopicPedagogyTemplate(
        topic_slug="command_injection_and_code_execution",
        title="Command Injection & Arbitrary Code Execution (`eval`, `exec`, `shell=True`)",
        vector_ids=("A.1", "F.1"),
        everyday_analogy=(
            "Giving `eval()` or `shell=True` to user input is like signing a blank check and handing it to "
            "a stranger so they can 'fill in the exact amount for the groceries'—they can write any instruction they want."
        ),
        plain_explanation=(
            "Functions like `eval()`, `exec()`, `os.system()`, and `subprocess.run(..., shell=True)` interpret "
            "text strings as live system commands. If an attacker smuggles characters like `;`, `&&`, or `| sh` "
            "into a filename or input field, the computer executes the attacker's command right alongside yours."
        ),
        social_engineering_angle=(
            "Copy-paste traps on websites or in README files often disguise malicious commands inside `echo <base64> | base64 -d | sh` "
            "or ask you to approve a quick shell one-liner to 'fix a permission error'."
        ),
        level2_engineering_deep_dive=(
            "**Level 2 — Secure Engineering Pattern:**\n"
            "- Always pass commands as an explicit argument list: `subprocess.run(['python3', 'script.py', arg], shell=False)`.\n"
            "- Replace `eval()` with safe parsers like `json.loads()` or `ast.literal_eval()`."
        ),
        level3_adversarial_mastery=(
            "**Level 3 — Adversarial & Cryptographic Mastery:**\n"
            "- Even with `shell=False`, legitimate binaries (GTFOBins/LOLBins like `find -exec`, `tar --checkpoint-action`, `git -c`) "
            "can execute sub-commands via flags. Pair explicit `argv` lists with binary allowlists and `bubblewrap` (`bwrap --unshare-all`) namespace isolation."
        ),
        user_checklist=(
            "Reject `eval()`, `exec()`, `os.system()`, and `shell=True`.",
            "Always inspect decoded payloads before approving any command in a terminal.",
        ),
    ),
    "password_entropy_and_dictionaries": TopicPedagogyTemplate(
        topic_slug="password_entropy_and_dictionaries",
        title="Password Strength, Dictionary Attacks & Cryptographic Randomness (`secrets` vs `random`)",
        vector_ids=("D.1", "D.2", "D.3"),
        everyday_analogy=(
            "Replacing 'e' with '3' and 'a' with '@' in `P@ssw0rd2026!` is like hiding your house key under "
            "the doormat—every burglar checks there in the very first second."
        ),
        plain_explanation=(
            "Modern password crackers test millions of dictionary words combined with common rules (adding years, "
            "`!`, or Leet-speak substitutions like `0->o`, `1->i`, `@->a`) in milliseconds. Additionally, Python's "
            "standard `random` module is designed for simulations, not security—its outputs are mathematically predictable."
        ),
        social_engineering_angle=(
            "Attackers guess passwords using words from your project name, username, or company name (e.g., `ActiveSec_Admin2026!`)."
        ),
        level2_engineering_deep_dive=(
            "**Level 2 — Secure Engineering Pattern:**\n"
            "- Always generate secrets and tokens using Python's `secrets` module (`secrets.token_urlsafe(32)`), which reads from the OS cryptographic random source (`os.urandom`).\n"
            "- Never hardcode API keys in source files; load them from environment variables or a secret vault."
        ),
        level3_adversarial_mastery=(
            "**Level 3 — Adversarial & Cryptographic Mastery:**\n"
            "- Defend against dictionary mangling by reversing cracker rules (de-leeting, stripping affixes, splitting CamelCase) "
            "and blocking any stem that matches dictionary or project-context wordlists, while enforcing >= 52 bits of Shannon entropy."
        ),
        user_checklist=(
            "Use `secrets` instead of `random` for every password, token, or key.",
            "Never use dictionary words or project names in passwords, even with `@`, `0`, or `2026!`.",
        ),
    ),
    "unsafe_deserialization_and_code_execution": TopicPedagogyTemplate(
        topic_slug="unsafe_deserialization_and_code_execution",
        title="Unsafe Deserialization (`pickle`, `marshal`, `yaml.load`)",
        vector_ids=("B.3", "A.1"),
        everyday_analogy=(
            "Loading an untrusted `pickle` file is like hiring a furniture assembler who is allowed to bring "
            "and run any power tool in your house without supervision."
        ),
        plain_explanation=(
            "Python's `pickle` format does not just store data; it stores instructions on how to reconstruct "
            "arbitrary Python objects. A malicious pickle file executes arbitrary code the instant `pickle.loads()` is called."
        ),
        social_engineering_angle=(
            "Attackers distribute poisoned ML model checkpoints or cached `.pkl` data files that execute a reverse shell upon loading."
        ),
        level2_engineering_deep_dive=(
            "**Level 2 — Secure Engineering Pattern:**\n"
            "- Use pure data formats (`json`, `safetensors`, or `yaml.safe_load`) and validate fields against a strict dataclass or schema."
        ),
        level3_adversarial_mastery=(
            "**Level 3 — Adversarial & Cryptographic Mastery:**\n"
            "- In `pickle`, the `__reduce__` magic method allows specifying any callable (such as `os.system`) and arguments directly in the byte stream."
        ),
        user_checklist=(
            "Never load untrusted files with `pickle` or `marshal`; use `json` or `safetensors`.",
        ),
    ),
    "trojan_source_and_obfuscation": TopicPedagogyTemplate(
        topic_slug="trojan_source_and_obfuscation",
        title="Trojan Source Invisible Unicode & Command Obfuscation",
        vector_ids=("B.4", "F.1"),
        everyday_analogy=(
            "Invisible Unicode control characters act like magic ink that flips the order of words on a page "
            "so a human reader sees a harmless comment while the computer executes a hidden backdoor."
        ),
        plain_explanation=(
            "Bidirectional Unicode override characters (CVE-2021-42574) and Base64/Hex command pipelines hide "
            "what code or shell commands actually do during human review."
        ),
        social_engineering_angle=(
            "This vector directly targets human reviewers during code review or `sudo` approval dialogs."
        ),
        level2_engineering_deep_dive=(
            "**Level 2 — Secure Engineering Pattern:**\n"
            "- Strip or reject Unicode bidirectional control characters (`U+202A`–`U+202E`, `U+2066`–`U+2069`) and zero-width characters in pre-commit gates."
        ),
        level3_adversarial_mastery=(
            "**Level 3 — Adversarial & Cryptographic Mastery:**\n"
            "- Combine AST inspection with deterministic de-obfuscation (`CommandDeobfuscator`) so every approval shows the canonical, decoded payload."
        ),
        user_checklist=(
            "Never approve commands containing Base64/Hex decoding pipes or invisible characters.",
        ),
    ),
    "secure_coding_fundamentals": TopicPedagogyTemplate(
        topic_slug="secure_coding_fundamentals",
        title="Secure Coding Fundamentals & Dual-Model Verification",
        vector_ids=("A.1", "F.1"),
        everyday_analogy=(
            "Just like an airplane requires both automated pre-flight instrument checks and a co-pilot "
            "cross-check before takeoff, generated code requires both deterministic tests and an independent reviewer model."
        ),
        plain_explanation=(
            "Small coding models optimize for plausible-looking code, not security. By combining deterministic "
            "Ring-0 tests with an independent second reviewer model, vulnerabilities are caught and repaired before the program ever runs."
        ),
        social_engineering_angle=(
            "Understanding why a piece of code was blocked makes you immune to urgent prompts asking you to bypass security checks."
        ),
        level2_engineering_deep_dive=(
            "**Level 2 — Secure Engineering Pattern:**\n"
            "- Enforce Separation of Duties (SoD): the agent that writes code has no shell execution rights, and the sandbox test-runner has no network access."
        ),
        level3_adversarial_mastery=(
            "**Level 3 — Adversarial & Cryptographic Mastery:**\n"
            "- Defense-in-depth combines capability tokens, deterministic AST/sandbox verification, and context-isolated security review."
        ),
        user_checklist=(
            "Review the plain-language explanation whenever the harness blocks or repairs unsafe code.",
        ),
    ),
}


@dataclass(frozen=True, slots=True)
class UserLearningCase:
    """Immutable record of a security case explained and resolved for the user."""

    case_id: int
    timestamp_iso: str
    topic_slug: str
    task_description: str
    vulnerability_titles: Tuple[str, ...]
    plain_explanation: str
    how_it_was_fixed: str
    coder_model_used: str
    reviewer_model_used: str
    recommended_model: Optional[str]
    unsafe_code_snippet: str
    repaired_code_snippet: str
    verified_safe: bool


class UserWikiManager(SecureComponent):
    """Ring-1 manager for the didactic User Security Academy Wiki (`wiki_user/`)."""

    def __init__(
        self,
        *,
        repo_root: Optional[Path | str] = None,
        user_wiki_dir: Optional[Path | str] = None,
        credential_guard: Optional[CredentialGuard] = None,
    ) -> None:
        resolved_root = (
            Path(os.path.realpath(repo_root))
            if repo_root is not None
            else Path(__file__).resolve().parents[3]
        )
        self._repo_root: Path = resolved_root

        if user_wiki_dir is not None:
            resolved_wiki = Path(os.path.realpath(user_wiki_dir))
            if not (
                resolved_wiki == self._repo_root
                or str(resolved_wiki).startswith(str(self._repo_root) + os.sep)
            ):
                raise WikiSecurityError(
                    f"User wiki directory '{user_wiki_dir}' escapes repository root '{self._repo_root}'.",
                    vector_id="A.3",
                    component_id="user_wiki_manager",
                )
            self._user_wiki_dir: Path = resolved_wiki
        else:
            self._user_wiki_dir = self._repo_root / "wiki_user"

        self._credential_guard: CredentialGuard = credential_guard or CredentialGuard()
        self._cases: List[UserLearningCase] = []

    @classmethod
    def security_assessment(cls) -> ComponentSecurityAssessment:
        return ComponentSecurityAssessment(
            component_id="user_wiki_manager",
            title="Ring-1 Didactic User Security Academy Wiki Manager (`wiki_user/`)",
            ring_level=1,
            source_path="src/activesec/core/user_wiki_manager.py",
            security_test_path="tests/security/test_sec_user_wiki_manager.py",
            threat_vectors=("F.1", "D.2", "B.4", "A.3"),
            summary=(
                "Maintains a human-friendly, progressive cybersecurity learning wiki in `wiki_user/` "
                "that explains discovered code vulnerabilities, social-engineering patterns, and "
                "verified fixes in clear language. Starts at beginner-friendly Level 1 and unlocks "
                "Level 2 (Secure Engineering) and Level 3 (Adversarial Mastery) as the user resolves cases."
            ),
            enforced_invariants=(
                "Confines all writes strictly inside canonical `wiki_user/` under the repository root and rejects symlinks.",
                "Scrubs all code snippets and explanations through CredentialGuard.redact_secrets() and blocks Trojan Source Unicode characters.",
                "Adapts explanation depth automatically across Level 1 (1-2 cases), Level 2 (3-4 cases), and Level 3 (5+ cases).",
            ),
            residual_risks=(
                "Educational examples must never be executed directly outside the sandbox (mitigated by storing them only as static markdown documentation).",
            ),
        )

    @property
    def user_wiki_dir(self) -> Path:
        return self._user_wiki_dir

    @property
    def cases(self) -> Tuple[UserLearningCase, ...]:
        return tuple(self._cases)

    @property
    def current_mastery_level(self) -> int:
        """Compute progressive curriculum complexity level (1 = Beginner, 2 = Intermediate, 3 = Expert)."""
        count = len(self._cases)
        if count >= 5:
            return 3
        if count >= 3:
            return 2
        return 1

    @property
    def mastery_level_label(self) -> str:
        level = self.current_mastery_level
        if level == 1:
            return "Level 1: Security Foundations (Plain-Language & Everyday Analogies)"
        if level == 2:
            return "Level 2: Secure Architecture Practitioner (AST Invariants & Defensive Patterns)"
        return "Level 3: Adversarial Security Expert (Deep Exploit Mechanics & Cryptographic Guarantees)"

    def _sanitize_wiki_text(self, text: str) -> str:
        clean_chars: List[str] = []
        for ch in text:
            if ord(ch) not in TROJAN_SOURCE_UNICODE_CHARS:
                clean_chars.append(ch)
        scrubbed = "".join(clean_chars)
        return self._credential_guard.redact_secrets(scrubbed)

    def _safe_write_file(self, target_path: Path, content: str) -> None:
        if os.path.islink(target_path) or os.path.islink(target_path.parent):
            raise WikiSecurityError(
                f"Refusing to write user wiki file to symbolic link '{target_path}'.",
                vector_id="A.3",
                component_id="user_wiki_manager",
            )
        real_parent = os.path.realpath(target_path.parent)
        real_wiki = os.path.realpath(self._user_wiki_dir)
        if not (real_parent == real_wiki or real_parent.startswith(real_wiki + os.sep)):
            raise WikiSecurityError(
                f"User wiki target '{target_path}' escapes canonical directory '{real_wiki}'.",
                vector_id="A.3",
                component_id="user_wiki_manager",
            )
        sanitized = self._sanitize_wiki_text(content)
        target_path.write_text(sanitized, encoding="utf-8")

    def record_learning_case(
        self,
        *,
        topic_slug: str,
        task_description: str,
        vulnerability_titles: Sequence[str],
        plain_explanation: str,
        how_it_was_fixed: str,
        coder_model_used: str,
        reviewer_model_used: str,
        recommended_model: Optional[str] = None,
        unsafe_code_snippet: str = "",
        repaired_code_snippet: str = "",
        verified_safe: bool = True,
    ) -> UserLearningCase:
        """Record a security review/repair event and update all `wiki_user/` pages."""
        slug = topic_slug if topic_slug in DEFAULT_CURRICULUM else "secure_coding_fundamentals"
        case = UserLearningCase(
            case_id=len(self._cases) + 1,
            timestamp_iso=datetime.date.today().isoformat(),
            topic_slug=slug,
            task_description=self._sanitize_wiki_text(task_description.strip()),
            vulnerability_titles=tuple(self._sanitize_wiki_text(t) for t in vulnerability_titles),
            plain_explanation=self._sanitize_wiki_text(plain_explanation.strip()),
            how_it_was_fixed=self._sanitize_wiki_text(how_it_was_fixed.strip()),
            coder_model_used=self._sanitize_wiki_text(coder_model_used.strip()),
            reviewer_model_used=self._sanitize_wiki_text(reviewer_model_used.strip()),
            recommended_model=self._sanitize_wiki_text(recommended_model.strip()) if recommended_model else None,
            unsafe_code_snippet=self._sanitize_wiki_text(unsafe_code_snippet.strip()),
            repaired_code_snippet=self._sanitize_wiki_text(repaired_code_snippet.strip()),
            verified_safe=verified_safe,
        )
        self._cases.append(case)
        self.sync_user_wiki()
        return case

    def render_lesson_page(self, topic_slug: str) -> str:
        """Render a progressive lesson page tailored to the user's current mastery level."""
        template = DEFAULT_CURRICULUM.get(topic_slug, DEFAULT_CURRICULUM["secure_coding_fundamentals"])
        level = self.current_mastery_level
        topic_cases = [c for c in self._cases if c.topic_slug == topic_slug]
        vectors_md = ", ".join(f"`{v}`" for v in template.vector_ids)
        checklist_md = "\n".join(f"- [x] {item}" for item in template.user_checklist)

        progressive_sections: List[str] = []
        if level >= 2:
            progressive_sections.append(f"---\n\n## 4. {template.level2_engineering_deep_dive}")
        else:
            progressive_sections.append(
                "---\n\n> *Tip: Complete 3 security cases in ActiveSecHarness to unlock **Level 2: Secure Engineering Patterns** on this page!*"
            )

        if level >= 3:
            progressive_sections.append(f"---\n\n## 5. {template.level3_adversarial_mastery}")
        elif level == 2:
            progressive_sections.append(
                "---\n\n> *Tip: Complete 5 security cases to unlock **Level 3: Adversarial & Cryptographic Mastery**!*"
            )

        case_blocks: List[str] = []
        for c in topic_cases:
            status_str = "Repaired & Verified Safe in Sandbox" if c.verified_safe else "Blocked from Execution (Needs Fix)"
            rec_line = (
                f"\n- **Recommended Stronger Model for Fix:** `{c.recommended_model}`"
                if c.recommended_model
                else ""
            )
            unsafe_block = (
                f"\n### Unsafe Draft (Blocked from Execution)\n```python\n{c.unsafe_code_snippet}\n```\n"
                if c.unsafe_code_snippet
                else ""
            )
            safe_block = (
                f"\n### Verified Safe Solution\n```python\n{c.repaired_code_snippet}\n```\n"
                if c.repaired_code_snippet
                else ""
            )
            vulns = ", ".join(c.vulnerability_titles) if c.vulnerability_titles else "None (Clean on first pass)"
            case_blocks.append(
                f"### Case #{c.case_id} ({c.timestamp_iso}) — {status_str}\n"
                f"- **Your Task:** {c.task_description}\n"
                f"- **Detected Risks:** {vulns}\n"
                f"- **Coder Model:** `{c.coder_model_used}` | **Reviewer Model:** `{c.reviewer_model_used}`{rec_line}\n"
                f"- **Plain-Language Explanation:** {c.plain_explanation}\n"
                f"- **How to Fix It:** {c.how_it_was_fixed}\n"
                f"{unsafe_block}{safe_block}"
            )

        cases_md = "\n\n".join(case_blocks) if case_blocks else "_No live cases recorded for this topic yet._"
        extra_md = "\n\n".join(progressive_sections)

        return f"""# Security Academy Lesson: {template.title}

- **Topic ID:** `{template.topic_slug}`
- **Related Threat Taxonomy Vectors:** {vectors_md}
- **Your Current Academy Level:** **{self.mastery_level_label}**

---

## 1. Everyday Analogy (Why Does This Matter?)

{template.everyday_analogy}

---

## 2. What Is the Security Problem in Plain Language?

{template.plain_explanation}

### How Attackers & Social Engineers Use This Against You
{template.social_engineering_angle}

---

## 3. Your Personal Practice Checklist

{checklist_md}

{extra_md}

---

## Hands-On Cases from Your Workspace

{cases_md}
"""

    def render_index_page(self) -> str:
        """Render `wiki_user/INDEX.md` entry point."""
        level = self.current_mastery_level
        seen_slugs = list(dict.fromkeys(c.topic_slug for c in self._cases))
        if not seen_slugs:
            seen_slugs = ["zip_slip_and_zip_bombs"]

        lesson_rows: List[str] = []
        for slug in seen_slugs:
            tmpl = DEFAULT_CURRICULUM.get(slug, DEFAULT_CURRICULUM["secure_coding_fundamentals"])
            count = sum(1 for c in self._cases if c.topic_slug == slug)
            lesson_rows.append(
                f"| **[`{tmpl.title}`](lessons/{slug}.md)** | `{', '.join(tmpl.vector_ids)}` | {count} case(s) |"
            )

        lessons_table = "\n".join(lesson_rows)
        return f"""# ActiveSecHarness – User Security Academy Wiki (`wiki_user/INDEX.md`)

Welcome to your personal **Cybersecurity Learning Wiki**!

Whenever ActiveSecHarness checks, blocks, or repairs code written during your tasks, it translates the technical findings into clear, practical lessons here. The goal is simple: **every time you use the harness, you become stronger at spotting security flaws and social-engineering traps yourself.**

---

## Your Current Security Mastery Level

- **Current Rank:** **{self.mastery_level_label}**
- **Total Security Cases Analyzed:** **{len(self._cases)}**
- **Progression Path:**
  - **Level 1 (1–2 cases):** Plain-language explanations, everyday analogies, and core safety habits. {"**(ACTIVE)**" if level == 1 else "(Completed)"}
  - **Level 2 (3–4 cases):** Unlocks **Secure Engineering Patterns** (canonical paths, streaming quotas, AST invariants, Separation of Duties). {"**(ACTIVE)**" if level == 2 else ("(Completed)" if level > 2 else "(Locked)")}
  - **Level 3 (5+ cases):** Unlocks **Adversarial & Cryptographic Mastery** (exploit internals, TOCTOU, non-recursive bombs, cryptographic guarantees). {"**(ACTIVE)**" if level == 3 else "(Locked)"}

---

## Your Active Security Lessons

| Lesson & Topic | Threat Vectors | Workspace Cases |
| :--- | :--- | :--- |
{lessons_table}

---

## Quick Navigation

- **[`wiki_user/LEARNING_PROGRESS.md`](LEARNING_PROGRESS.md)** — Chronological log of all vulnerabilities caught, explained, and repaired in your sessions.
- **In Interactive Chat (`--chat`):** Type `/learn` at any time to view your latest security lesson directly in the terminal.
"""

    def render_learning_progress_page(self) -> str:
        """Render `wiki_user/LEARNING_PROGRESS.md` chronological case log."""
        if not self._cases:
            body = "_No security cases recorded yet. Run a task in `--chat` to generate your first lesson!_"
        else:
            rows: List[str] = []
            for c in reversed(self._cases):
                status = "Repaired & Verified" if c.verified_safe else "Blocked (Unsafe)"
                vulns = "; ".join(c.vulnerability_titles) if c.vulnerability_titles else "Verified Clean"
                rows.append(
                    f"### Case #{c.case_id} ({c.timestamp_iso}) — [{c.topic_slug}](lessons/{c.topic_slug}.md)\n"
                    f"- **Status:** **{status}**\n"
                    f"- **Task:** {c.task_description}\n"
                    f"- **Findings:** {vulns}\n"
                    f"- **Plain Explanation:** {c.plain_explanation}\n"
                    f"- **Solution Applied:** {c.how_it_was_fixed}\n"
                )
            body = "\n---\n\n".join(rows)

        return f"""# User Security Academy – Learning Progress (`wiki_user/LEARNING_PROGRESS.md`)

- **Current Mastery Level:** **{self.mastery_level_label}**
- **Cases Completed:** {len(self._cases)}

---

{body}
"""

    def sync_user_wiki(self) -> None:
        """Write/update `wiki_user/INDEX.md`, `wiki_user/LEARNING_PROGRESS.md`, and lesson pages."""
        lessons_dir = self._user_wiki_dir / "lessons"
        lessons_dir.mkdir(parents=True, exist_ok=True)

        active_slugs = set(c.topic_slug for c in self._cases) | {"zip_slip_and_zip_bombs"}
        for slug in sorted(active_slugs):
            lesson_path = lessons_dir / f"{slug}.md"
            self._safe_write_file(lesson_path, self.render_lesson_page(slug))

        self._safe_write_file(self._user_wiki_dir / "INDEX.md", self.render_index_page())
        self._safe_write_file(
            self._user_wiki_dir / "LEARNING_PROGRESS.md",
            self.render_learning_progress_page(),
        )

    def format_terminal_summary(self) -> str:
        """Return a concise terminal-friendly summary for the `/learn` REPL command."""
        lines = [
            "=== User Security Academy Wiki (`wiki_user/`) ===",
            f"Mastery Rank: {self.mastery_level_label}",
            f"Cases Completed: {len(self._cases)}",
            f"Index File: {self._user_wiki_dir / 'INDEX.md'}",
        ]
        if self._cases:
            latest = self._cases[-1]
            lines.extend(
                [
                    f"Latest Case (#{latest.case_id} - {latest.topic_slug}):",
                    f"  Status: {'VERIFIED SAFE' if latest.verified_safe else 'BLOCKED (UNSAFE)'}",
                    f"  What was unsafe: {latest.plain_explanation}",
                    f"  How to fix it:   {latest.how_it_was_fixed}",
                    f"  Lesson Page:     {self._user_wiki_dir / 'lessons' / (latest.topic_slug + '.md')}",
                ]
            )
            if latest.recommended_model:
                lines.append(f"  Recommended Stronger Model: {latest.recommended_model}")
        else:
            lines.append("Tip: Run a coding task in `--chat` to record your first hands-on security lesson.")
        return "\n".join(lines)
