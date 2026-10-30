# ActiveSecHarness – Engineering, Security & Wiki Standards (`AGENTS.md`)

All human contributors and AI coding agents operating in this repository MUST strictly adhere to these engineering, security, testing, and documentation routines.

---

## 1. Language Policy: 100% English in Code, Docs, Wiki, and Git

- **All source code** (identifiers, docstrings, comments, type annotations, exception messages), **all documentation** (`README.md`, `docs/`, `wiki/`), **all tests**, and **all Git commit messages** MUST be written in clear, precise **English**.
- Conversational chat with the user may take place in the user's preferred language (e.g., German), but every artifact written to the repository or Git history is strictly English.

---

## 2. Programming Paradigm: Object-Oriented, Pythonic, Safe by Construction

1. **Object-Oriented Architecture (OOP):**
   - Every security guard, kernel verifier, token engine, and harness subsystem must inherit from `SecureComponent` (`src/activesec/core/component.py`) and declare its explicit `ComponentSecurityAssessment` metadata.
   - Prefer composition and explicit interfaces (`abc.ABC`, `typing.Protocol`) over deep inheritance trees or procedural scripts.
2. **Pythonic & Strictly Typed:**
   - Python 3.11+ with 100% type annotations on all functions, methods, and attributes (`from __future__ import annotations`).
   - State and policy configurations must use immutable dataclasses (`@dataclass(frozen=True, slots=True)`).
   - Use context managers (`__enter__` / `__exit__`) for any resource lifecycle (quarantine directories, sandbox processes, temporary files).
3. **Safe by Construction (Zero Unsafe Primitives):**
   - **FORBIDDEN in production code:** `eval()`, `exec()`, `pickle.loads()`, `yaml.load()` (without `SafeLoader`), `subprocess.run(..., shell=True)`, `os.system()`, `zipfile.ZipFile.extractall()`, `tarfile.TarFile.extractall()`, or `random` for security/tokens (use `secrets` / `os.urandom`).
   - Always resolve paths canonically via `os.path.realpath()` before checking prefix containment.
   - Fail closed: every security check must raise a specific subclass of `ActiveSecError` (`src/activesec/core/exceptions.py`) on violation; silent `except Exception: pass` is strictly prohibited.

---

## 3. Mandatory Component Security Testing (`tests/security/`)

Every component in `src/activesec/` MUST have a dedicated adversarial security test module in `tests/security/test_sec_<component_name>.py`:

- **Adversarial Focus:** Security tests do not merely test happy-path functionality; they actively simulate attack vectors defined in [`docs/01_threat_taxonomy.md`](docs/01_threat_taxonomy.md) (e.g., crafted ZipBombs with spoofed headers, Zip-Slip `../../` traversal, forged HMAC capability tokens, privilege escalation via attenuation bypass, Leet-speak/context-word dictionary attacks, SSRF against `169.254.169.254` and `127.0.0.1`).
- **Vector Traceability:** Each security test docstring or marker must reference the threat vector ID it verifies (e.g., `[Vector B.1: Decompression Bomb]`, `[Vector D.1: Dictionary Attack]`).

---

## 4. Karpathy LLM Security Wiki (`wiki/`) & Automated Synchronization

Following Andrej Karpathy's **LLM Wiki** paradigm, `wiki/` is a persistent, compounding, self-updating knowledge base—not a static manual that bit-rots:

- **`wiki/INDEX.md`**: Entry point mapping the entire architecture, threat domains, and component pages.
- **`wiki/SECURITY_LEDGER.md`**: Automatically compiled live table of every `SecureComponent`, its ring level, threat vectors mitigated, residual risk assessment, and real-time security test pass/fail status.
- **`wiki/components/<component_id>.md`**: Detailed per-component security assessment page, combining architectural design notes with automatically injected test verification tables and AST-extracted invariants.
- **`wiki/vectors/`**: Cross-cutting threat domain synthesis pages.
- **`wiki/log.md`**: Chronological append-only log of security verifications and architecture updates.
- **Automation Rule:** Whenever a component or security test is added or modified, you MUST run:
  ```bash
  python3 tools/wiki_sync.py
  ```
  before committing so the Wiki reflects the exact live test and code state.

---

## 5. Git Workflow: Atomic Commits with Detailed English Messages

- **Atomic Commits:** Each commit must encapsulate exactly one cohesive logical unit (e.g., one component + its dedicated security test + its updated wiki assessment). Never bundle unrelated changes into a monolithic commit.
- **Structured English Commit Messages:**
  ```text
  <type>(<scope>): <concise summary in imperative mood>

  Why:
  - Explain the architectural or security motivation.

  What:
  - Detail the classes, invariants, and methods introduced or modified.

  Security & Verification:
  - Threat Vectors Addressed: [e.g., B.1 ZipBomb, B.2 Zip-Slip]
  - Security Tests Verified: [e.g., tests/security/test_sec_archive_guard.py]
  - Wiki Sync Status: Updated wiki/SECURITY_LEDGER.md and component page.
  ```
  Allowed `<type>` values: `feat`, `sec`, `fix`, `refactor`, `docs`, `test`, `chore`.
