# Threat Vector Synthesis – Domain D: Passwords, Dictionary Attacks & Secret DLP

- **Taxonomy Reference:** [`docs/01_threat_taxonomy.md#domain-d`](../../docs/01_threat_taxonomy.md)
- **Primary Mitigating Components:**
  - [`credential_guard`](../components/credential_guard.md) (Entropy analysis, Leet-speak de-mangling, dictionary & project-context word blocking, CSPRNG secret generation, and bidirectional secret redaction)

## Core Threat Model
Passwords that appear complex to naive regex rules (e.g., `P@ssw0rd2026!` or `ActiveSec_Admin1!`) fall immediately to rule-based dictionary attacks. Additionally, cleartext API keys in files or stdout can leak into LLM prompts or Git history.

## Enforced Invariants
1. Passwords undergo reverse cracker normalization (stripping affixes, reversing Leet-speak, splitting tokens) and are checked against built-in and custom dictionaries plus project-context identifiers.
2. Minimum effective structural entropy and character diversity are deterministically enforced.
3. Secrets are generated exclusively via `secrets` CSPRNG and redacted from text streams via regex + Shannon entropy before reaching any LLM.
