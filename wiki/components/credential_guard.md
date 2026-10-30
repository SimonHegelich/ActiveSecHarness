# Component Security Assessment: `credential_guard`

> **Auto-Generated & Verified by `tools/wiki_sync.py`** — Do not edit manual status badges directly; update the `ComponentSecurityAssessment` contract in [`src/activesec/guards/credential_guard.py`](../../src/activesec/guards/credential_guard.py) or the security test suite in [`tests/security/test_sec_credential_guard.py`](../../tests/security/test_sec_credential_guard.py).

---

## 1. Security Posture Metadata

| Attribute | Value |
| :--- | :--- |
| **Component ID** | `credential_guard` |
| **Title** | Ring-0 Password Entropy, Dictionary Defense & Secret DLP Guard |
| **Privilege Ring** | **Ring 0** |
| **Mitigated Threat Vectors** | `D.1`, `D.2`, `D.3` |
| **Source File** | [`src/activesec/guards/credential_guard.py`](../../src/activesec/guards/credential_guard.py) (`sha256:551bc705ce52`) |
| **Dedicated Security Test Suite** | [`tests/security/test_sec_credential_guard.py`](../../tests/security/test_sec_credential_guard.py) |
| **AST Static Safety Audit** | **CLEAN (Zero Forbidden Primitives)** |
| **Adversarial Security Verification** | **VERIFIED (PASS)** (3 test vectors) |

---

## 2. Architectural Summary

Enforces high-entropy password validation, reverse cracker de-mangling (Leet-speak, affix stripping, CamelCase splitting) against dictionary and project-context wordlists, CSPRNG secret generation, and bidirectional cleartext secret redaction.

---

## 3. Enforced Deterministic Security Invariants

- Rejects any password shorter than min_length (14), below min_shannon_bits (52.0), or with fewer than 3 character classes.
- Reverses Leet-speak substitutions (0->o, 1->i/l, 3->e, 4->a, @->a, $->s) and strips digit/symbol affixes before matching against compromised dictionaries and project context words.
- Rejects keyboard walks (qwerty/qwertz/123456) and repeated character sequences.
- Redacts PEM private keys, API tokens (OpenAI, GitHub, AWS, Slack), and secret assignments into deterministic <REDACTED:TYPE:HASH8> placeholders.

---

## 4. Dedicated Component Security Tests (`tests/security/test_sec_credential_guard.py`)

| Test Function | Verified Adversarial Vector & Invariant | Status |
| :--- | :--- | :--- |
| `test_sec_dictionary_and_mangled_passwords_rejected` | [Vector D.1: Dictionary & Mutation Attack] Rejects mangled, Leet-speak, and context passwords. | **PASS** |
| `test_sec_csprng_generated_secret_passes_validation` | [Vector D.3: Cryptographic Strength] Secrets generated via CSPRNG pass all entropy and dictionary checks. | **PASS** |
| `test_sec_bidirectional_secret_redaction_and_egress_block` | [Vector D.2: Secret Leakage / DLP] Redacts API keys and PEM blocks and blocks cleartext egress. | **PASS** |

---

## 5. Known Residual Risks & Defense-in-Depth Pairing

- Custom offline wordlists beyond the built-in + configured bloom/set dictionary require mounting external wordlist files in production.
