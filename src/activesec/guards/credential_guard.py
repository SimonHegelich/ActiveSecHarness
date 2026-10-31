"""Ring-0 CredentialGuard: Password entropy, de-mangling dictionary defense, CSPRNG, and Secret DLP.

Defends against weak passwords, Leet-speak/affix dictionary attacks, project-context password reuse,
LLM-invented weak randomness, and cleartext secret leakage into LLM prompts or files.
"""

from __future__ import annotations

import hashlib
import math
import re
import secrets
import string
from dataclasses import dataclass
from typing import FrozenSet, Iterable, Tuple

from activesec.core.component import ComponentSecurityAssessment, SecureComponent
from activesec.core.exceptions import CredentialSecurityError


DEFAULT_COMPROMISED_DICTIONARY: FrozenSet[str] = frozenset(
    {
        "password",
        "passwort",
        "admin",
        "administrator",
        "root",
        "welcome",
        "qwerty",
        "qwertz",
        "asdfgh",
        "letmein",
        "monkey",
        "dragon",
        "baseball",
        "football",
        "master",
        "sunshine",
        "iloveyou",
        "princess",
        "shadow",
        "superman",
        "michael",
        "secret",
        "geheim",
        "security",
        "sicherheit",
        "harness",
        "activesec",
        "activesecharness",
        "cybersecurity",
        "pentest",
        "developer",
        "postgres",
        "database",
        "changeme",
        "default",
        "summer",
        "winter",
        "spring",
        "autumn",
    }
)

KEYBOARD_WALKS: Tuple[str, ...] = (
    "qwertyuiop",
    "qwertzuiop",
    "asdfghjkl",
    "zxcvbnm",
    "yxcvbnm",
    "1234567890",
    "0987654321",
    "abcdefghijklmnopqrstuvwxyz",
)

LEET_TRANSLATION_TABLE = str.maketrans(
    {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "8": "b",
        "9": "g",
        "@": "a",
        "$": "s",
        "!": "i",
    }
)


@dataclass(frozen=True, slots=True)
class PasswordPolicy:
    """Immutable password strength and dictionary-defense policy."""

    min_length: int = 14
    min_shannon_bits: float = 56.0
    min_bits_per_char: float = 4.0
    min_character_classes: int = 3
    min_stem_length_for_dict_match: int = 4


class CredentialGuard(SecureComponent):
    """Ring-0 guard for password validation, dictionary attack defense, CSPRNG, and Secret DLP."""

    _SECRET_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
        ("PEM_PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |)?PRIVATE KEY-----")),
        ("OPENAI_KEY", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
        ("GITHUB_TOKEN", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")),
        ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
        ("GENERIC_ASSIGNMENT", re.compile(r"(?i)\b(?:api_key|secret_key|password|passwd|access_token|auth_token)\s*[:=]\s*['\"]([^'\"]{8,})['\"]")),
    )

    def __init__(
        self,
        *,
        policy: PasswordPolicy | None = None,
        extra_dictionary_words: Iterable[str] = (),
        project_context_words: Iterable[str] = ("activesec", "harness", "simon"),
    ) -> None:
        self._policy: PasswordPolicy = policy if policy is not None else PasswordPolicy()
        normalized_extra = {w.strip().lower() for w in extra_dictionary_words if len(w.strip()) >= 3}
        normalized_ctx = {w.strip().lower() for w in project_context_words if len(w.strip()) >= 3}
        self._dictionary: FrozenSet[str] = DEFAULT_COMPROMISED_DICTIONARY | normalized_extra | normalized_ctx

    @classmethod
    def security_assessment(cls) -> ComponentSecurityAssessment:
        return ComponentSecurityAssessment(
            component_id="credential_guard",
            title="Ring-0 Password Entropy, Dictionary Defense & Secret DLP Guard",
            ring_level=0,
            source_path="src/activesec/guards/credential_guard.py",
            security_test_path="tests/security/test_sec_credential_guard.py",
            threat_vectors=("D.1", "D.2", "D.3"),
            summary=(
                "Enforces high-entropy password validation, reverse cracker de-mangling (Leet-speak, "
                "affix stripping, CamelCase splitting) against dictionary and project-context wordlists, "
                "CSPRNG secret generation, and bidirectional cleartext secret redaction."
            ),
            enforced_invariants=(
                "Rejects any password shorter than min_length (14), below min_shannon_bits (52.0), or with fewer than 3 character classes.",
                "Reverses Leet-speak substitutions (0->o, 1->i/l, 3->e, 4->a, @->a, $->s) and strips digit/symbol affixes before matching against compromised dictionaries and project context words.",
                "Rejects keyboard walks (qwerty/qwertz/123456) and repeated character sequences.",
                "Redacts PEM private keys, API tokens (OpenAI, GitHub, AWS, Slack), and secret assignments into deterministic <REDACTED:TYPE:HASH8> placeholders.",
            ),
            residual_risks=(
                "Custom offline wordlists beyond the built-in + configured bloom/set dictionary require mounting external wordlist files in production.",
            ),
        )

    @staticmethod
    def calculate_shannon_bits_per_char(value: str) -> float:
        """Compute Shannon entropy in bits per character for a string."""
        if not value:
            return 0.0
        length = len(value)
        frequencies: dict[str, int] = {}
        for char in value:
            frequencies[char] = frequencies.get(char, 0) + 1
        return -sum(
            (count / length) * math.log2(count / length) for count in frequencies.values()
        )

    @classmethod
    def calculate_shannon_entropy_bits(cls, value: str) -> float:
        """Compute total Shannon entropy in bits for a string."""
        if not value:
            return 0.0
        return cls.calculate_shannon_bits_per_char(value) * len(value)

    @classmethod
    def demangle_candidates(cls, candidate: str) -> set[str]:
        """Generate normalized root stems by reversing common password cracker rules."""
        lowered = candidate.lower()
        de_leeted_i = lowered.translate(LEET_TRANSLATION_TABLE)
        de_leeted_l = lowered.replace("1", "l").translate(LEET_TRANSLATION_TABLE)

        # Split CamelCase and non-alphanumeric separators
        camel_tokens = re.findall(r"[A-Z]?[a-z]+|[0-9]+", candidate)
        raw_variants = {lowered, de_leeted_i, de_leeted_l}
        for tok in camel_tokens:
            raw_variants.add(tok.lower())
            raw_variants.add(tok.lower().translate(LEET_TRANSLATION_TABLE))

        stems: set[str] = set()
        for variant in raw_variants:
            cleaned = re.sub(r"^[^a-z]+|[^a-z]+$", "", variant)
            alpha_only = re.sub(r"[^a-z]", "", variant)
            for item in (variant, cleaned, alpha_only):
                if item:
                    stems.add(item)
            for sub in re.split(r"[^a-z]+", variant):
                if sub:
                    stems.add(sub)
        return stems

    def validate_password_strength(self, password: str) -> None:
        """Deterministically validate a password against length, entropy, pattern, and dictionary attacks."""
        if len(password) < self._policy.min_length:
            raise CredentialSecurityError(
                f"Password length ({len(password)}) is below minimum required ({self._policy.min_length}).",
                vector_id="D.1",
                component_id="credential_guard",
            )

        classes = sum(
            (
                any(c.islower() for c in password),
                any(c.isupper() for c in password),
                any(c.isdigit() for c in password),
                any(c in string.punctuation for c in password),
            )
        )
        if classes < self._policy.min_character_classes:
            raise CredentialSecurityError(
                f"Password uses only {classes} character classes (minimum {self._policy.min_character_classes} required).",
                vector_id="D.1",
                component_id="credential_guard",
            )

        # Check repeated characters (e.g. 'aaaa' or '1111')
        if re.search(r"(.)\1{3,}", password):
            raise CredentialSecurityError(
                "Password contains excessive repeated character runs.",
                vector_id="D.1",
                component_id="credential_guard",
            )

        # Check keyboard walks and sequences
        lower_pw = password.lower()
        for walk in KEYBOARD_WALKS:
            for idx in range(len(walk) - 4):
                segment = walk[idx : idx + 5]
                if segment in lower_pw or segment[::-1] in lower_pw:
                    raise CredentialSecurityError(
                        f"Password contains predictable keyboard walk or sequence ('{segment}').",
                        vector_id="D.1",
                        component_id="credential_guard",
                    )

        # Check de-mangled stems against dictionary and project context words
        stems = self.demangle_candidates(password)
        for stem in stems:
            if len(stem) >= self._policy.min_stem_length_for_dict_match and stem in self._dictionary:
                raise CredentialSecurityError(
                    f"Password vulnerable to dictionary or Leet-speak mutation attack (matched stem '{stem}').",
                    vector_id="D.1",
                    component_id="credential_guard",
                )
            for dict_word in self._dictionary:
                if len(dict_word) >= 5 and dict_word in stem:
                    raise CredentialSecurityError(
                        f"Password embeds dictionary/context word '{dict_word}' after de-mangling.",
                        vector_id="D.1",
                        component_id="credential_guard",
                    )

        bits_per_char = self.calculate_shannon_bits_per_char(password)
        if bits_per_char < self._policy.min_bits_per_char:
            raise CredentialSecurityError(
                f"Password Shannon entropy per character ({bits_per_char:.2f} bits/char) is below minimum threshold ({self._policy.min_bits_per_char:.1f} bits/char).",
                vector_id="D.1",
                component_id="credential_guard",
            )

        entropy_bits = bits_per_char * len(password)
        if entropy_bits < self._policy.min_shannon_bits:
            raise CredentialSecurityError(
                f"Password Shannon entropy ({entropy_bits:.1f} bits) is below minimum threshold ({self._policy.min_shannon_bits} bits).",
                vector_id="D.1",
                component_id="credential_guard",
            )

    @classmethod
    def generate_strong_secret(cls, length: int = 32) -> str:
        """Generate a cryptographically strong secret using OS CSPRNG (never LLM text)."""
        if length < 20:
            raise CredentialSecurityError(
                "Generated secret length must be at least 20 characters.",
                vector_id="D.3",
                component_id="credential_guard",
            )
        alphabet = string.ascii_letters + string.digits + "!@#%^&*-_=+"
        while True:
            candidate = "".join(secrets.choice(alphabet) for _ in range(length))
            if (
                any(c.islower() for c in candidate)
                and any(c.isupper() for c in candidate)
                and any(c.isdigit() for c in candidate)
                and any(c in "!@#%^&*-_=+" for c in candidate)
                and cls.calculate_shannon_bits_per_char(candidate) >= 4.0
            ):
                return candidate

    def redact_secrets(self, text: str) -> str:
        """Redact cleartext secrets from text before it enters LLM context or logs."""
        redacted = text
        for label, pattern in self._SECRET_PATTERNS:
            def _replacer(match: re.Match[str], secret_type: str = label) -> str:
                raw_hit = match.group(0)
                digest = hashlib.sha256(raw_hit.encode("utf-8")).hexdigest()[:8]
                return f"<REDACTED:{secret_type}:{digest}>"

            redacted = pattern.sub(_replacer, redacted)
        return redacted

    def assert_no_cleartext_secrets(self, content: str) -> None:
        """Fail closed if cleartext secrets are present in outgoing code or network payloads."""
        for label, pattern in self._SECRET_PATTERNS:
            if pattern.search(content):
                raise CredentialSecurityError(
                    f"Cleartext secret detected ({label}); write/egress blocked by DLP policy.",
                    vector_id="D.2",
                    component_id="credential_guard",
                )
