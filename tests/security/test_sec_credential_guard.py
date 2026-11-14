"""Adversarial security tests for CredentialGuard (src/activesec/guards/credential_guard.py).

Verifies defense against dictionary attacks, Leet-speak mutations, project-context passwords,
keyboard walks, and cleartext secret leakage (DLP).
"""

from __future__ import annotations

import pytest

from activesec.core.exceptions import CredentialSecurityError
from activesec.guards.credential_guard import CredentialGuard


@pytest.mark.security
@pytest.mark.parametrize(
    "weak_candidate",
    [
        "P@ssw0rd2026!Xy",        # Leet-speak + year suffix on dictionary word 'password'
        "Act1veSec_H@rness99!",   # Project context words with Leet-speak
        "S1m0n_Admin_2026!",      # Operator/project context word + 'admin'
        "Qwerty12345!@#Ab",       # Keyboard walk + numerical sequence
        "Summer2026!!Secure",     # Season + year + common dictionary word
        "AAAAbbbb1111!!!!",       # Repeated character runs
        "Short1!Aa",              # Below minimum length
    ],
)
def test_sec_dictionary_and_mangled_passwords_rejected(weak_candidate: str) -> None:
    """[Vector D.1: Dictionary & Mutation Attack] Rejects mangled, Leet-speak, and context passwords."""
    guard = CredentialGuard()
    with pytest.raises(CredentialSecurityError) as exc_info:
        guard.validate_password_strength(weak_candidate)
    assert exc_info.value.vector_id == "D.1"


@pytest.mark.security
def test_sec_csprng_generated_secret_passes_validation() -> None:
    """[Vector D.3: Cryptographic Strength] Secrets generated via CSPRNG pass all entropy and dictionary checks."""
    guard = CredentialGuard()
    strong_secret = guard.generate_strong_secret(length=28)
    guard.validate_password_strength(strong_secret)


@pytest.mark.security
def test_sec_bidirectional_secret_redaction_and_egress_block() -> None:
    """[Vector D.2: Secret Leakage / DLP] Redacts API keys and PEM blocks and blocks cleartext egress."""
    guard = CredentialGuard()
    leaked_text = (
        "Config loaded:\n"
        "OPENAI_API_KEY=sk-proj-1234567890abcdefghijklmnop\n"
        "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    )

    sanitized = guard.redact_secrets(leaked_text)
    assert "sk-proj-" not in sanitized
    assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
    assert "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU=" not in sanitized
    assert "<REDACTED:OPENAI_KEY:" in sanitized
    assert "<REDACTED:AWS_ACCESS_KEY:" in sanitized
    assert "<REDACTED:PEM_PRIVATE_KEY:" in sanitized

    with pytest.raises(CredentialSecurityError) as exc_info:
        guard.assert_no_cleartext_secrets(leaked_text)
    assert exc_info.value.vector_id == "D.2"


@pytest.mark.security
@pytest.mark.parametrize(
    "secret_assignment",
    [
        "AWS_" + "SECRET_ACCESS_KEY=" + ("b" * 40),
        "aws_" + "secret_access_key: '" + ("Z" * 32) + "'",
        "access_token=" + ("t" * 24),
        "private_key = '" + ("p" * 20) + "'",
    ],
)
def test_sec_cloud_and_unquoted_secret_assignments_blocked(secret_assignment: str) -> None:
    """[Vector D.2: Secret Leakage / DLP] Blocks quoted and unquoted cloud secret key assignments."""
    guard = CredentialGuard()
    with pytest.raises(CredentialSecurityError) as exc_info:
        guard.assert_no_cleartext_secrets(secret_assignment)
    assert exc_info.value.vector_id == "D.2"
    redacted = guard.redact_secrets(secret_assignment)
    assert "<REDACTED:" in redacted


@pytest.mark.security
def test_sec_jwt_tokens_redacted_and_blocked_while_benign_dotted_identifiers_pass() -> None:
    """[Vector D.2: Secret Leakage / DLP] Scrubs and blocks JWT tokens while leaving benign dotted identifiers untouched."""
    guard = CredentialGuard()
    jwt_hdr = "eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    jwt_pay = "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ"
    jwt_sig = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    sample_jwt = f"{jwt_hdr}.{jwt_pay}.{jwt_sig}"

    payload = f"Authorization: Bearer {sample_jwt}\nmodule=activesec.guards.credential_guard"
    redacted = guard.redact_secrets(payload)
    assert sample_jwt not in redacted
    assert "<REDACTED:JWT_TOKEN:" in redacted
    assert "activesec.guards.credential_guard" in redacted

    with pytest.raises(CredentialSecurityError) as exc_info:
        guard.assert_no_cleartext_secrets(payload)
    assert exc_info.value.vector_id == "D.2"

    # Benign dotted identifiers and version numbers must pass without false positives
    benign_text = "import activesec.core.security_kernel\nversion = 'v1.2026.11'\nconfig.app.name = 'demo'"
    guard.assert_no_cleartext_secrets(benign_text)
    assert guard.redact_secrets(benign_text) == benign_text


