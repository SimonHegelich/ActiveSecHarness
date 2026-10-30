"""Ring-1 Social-Engineering De-Obfuscator & Explain-Before-Sudo Command Analyzer.

Protects the human operator from social engineering, obfuscated commands (Base64/Hex),
Trojan Source invisible Unicode control characters, and Living-off-the-Land traps.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Tuple

from activesec.core.component import ComponentSecurityAssessment, SecureComponent
from activesec.core.exceptions import SocialEngineeringAlertError


TROJAN_SOURCE_UNICODE_CHARS: FrozenSet[int] = frozenset(
    {
        0x202A,  # LEFT-TO-RIGHT EMBEDDING
        0x202B,  # RIGHT-TO-LEFT EMBEDDING
        0x202C,  # POP DIRECTIONAL FORMATTING
        0x202D,  # LEFT-TO-RIGHT OVERRIDE
        0x202E,  # RIGHT-TO-LEFT OVERRIDE
        0x2066,  # LEFT-TO-RIGHT ISOLATE
        0x2067,  # RIGHT-TO-LEFT ISOLATE
        0x2068,  # FIRST STRONG ISOLATE
        0x2069,  # POP DIRECTIONAL ISOLATE
        0x200B,  # ZERO WIDTH SPACE
        0x200C,  # ZERO WIDTH NON-JOINER
        0x200D,  # ZERO WIDTH JOINER
        0xFEFF,  # ZERO WIDTH NO-BREAK SPACE
    }
)


@dataclass(frozen=True, slots=True)
class CommandRiskReport:
    """Immutable de-obfuscation and social-engineering risk assessment for a sudo request."""

    raw_command: str
    decoded_payloads: Tuple[str, ...]
    detected_vectors: Tuple[str, ...]
    risk_level: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    human_explanation: str
    requires_typed_confirmation: bool


class CommandDeobfuscator(SecureComponent):
    """Ring-1 analyzer that de-obfuscates commands and flags social-engineering traps before sudo."""

    _BASE64_PIPE_PATTERN = re.compile(
        r"(?:echo|printf)\s+['\"]?([A-Za-z0-9+/=]{8,})['\"]?\s*\|\s*(?:base64\s+(?:-d|--decode)|openssl\s+enc\s+-d\s+-base64)"
    )
    _HEX_PIPE_PATTERN = re.compile(
        r"(?:echo|printf)\s+['\"]?([0-9a-fA-F]{8,})['\"]?\s*\|\s*xxd\s+-r\s+-p"
    )
    _PIPE_TO_SHELL_PATTERN = re.compile(
        r"(?:curl|wget|fetch)\b[^|]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b"
    )
    _INSECURE_TLS_FLAG_PATTERN = re.compile(
        r"\b(?:curl\s+[^;|]*?(?:-k|--insecure)|wget\s+[^;|]*?--no-check-certificate|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0)\b"
    )
    _SENSITIVE_TARGET_PATTERN = re.compile(
        r"(?:~/.ssh|/\.ssh/|/etc/shadow|/etc/sudoers|/var/run/docker\.sock|\.git/hooks)"
    )

    @classmethod
    def security_assessment(cls) -> ComponentSecurityAssessment:
        return ComponentSecurityAssessment(
            component_id="deobfuscator",
            title="Ring-1 Social-Engineering De-Obfuscator & Sudo Risk Explainer",
            ring_level=1,
            source_path="src/activesec/sovereign/deobfuscator.py",
            security_test_path="tests/security/test_sec_deobfuscator.py",
            threat_vectors=("B.4", "F.1", "A.1"),
            summary=(
                "Protects the human operator during sudo ceremonies by detecting Trojan Source "
                "invisible Unicode characters, decoding inline Base64/Hex payloads, and flagging "
                "pipe-to-shell (curl | sh), insecure TLS flags, and sensitive host path access."
            ),
            enforced_invariants=(
                "Immediately blocks commands containing Trojan Source bidirectional or zero-width Unicode control characters (CVE-2021-42574).",
                "Automatically decodes Base64 and Hex encoded command pipelines so the operator sees the real payload before deciding.",
                "Classifies curl/wget-to-shell, obfuscated execution, and ~/.ssh or docker.sock access as CRITICAL risk requiring anti-reflex intervention.",
            ),
            residual_risks=(
                "External scripts whose logic resides on a remote server not yet downloaded (mitigated by MalwareGuard quarantine before execution).",
            ),
        )

    def inspect_command(self, command: str, *, fail_on_critical: bool = False) -> CommandRiskReport:
        """Analyze and de-obfuscate a command prior to presenting a sudo approval dialog."""
        for ch in command:
            codepoint = ord(ch)
            if codepoint in TROJAN_SOURCE_UNICODE_CHARS:
                raise SocialEngineeringAlertError(
                    f"Trojan Source / invisible Unicode control character detected (U+{codepoint:04X}).",
                    vector_id="B.4",
                    component_id="deobfuscator",
                )

        decoded_payloads: list[str] = []
        vectors: list[str] = []
        explanations: list[str] = []
        risk_level = "LOW"

        # 1. Decode Base64 pipelines
        for match in self._BASE64_PIPE_PATTERN.finditer(command):
            b64_blob = match.group(1)
            try:
                decoded = base64.b64decode(b64_blob, validate=True).decode("utf-8", errors="replace")
            except binascii.Error:
                decoded = "<malformed-base64>"
            decoded_payloads.append(decoded)
            vectors.append("F.1:Base64Obfuscation")
            explanations.append(f"Command hides payload via Base64 encoding -> Decoded: `{decoded}`")
            risk_level = "CRITICAL"

        # 2. Decode Hex pipelines
        for match in self._HEX_PIPE_PATTERN.finditer(command):
            hex_blob = match.group(1)
            try:
                decoded = bytes.fromhex(hex_blob).decode("utf-8", errors="replace")
            except ValueError:
                decoded = "<malformed-hex>"
            decoded_payloads.append(decoded)
            vectors.append("F.1:HexObfuscation")
            explanations.append(f"Command hides payload via Hex encoding -> Decoded: `{decoded}`")
            risk_level = "CRITICAL"

        # 3. Check combined text (raw + decoded payloads) for high-risk patterns
        combined_inspection_text = "\n".join([command, *decoded_payloads])

        if self._PIPE_TO_SHELL_PATTERN.search(combined_inspection_text):
            vectors.append("F.1:PipeToShell")
            explanations.append("Downloads remote content and pipes it directly into a shell interpreter (classic Trojan/LotL trap).")
            risk_level = "CRITICAL"

        if self._SENSITIVE_TARGET_PATTERN.search(combined_inspection_text):
            vectors.append("A.4:SensitiveHostTarget")
            explanations.append("Accesses critical host credentials, SSH keys, Docker socket, or Git hooks.")
            risk_level = "CRITICAL"

        if self._INSECURE_TLS_FLAG_PATTERN.search(combined_inspection_text):
            vectors.append("C.1:InsecureTLSFlag")
            explanations.append("Disables TLS certificate validation, enabling Man-in-the-Middle payload tampering.")
            if risk_level != "CRITICAL":
                risk_level = "HIGH"

        if not explanations:
            explanations.append("No obfuscation or high-risk social-engineering patterns detected.")

        report = CommandRiskReport(
            raw_command=command,
            decoded_payloads=tuple(decoded_payloads),
            detected_vectors=tuple(vectors),
            risk_level=risk_level,
            human_explanation=" | ".join(explanations),
            requires_typed_confirmation=risk_level in ("HIGH", "CRITICAL"),
        )

        if fail_on_critical and report.risk_level == "CRITICAL":
            raise SocialEngineeringAlertError(
                f"Critical social-engineering or LotL pattern blocked: {report.human_explanation}",
                vector_id="F.1",
                component_id="deobfuscator",
            )

        return report
