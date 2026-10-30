"""Ring-0 CanaryGuard: Zero-false-positive honeypot tripwire for prompt injection and exfiltration.

Plants decoy honeyfiles and canary tokens (synthetic AWS/OpenAI/SSH credentials) that have
zero legitimate operational use. Any attempt by an agent or subprocess to read a canary path
or emit a canary token in command args, stdout, or network payloads proves compromise with
100% certainty and immediately triggers emergency token revocation.
"""

from __future__ import annotations

import base64
import os
import secrets
from dataclasses import dataclass
from typing import Callable, Dict, FrozenSet, Optional, Tuple

from activesec.core.component import ComponentSecurityAssessment, SecureComponent
from activesec.core.exceptions import CanaryTripwireError


RevocationCallback = Callable[[str], None]


@dataclass(frozen=True, slots=True)
class CanaryArtifact:
    """Immutable descriptor of a planted honeypot canary token or honeyfile."""

    canary_id: str
    kind: str  # "AWS_KEY", "OPENAI_KEY", "SSH_KEY_FILE", "ENV_DECOY"
    secret_value: str
    honeypot_path: Optional[str] = None


class CanaryGuard(SecureComponent):
    """Ring-0 honeypot canary generator and tripwire verifier."""

    def __init__(self, *, on_tripwire: Optional[RevocationCallback] = None) -> None:
        self._canaries: Dict[str, CanaryArtifact] = {}
        self._honeypot_paths: set[str] = set()
        self._on_tripwire: Optional[RevocationCallback] = on_tripwire

    @classmethod
    def security_assessment(cls) -> ComponentSecurityAssessment:
        return ComponentSecurityAssessment(
            component_id="canary_guard",
            title="Ring-0 Honeypot Canary & Zero-False-Positive Intrusion Tripwire",
            ring_level=0,
            source_path="src/activesec/guards/canary_guard.py",
            security_test_path="tests/security/test_sec_canary_guard.py",
            threat_vectors=("F.2", "C.3", "D.2", "A.1"),
            summary=(
                "Deploys synthetic honeypot credentials and decoy files (Canary Tokens) that no "
                "legitimate task ever touches. Detects indirect prompt injection, credential harvesting, "
                "and covert exfiltration (including Base64/Hex-encoded leaks) with zero false positives."
            ),
            enforced_invariants=(
                "Generates cryptographically unique decoy tokens (synthetic AWS AKIA, OpenAI sk-canary, SSH honeyfiles) via CSPRNG.",
                "Canonicalizes inspected file paths (os.path.realpath) so symlink or ../ access to a honeyfile immediately trips the alarm.",
                "Inspects outbound commands, tool outputs, and network bodies for both raw and Base64/Hex-encoded canary values.",
                "Invokes the registered emergency revocation callback prior to raising CanaryTripwireError.",
            ),
            residual_risks=(
                "Sophisticated attacker who selectively exfiltrates only application source code while avoiding credential files (mitigated by NetworkGuard offline default).",
            ),
        )

    @property
    def registered_canaries(self) -> Tuple[CanaryArtifact, ...]:
        return tuple(self._canaries.values())

    @property
    def honeypot_paths(self) -> FrozenSet[str]:
        return frozenset(self._honeypot_paths)

    def deploy_default_canaries(self, workspace_dir: Optional[str] = None) -> Tuple[CanaryArtifact, ...]:
        """Generate and register a suite of high-enticement canary tokens and optional honeyfile."""
        aws_suffix = "".join(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(16))
        aws_canary = CanaryArtifact(
            canary_id="canary_aws_root",
            kind="AWS_KEY",
            secret_value=f"AKIA{aws_suffix}",
        )
        openai_canary = CanaryArtifact(
            canary_id="canary_openai_prod",
            kind="OPENAI_KEY",
            secret_value=f"sk-canary-{secrets.token_hex(16)}",
        )
        self.register_canary(aws_canary)
        self.register_canary(openai_canary)

        deployed = [aws_canary, openai_canary]
        if workspace_dir is not None:
            real_ws = os.path.realpath(workspace_dir)
            os.makedirs(real_ws, mode=0o700, exist_ok=True)
            honey_file = os.path.join(real_ws, ".aws_prod_credentials.canary")
            file_secret = f"aws_secret_access_key = {secrets.token_urlsafe(30)}"
            with open(honey_file, "w", encoding="utf-8") as fh:
                fh.write(f"[production]\naws_access_key_id = {aws_canary.secret_value}\n{file_secret}\n")
            os.chmod(honey_file, 0o600)
            file_canary = CanaryArtifact(
                canary_id="canary_honeyfile_aws",
                kind="HONEYFILE",
                secret_value=file_secret,
                honeypot_path=os.path.realpath(honey_file),
            )
            self.register_canary(file_canary)
            deployed.append(file_canary)

        return tuple(deployed)

    def register_canary(self, artifact: CanaryArtifact) -> None:
        """Register a custom canary artifact with the tripwire monitor."""
        if len(artifact.secret_value) < 12:
            raise CanaryTripwireError(
                "Canary secret value must be at least 12 characters to prevent accidental collisions.",
                vector_id="D.2",
                component_id="canary_guard",
            )
        self._canaries[artifact.canary_id] = artifact
        if artifact.honeypot_path is not None:
            self._honeypot_paths.add(os.path.realpath(artifact.honeypot_path))

    def _trigger_alarm(self, message: str, *, vector_id: str, token_id: Optional[str] = None) -> None:
        if self._on_tripwire is not None and token_id is not None:
            self._on_tripwire(token_id)
        raise CanaryTripwireError(
            message,
            vector_id=vector_id,
            component_id="canary_guard",
        )

    def check_path_access(self, target_path: str, *, active_token_id: Optional[str] = None) -> None:
        """Trip immediately if an agent attempts to read, stat, or modify a honeypot file."""
        real_target = os.path.realpath(target_path)
        if real_target in self._honeypot_paths:
            self._trigger_alarm(
                f"CRITICAL TRIPWIRE: Agent accessed honeypot file '{target_path}'. Active compromise detected!",
                vector_id="F.2",
                token_id=active_token_id,
            )

    def check_stream_for_canaries(self, data: str, *, active_token_id: Optional[str] = None) -> None:
        """Inspect command arguments, stdout, or network payloads for raw or encoded canary tokens."""
        if not data:
            return

        for artifact in self._canaries.values():
            secret = artifact.secret_value
            b64_secret = base64.b64encode(secret.encode("utf-8")).decode("ascii").rstrip("=")
            hex_secret = secret.encode("utf-8").hex()

            if secret in data or (len(b64_secret) >= 12 and b64_secret in data) or hex_secret in data.lower():
                self._trigger_alarm(
                    f"CRITICAL TRIPWIRE: Canary token '{artifact.canary_id}' ({artifact.kind}) detected in stream! Exfiltration blocked.",
                    vector_id="C.3",
                    token_id=active_token_id,
                )
