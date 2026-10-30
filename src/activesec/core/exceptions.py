"""Strict security exception hierarchy for ActiveSecHarness.

All security violations fail closed by raising a specific subclass of ActiveSecError
carrying structured threat vector metadata for audit logging and TelosLines telemetry.
"""

from __future__ import annotations


class ActiveSecError(Exception):
    """Base exception for all security violations in ActiveSecHarness."""

    def __init__(self, message: str, *, vector_id: str = "UNKNOWN", component_id: str = "core") -> None:
        super().__init__(message)
        self.message: str = message
        self.vector_id: str = vector_id
        self.component_id: str = component_id

    def __str__(self) -> str:
        return f"[{self.component_id}:{self.vector_id}] {self.message}"


class CapabilityViolationError(ActiveSecError):
    """Raised when a capability token is invalid, expired, tainted, forged, or violates attenuation."""


class AuditIntegrityError(ActiveSecError):
    """Raised when tampering, deletion, reordering, or signature forgery is detected in the audit log."""


class ArchiveSecurityError(ActiveSecError):
    """Raised when an archive triggers decompression bomb, Zip-Slip, or special-file guards."""


class CredentialSecurityError(ActiveSecError):
    """Raised when a password fails entropy/dictionary checks or when cleartext secrets are detected."""


class NetworkSecurityError(ActiveSecError):
    """Raised when a network request violates TLS 1.3, domain allowlists, or Anti-SSRF IP checks."""


class MalwareSecurityError(ActiveSecError):
    """Raised when a file fails magic-byte spoofing, polyglot, YARA-like pattern, or malware hash checks."""


class SandboxSecurityError(ActiveSecError):
    """Raised when a sandbox configuration, environment, mount, or subprocess execution violates containment."""


class CanaryTripwireError(ActiveSecError):
    """Raised with zero false positives when a honeypot canary token or file is accessed or exfiltrated."""


class SocialEngineeringAlertError(ActiveSecError):
    """Raised when a command exhibits obfuscation, Trojan Source Unicode, or high-risk LotL patterns."""


class ModelSecurityError(ActiveSecError):
    """Raised when LLM provider configuration, routing, digest verification, or response validation fails."""

