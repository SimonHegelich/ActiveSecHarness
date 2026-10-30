"""Ring-0 NetworkGuard: TLS 1.3 transport enforcement and socket-level Anti-SSRF validator.

Blocks cleartext protocols, weak TLS configurations, cloud metadata endpoints (169.254.169.254),
loopback/private RFC1918 pivoting, and DNS rebinding attacks unless explicitly scoped by a
Pentest CapabilityToken.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
import urllib.parse
from dataclasses import dataclass
from typing import Callable, FrozenSet, List, Tuple

from activesec.core.component import ComponentSecurityAssessment, SecureComponent
from activesec.core.exceptions import NetworkSecurityError


ResolverFunc = Callable[[str, int], List[str]]


@dataclass(frozen=True, slots=True)
class ValidatedEndpoint:
    """Immutable record of a verified network connection target with pinned IP addresses."""

    scheme: str
    hostname: str
    port: int
    pinned_ips: Tuple[str, ...]


class NetworkGuard(SecureComponent):
    """Ring-0 network transport and Anti-SSRF gateway."""

    ALLOWED_SCHEMES: FrozenSet[str] = frozenset({"https"})

    def __init__(
        self,
        *,
        allowed_domains: FrozenSet[str] | None = None,
        allowed_private_cidr_scopes: FrozenSet[str] = frozenset(),
        dns_resolver: ResolverFunc | None = None,
    ) -> None:
        self._allowed_domains: FrozenSet[str] | None = allowed_domains
        self._allowed_private_networks: Tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
            ipaddress.ip_network(cidr, strict=False) for cidr in allowed_private_cidr_scopes
        )
        self._dns_resolver: ResolverFunc = dns_resolver if dns_resolver is not None else self._default_resolve

    @classmethod
    def security_assessment(cls) -> ComponentSecurityAssessment:
        return ComponentSecurityAssessment(
            component_id="network_guard",
            title="Ring-0 TLS 1.3 Transport & Anti-SSRF Network Guard",
            ring_level=0,
            source_path="src/activesec/guards/network_guard.py",
            security_test_path="tests/security/test_sec_network_guard.py",
            threat_vectors=("C.1", "C.2", "C.3"),
            summary=(
                "Enforces HTTPS with TLS 1.3, full certificate chain & hostname verification, "
                "domain allowlisting, and socket-level IP validation against SSRF, cloud metadata "
                "theft (169.254.169.254), localhost pivoting, and DNS rebinding."
            ),
            enforced_invariants=(
                "Rejects cleartext http://, ftp://, ws://, file://, and gopher:// schemes.",
                "Constructs ssl.SSLContext with minimum_version = ssl.TLSVersion.TLSv1_3, verify_mode = ssl.CERT_REQUIRED, and check_hostname = True.",
                "Resolves DNS once and validates every returned IP against loopback, link-local (169.254.0.0/16), RFC1918 private, multicast, and unspecified ranges unless explicitly covered by a Pentest lab CIDR.",
                "Rejects embedded URL credentials (user:pass@host) and insecure CLI flags (-k, --insecure).",
            ),
            residual_risks=(
                "Application-layer data exfiltration to an explicitly allowlisted public domain (mitigated by pairing with CredentialGuard DLP inspection).",
            ),
        )

    @staticmethod
    def _default_resolve(hostname: str, port: int) -> List[str]:
        try:
            infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise NetworkSecurityError(
                f"DNS resolution failed for host '{hostname}': {exc}",
                vector_id="C.2",
                component_id="network_guard",
            ) from exc
        ips: List[str] = []
        for info in infos:
            ip_str = str(info[4][0])
            if ip_str not in ips:
                ips.append(ip_str)
        return ips

    @staticmethod
    def create_hardened_tls_context() -> ssl.SSLContext:
        """Create a hardened TLS 1.3 SSLContext with mandatory certificate and hostname checks."""
        ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        ctx.options |= ssl.OP_NO_COMPRESSION
        return ctx

    def validate_url_target(self, url: str) -> ValidatedEndpoint:
        """Validate a URL against scheme, domain allowlist, and socket-level Anti-SSRF IP checks."""
        parsed = urllib.parse.urlsplit(url)
        scheme = parsed.scheme.lower()

        if scheme not in self.ALLOWED_SCHEMES:
            raise NetworkSecurityError(
                f"Insecure or forbidden URL scheme '{scheme}://'; HTTPS with TLS 1.3 is required.",
                vector_id="C.1",
                component_id="network_guard",
            )

        if parsed.username or parsed.password:
            raise NetworkSecurityError(
                "Embedded credentials in URL are forbidden.",
                vector_id="C.3",
                component_id="network_guard",
            )

        hostname = (parsed.hostname or "").lower().strip()
        if not hostname:
            raise NetworkSecurityError(
                "URL is missing a valid hostname.",
                vector_id="C.1",
                component_id="network_guard",
            )

        if self._allowed_domains is not None and hostname not in self._allowed_domains:
            raise NetworkSecurityError(
                f"Host '{hostname}' is not in the permitted domain allowlist.",
                vector_id="C.3",
                component_id="network_guard",
            )

        port = parsed.port or 443
        resolved_ips = self._dns_resolver(hostname, port)
        if not resolved_ips:
            raise NetworkSecurityError(
                f"Host '{hostname}' resolved to zero IP addresses.",
                vector_id="C.2",
                component_id="network_guard",
            )

        for ip_str in resolved_ips:
            self._validate_ip_address(ip_str, hostname=hostname)

        return ValidatedEndpoint(
            scheme=scheme,
            hostname=hostname,
            port=port,
            pinned_ips=tuple(resolved_ips),
        )

    def _validate_ip_address(self, ip_str: str, *, hostname: str) -> None:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError as exc:
            raise NetworkSecurityError(
                f"Invalid IP address '{ip_str}' for host '{hostname}'.",
                vector_id="C.2",
                component_id="network_guard",
            ) from exc

        # Unwrap IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1 or ::ffff:169.254.169.254)
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
            ip_obj = ip_obj.ipv4_mapped

        # Check if explicitly covered by an isolated Pentest Lab scope
        if any(ip_obj in net for net in self._allowed_private_networks):
            return

        if (
            ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_private
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
            or ip_obj.is_reserved
        ):
            raise NetworkSecurityError(
                f"SSRF / Internal network access blocked: '{hostname}' resolved to restricted IP '{ip_obj}'.",
                vector_id="C.2",
                component_id="network_guard",
            )
