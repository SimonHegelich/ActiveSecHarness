"""Adversarial security tests for NetworkGuard (src/activesec/guards/network_guard.py).

Verifies TLS 1.3 enforcement, cleartext protocol rejection, SSRF protection against
cloud metadata (169.254.169.254), localhost/RFC1918 pivoting, IPv6-mapped bypasses,
and DNS rebinding defense.
"""

from __future__ import annotations

import ssl

import pytest

from activesec.core.exceptions import NetworkSecurityError
from activesec.guards.network_guard import NetworkGuard, PinnedHTTPSConnection


@pytest.mark.security
@pytest.mark.parametrize(
    "insecure_url",
    [
        "http://api.github.com/repos",
        "ftp://files.example.com/archive.zip",
        "ws://realtime.example.com/socket",
        "file:///etc/passwd",
        "https://admin:secretpass@api.example.com/v1",
    ],
)
def test_sec_cleartext_schemes_and_embedded_creds_blocked(insecure_url: str) -> None:
    """[Vector C.1 & C.3: Insecure Transport] Rejects non-HTTPS schemes and embedded URL credentials."""
    guard = NetworkGuard(dns_resolver=lambda host, port: ["93.184.216.34"])
    with pytest.raises(NetworkSecurityError):
        guard.validate_url_target(insecure_url)


@pytest.mark.security
@pytest.mark.parametrize(
    "ssrf_ip",
    [
        "169.254.169.254",         # AWS/GCP/Azure Cloud Metadata Service
        "127.0.0.1",               # IPv4 Loopback
        "::1",                     # IPv6 Loopback
        "::ffff:127.0.0.1",        # IPv4-mapped IPv6 Loopback bypass attempt
        "::ffff:169.254.169.254",  # IPv4-mapped IPv6 Metadata bypass attempt
        "10.0.0.15",               # RFC1918 Private Class A
        "172.16.5.4",              # RFC1918 Private Class B
        "192.168.1.1",             # RFC1918 Private Class C
        "0.0.0.0",                 # Unspecified address
    ],
)
def test_sec_ssrf_and_dns_rebinding_ips_blocked(ssrf_ip: str) -> None:
    """[Vector C.2: SSRF & DNS Rebinding] Blocks domains resolving to loopback, metadata, or RFC1918 IPs."""
    guard = NetworkGuard(dns_resolver=lambda host, port: [ssrf_ip])
    with pytest.raises(NetworkSecurityError) as exc_info:
        guard.validate_url_target("https://rebind-attacker.example.com/api")
    assert exc_info.value.vector_id == "C.2"


@pytest.mark.security
def test_sec_scoped_pentest_lab_cidr_permitted_only_within_scope() -> None:
    """[Vector C.2: Scoped Pentest Lab] Allows isolated lab subnet 10.99.42.0/24 while blocking other private IPs."""
    guard = NetworkGuard(
        allowed_private_cidr_scopes=frozenset({"10.99.42.0/24"}),
        dns_resolver=lambda host, port: ["10.99.42.15"] if host == "lab-target.local" else ["192.168.1.50"],
    )
    endpoint = guard.validate_url_target("https://lab-target.local:8443/vuln")
    assert endpoint.pinned_ips == ("10.99.42.15",)

    with pytest.raises(NetworkSecurityError):
        guard.validate_url_target("https://host-lan.local/admin")


@pytest.mark.security
def test_sec_hardened_tls_context_enforces_tls13() -> None:
    """[Vector C.1: TLS Hardening] Ensures SSLContext requires TLS 1.3 and strict certificate verification."""
    ctx = NetworkGuard.create_hardened_tls_context()
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


@pytest.mark.security
def test_sec_socket_level_ip_pinning_defeats_post_check_dns_rebinding(monkeypatch: pytest.MonkeyPatch) -> None:
    """[Vector C.3: DNS Rebinding TOCTOU Defense] PinnedHTTPSConnection dials the pre-validated IP while preserving TLS SNI hostname."""
    guard = NetworkGuard(dns_resolver=lambda host, port: ["93.184.216.34"])
    conn = guard.build_pinned_https_connection("https://api.example.com:8443/v1")
    assert isinstance(conn, PinnedHTTPSConnection)
    assert conn.pinned_ip == "93.184.216.34"
    assert conn.host == "api.example.com"
    assert conn.port == 8443

    dialed_targets: list[tuple[str, int]] = []
    sni_hosts: list[str] = []

    class DummyRawSocket:
        pass

    def fake_create_connection(address: tuple[str, int], timeout: object = None, source_address: object = None) -> DummyRawSocket:
        dialed_targets.append(address)
        return DummyRawSocket()

    def fake_wrap_socket(sock: object, server_hostname: str | None = None) -> str:
        sni_hosts.append(server_hostname or "")
        return "wrapped_tls13_socket"

    monkeypatch.setattr("socket.create_connection", fake_create_connection)
    monkeypatch.setattr(conn._context, "wrap_socket", fake_wrap_socket)

    conn.connect()
    # Even if DNS were rebound after validate_url_target, connect() dials the pinned IP 93.184.216.34 directly
    assert dialed_targets == [("93.184.216.34", 8443)]
    assert sni_hosts == ["api.example.com"]

