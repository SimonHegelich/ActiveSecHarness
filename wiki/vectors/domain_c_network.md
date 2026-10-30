# Threat Vector Synthesis – Domain C: Network, TLS & Anti-SSRF

- **Taxonomy Reference:** [`docs/01_threat_taxonomy.md#domain-c`](../../docs/01_threat_taxonomy.md)
- **Primary Mitigating Components:**
  - [`network_guard`](../components/network_guard.md) (TLS 1.3 enforcement, socket-level IP validation against SSRF and DNS rebinding)
  - [`capability_token`](../components/capability_token.md) (Explicit `network_destinations` allowlisting for Pentest Lab scopes)

## Core Threat Model
Agents tricked via indirect prompt injection may attempt to reach cloud metadata services (`169.254.169.254`), localhost admin ports (`127.0.0.1`), or private LAN subnets (`10.0.0.0/8`, `192.168.0.0/16`), or downgrade transport security.

## Enforced Invariants
1. Cleartext `http://`, `ftp://`, and `ws://` schemes are rejected by default.
2. TLS contexts enforce minimum TLS 1.3 (or strong TLS 1.2 AEAD) with `CERT_REQUIRED` and hostname verification.
3. All resolved IP addresses are validated against loopback, link-local, RFC1918 private, multicast, and reserved ranges unless explicitly granted by a scoped Pentest `CapabilityToken`.
