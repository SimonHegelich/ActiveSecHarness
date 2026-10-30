# Component Security Assessment: `network_guard`

> **Auto-Generated & Verified by `WikiManager` (`tools/wiki_sync.py`)** — Do not edit manual status badges directly; update the `ComponentSecurityAssessment` contract in [`src/activesec/guards/network_guard.py`](../../src/activesec/guards/network_guard.py) or the security test suite in [`tests/security/test_sec_network_guard.py`](../../tests/security/test_sec_network_guard.py).

---

## 1. Security Posture Metadata

| Attribute | Value |
| :--- | :--- |
| **Component ID** | `network_guard` |
| **Title** | Ring-0 TLS 1.3 Transport & Anti-SSRF Network Guard |
| **Privilege Ring** | **Ring 0** |
| **Mitigated Threat Vectors** | `C.1`, `C.2`, `C.3` |
| **Source File** | [`src/activesec/guards/network_guard.py`](../../src/activesec/guards/network_guard.py) (`sha256:12291c0db488`) |
| **Dedicated Security Test Suite** | [`tests/security/test_sec_network_guard.py`](../../tests/security/test_sec_network_guard.py) |
| **AST Static Safety Audit** | **CLEAN (Zero Forbidden Primitives)** |
| **Adversarial Security Verification** | **VERIFIED (PASS)** (4 test vectors) |

---

## 2. Architectural Summary

Enforces HTTPS with TLS 1.3, full certificate chain & hostname verification, domain allowlisting, and socket-level IP validation against SSRF, cloud metadata theft (169.254.169.254), localhost pivoting, and DNS rebinding.

---

## 3. Enforced Deterministic Security Invariants

- Rejects cleartext http://, ftp://, ws://, file://, and gopher:// schemes.
- Constructs ssl.SSLContext with minimum_version = ssl.TLSVersion.TLSv1_3, verify_mode = ssl.CERT_REQUIRED, and check_hostname = True.
- Resolves DNS once and validates every returned IP against loopback, link-local (169.254.0.0/16), RFC1918 private, multicast, and unspecified ranges unless explicitly covered by a Pentest lab CIDR.
- Rejects embedded URL credentials (user:pass@host) and insecure CLI flags (-k, --insecure).

---

## 4. Dedicated Component Security Tests (`tests/security/test_sec_network_guard.py`)

| Test Function | Verified Adversarial Vector & Invariant | Status |
| :--- | :--- | :--- |
| `test_sec_cleartext_schemes_and_embedded_creds_blocked` | [Vector C.1 & C.3: Insecure Transport] Rejects non-HTTPS schemes and embedded URL credentials. | **PASS** |
| `test_sec_ssrf_and_dns_rebinding_ips_blocked` | [Vector C.2: SSRF & DNS Rebinding] Blocks domains resolving to loopback, metadata, or RFC1918 IPs. | **PASS** |
| `test_sec_scoped_pentest_lab_cidr_permitted_only_within_scope` | [Vector C.2: Scoped Pentest Lab] Allows isolated lab subnet 10.99.42.0/24 while blocking other private IPs. | **PASS** |
| `test_sec_hardened_tls_context_enforces_tls13` | [Vector C.1: TLS Hardening] Ensures SSLContext requires TLS 1.3 and strict certificate verification. | **PASS** |

---

## 5. Known Residual Risks & Defense-in-Depth Pairing

- Application-layer data exfiltration to an explicitly allowlisted public domain (mitigated by pairing with CredentialGuard DLP inspection).
