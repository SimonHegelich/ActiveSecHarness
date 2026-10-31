# Component Security Assessment: `model_gateway`

> **Auto-Generated & Verified by `WikiManager` (`tools/wiki_sync.py`)** — Do not edit manual status badges directly; update the `ComponentSecurityAssessment` contract in [`src/activesec/harness/model_gateway.py`](../../src/activesec/harness/model_gateway.py) or the security test suite in [`tests/security/test_sec_model_gateway.py`](../../tests/security/test_sec_model_gateway.py).

---

## 1. Security Posture Metadata

| Attribute | Value |
| :--- | :--- |
| **Component ID** | `model_gateway` |
| **Title** | Ring-0 Hardened OpenRouter & Local Ollama Model Gateway |
| **Privilege Ring** | **Ring 0** |
| **Mitigated Threat Vectors** | `A.1`, `A.2`, `B.4`, `C.1`, `C.2`, `C.3`, `D.2`, `E.2`, `F.2` |
| **Source File** | [`src/activesec/harness/model_gateway.py`](../../src/activesec/harness/model_gateway.py) (`sha256:5db2c998110f`) |
| **Dedicated Security Test Suite** | [`tests/security/test_sec_model_gateway.py`](../../tests/security/test_sec_model_gateway.py) |
| **AST Static Safety Audit** | **CLEAN (Zero Forbidden Primitives)** |
| **Adversarial Security Verification** | **VERIFIED (PASS)** (8 test vectors) |

---

## 2. Architectural Summary

Mediates all LLM inference across cloud (OpenRouter) and local air-gapped (Ollama) models. Enforces immediate API key scrubbing from os.environ, per-session Denial-of-Wallet call budgets, pre-egress Canary tripwire & Secret DLP redaction, OpenRouter ZDR privacy routing invariants, local Ollama mutation blocking & SHA-256 digest pinning, capability-gated red-team model access, and bounded ingress stream reading with Trojan Source filtering.

---

## 3. Enforced Deterministic Security Invariants

- Pops OPENROUTER_API_KEY from os.environ on initialization when scrub_env=True so child processes cannot leak it.
- Runs CanaryGuard.check_stream_for_canaries() and CredentialGuard.redact_secrets() on every prompt message before network egress.
- Enforces TLS 1.3 via NetworkGuard.create_hardened_tls_context(), pins OpenRouter host to openrouter.ai, validates allowed_models, and injects provider={'data_collection': 'deny', 'allow_fallbacks': False, 'require_parameters': True}.
- Restricts local Ollama strictly to http://127.0.0.1:11434/api/chat and /api/show while blocking /api/pull, /api/create, /api/delete, /api/push, and /api/copy.
- Verifies SHA-256 model digests via /api/show when expected_sha256_digests is configured and requires a verified CapabilityToken for ModelRole.REDTEAM_PENTEST.
- Caps HTTP response streams at max_response_bytes (2 MB) and rejects responses containing Trojan Source Unicode control characters.

---

## 4. Dedicated Component Security Tests (`tests/security/test_sec_model_gateway.py`)

| Test Function | Verified Adversarial Vector & Invariant | Status |
| :--- | :--- | :--- |
| `test_sec_openrouter_api_key_scrubbed_from_environ` | [Vector A.2 & D.2: API Key Isolation] Immediately pops OPENROUTER_API_KEY from os.environ upon init. | **PASS** |
| `test_sec_openrouter_enforces_zdr_privacy_and_model_allowlist` | [Vector C.1 & C.3: OpenRouter ZDR & Model Allowlist] Injects data_collection='deny', TLS 1.3, and blocks unapproved models. | **PASS** |
| `test_sec_pre_egress_dlp_redaction_and_canary_tripwire` | [Vector D.2 & F.2: Pre-Egress DLP & Canary Tripwire] Redacts cleartext secrets and trips on Canary tokens before egress. | **PASS** |
| `test_sec_ollama_mutation_endpoints_and_remote_hosts_blocked` | [Vector A.1 & C.2: Ollama Endpoint Hardening] Blocks /api/pull, /api/delete, /api/create, and non-loopback hosts. | **PASS** |
| `test_sec_ollama_model_digest_mismatch_rejected` | [Vector C.3: Ollama Model Digest Pinning] Verifies model SHA-256 digest via /api/show and blocks tampered weights. | **PASS** |
| `test_sec_redteam_pentest_model_requires_verified_capability_token` | [Vector A.1: Red-Team Model Gating] Blocks REDTEAM_PENTEST uncensored model invocation without a valid pentest token. | **PASS** |
| `test_sec_ingress_oversized_response_and_trojan_unicode_rejected` | [Vector E.2 & B.4: Ingress Bomb & Trojan Unicode Defense] Rejects responses > max_response_bytes or containing Trojan Source Unicode. | **PASS** |
| `test_sec_session_request_budget_exhaustion_blocked` | [Vector E.2: Denial-of-Wallet Budget] Enforces max_requests_per_session to prevent runaway cost loops. | **PASS** |

---

## 5. Known Residual Risks & Defense-in-Depth Pairing

- Cloud model output could still propose subtle logic bugs in generated code (mitigated by routing all tool calls through Ring-0 SecurityKernel and SandboxGuard).
