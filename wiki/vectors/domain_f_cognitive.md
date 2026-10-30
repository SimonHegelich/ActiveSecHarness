# Threat Vector Synthesis – Domain F: Human Social Engineering & AI Prompt Injection

- **Taxonomy Reference:** [`docs/01_threat_taxonomy.md#domain-f`](../../docs/01_threat_taxonomy.md)
- **Primary Mitigating Components:**
  - [`deobfuscator`](../components/deobfuscator.md) (Base64/Hex decoding, Trojan Source Bidi detection, pipe-to-shell and social-engineering risk classification)
  - [`capability_token`](../components/capability_token.md) (Context taint-lock `require_untainted_context` preventing Confused Deputy escalation)

## Core Threat Model
Attackers target both the AI (via indirect prompt injection in untrusted files/webpages) and the human operator (via obfuscated commands, copy-paste traps, urgency framing, and approval fatigue during `sudo` prompts).

## Enforced Invariants
1. Commands presented for `sudo` approval are deterministically de-obfuscated (Base64/Hex payloads decoded inline, invisible Unicode characters flagged).
2. Tainted agent contexts (`context_tainted=True`) are automatically blocked from invoking privileged tokens that require untainted execution.
