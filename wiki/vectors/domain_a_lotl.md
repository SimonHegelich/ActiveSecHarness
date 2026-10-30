# Threat Vector Synthesis – Domain A: Living off the Land (LotL)

- **Taxonomy Reference:** [`docs/01_threat_taxonomy.md#domain-a`](../../docs/01_threat_taxonomy.md)
- **Primary Mitigating Components:**
  - [`capability_token`](../components/capability_token.md) (Cryptographic `sudo` chains, monotonic attenuation, binary allowlists)
  - [`deobfuscator`](../components/deobfuscator.md) (Detection of LOLBin evasion and encoded shell pipelines)

## Core Threat Model
Because a coding harness provides native access to `python`, `bash`, `git`, `curl`, and `tar`, any unauthorized or confused-deputy invocation turns the harness itself into a Living-off-the-Land weapon.

## Enforced Invariants
1. Every tool invocation requires a cryptographically valid `CapabilityToken` signed by Ring 0.
2. Delegating a token to a sub-agent strictly narrows allowed tools, path prefixes, binaries, and TTL (*Monotonic Attenuation*).
3. Subprocesses never inherit host environment secrets (`env={}` clean-room execution).
