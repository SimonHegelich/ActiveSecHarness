# Threat Vector Synthesis – Domain E: Sandbox Isolation & Resource Quotas

- **Taxonomy Reference:** [`docs/01_threat_taxonomy.md#domain-e`](../../docs/01_threat_taxonomy.md)
- **Primary Mitigating Components:**
  - [`capability_token`](../components/capability_token.md) (Per-call quota, TTL, and canonical path confinement)
  - Upcoming `sandbox_guard` (`bubblewrap` namespace isolation, `cgroups v2` PID/RAM caps, `seccomp-bpf`)

## Core Threat Model
Without OS-level namespace isolation and resource limits, a single malicious or runaway subprocess can read `~/.ssh`, exhaust host memory/PIDs via a fork bomb, or escape into the host user session.
