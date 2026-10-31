# LotLImmune Phase 1B — Comparative Defense Benchmark

Companion empirical scaffold for the `LotLImmune` paper (papermachineclip).

## What runs

```bash
PYTHONPATH=src python3 -m activesec.benchmark.benchmark_suite \
  --output results/lotlimmune_benchmark.json
```

## Regimes

| Regime | Implementation |
| :--- | :--- |
| `unguarded` | YOLO baseline — never blocks |
| `regex` | Static string/regex blacklist |
| `llm_judge` | **Offline heuristic stub** (no live LLM). Models documented blind spots and a 320 ms latency floor |
| `activesec_ring0` | Real `NetworkGuard`, `CredentialGuard`, `MalwareGuard`, `CommandDeobfuscator`, `SecurityKernel`; thin adapters for Zip-Slip member names / fork-bomb / disallowed flags |

## Scale caveat

Compact Phase-1B fixtures (not the full ≥120-attack E1 suite). Expand later without changing the regime interface.
