# LotLImmune E1 — Comparative Defense Benchmark

Companion empirical suite for the `LotLImmune` paper (papermachineclip).

## What runs

```bash
PYTHONPATH=src python3 -m activesec.benchmark.benchmark_suite \
  --output results/lotlimmune_benchmark.json
```

## Fixtures

- 120 attack + 120 benign across Domains A–F
- 12 kill-chain multi-stage scenarios
- Total `n_cases = 252`

## Regimes

| Regime | Implementation |
| :--- | :--- |
| `unguarded` | YOLO baseline — never blocks |
| `regex` | Static string/regex blacklist |
| `live_llm_judge` | Live Ollama (`qwen3:4b`) with on-disk cache; tiny JSON verdicts; per-case fallback |
| `activesec_ring0` | Real Ring-0 adapters (`NetworkGuard`, `CredentialGuard`, `MalwareGuard`, `CommandDeobfuscator`, `SecurityKernel`) |
| `hybrid_llm_plus_ring0` | Ring-0 authoritative; LLM advisory (cannot override Ring-0 allow) |

Intervals: Clopper–Pearson exact 95% CIs on ABR/FPR.
