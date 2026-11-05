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

## Phase 1C (Experiment E3): Multi-Step Trajectory & Conseca Ablation

```bash
PYTHONPATH=src python3 -m activesec.benchmark.benchmark_suite \
  --trajectories-only --output results/lotlimmune_benchmark.json
```

See **[`wiki/vectors/conseca_trajectory_ablation.md`](conseca_trajectory_ablation.md)** for the full 24-trajectory (`KC-T01`–`KC-T12` and `BT-01`–`BT-12`) comparison across `stateless_task_policy` (Oracle Conseca-style per-action policy: `66.7%` ABR, `0.0%` FPR), `coarse_boolean_taint` (`100.0%` ABR, `83.3%` FPR), and `activesec_product_ledger` (`100.0%` ABR, `0.0%` FPR, $\approx 20.0\ \mu\text{s}$/step $\mathcal{O}(1)$ state-folding scaling across $k \in \{1, 5, 10, 25, 50\}$).

