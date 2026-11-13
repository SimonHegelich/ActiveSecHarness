"""Integrity tests for the LotLImmune benchmark harness (src/activesec/benchmark/).

The benchmark scores each regime against the fixture's ground-truth ``kind`` (attack / benign).
These tests verify that the Ring-0 regime never uses that ground truth, or the fixture's descriptive
tags, to reach its decision, that the judge fallback is not an oracle, and that the multi-step
trajectories are blocked by the mechanism they are meant to demonstrate.
"""

from __future__ import annotations

import builtins
import dataclasses
from pathlib import Path

import pytest

from activesec.benchmark import benchmark_suite as bs
from activesec.benchmark.fixtures import load_fixtures, load_trajectory_fixtures


@pytest.mark.security
def test_sec_ring0_adapter_decisions_do_not_depend_on_fixture_kind_or_tags(tmp_path: Path) -> None:
    """[Vector F.1 & F.3: Benchmark Integrity] Ring-0 verdicts are identical when the fixture's kind and tags are hidden."""
    cases = list(load_fixtures())
    shipped = bs.Ring0Adapter(str(tmp_path / "ws_shipped"))
    hidden = bs.Ring0Adapter(str(tmp_path / "ws_hidden"))
    for case in cases:
        flipped_kind = "benign" if case.kind == "attack" else "attack"
        blind_case = dataclasses.replace(case, kind=flipped_kind, tags=())
        assert shipped.decide(case)[0] == hidden.decide(blind_case)[0], case.case_id


@pytest.mark.security
def test_sec_ring0_adapter_never_reports_a_block_the_real_guard_did_not_make(tmp_path: Path) -> None:
    """[Vector B.3 & D.2: Benchmark Integrity] A fixture the real MalwareGuard / CredentialGuard accepts is reported as allowed."""
    adapter = bs.Ring0Adapter(str(tmp_path / "ws"))
    by_id = {c.case_id: c for c in load_fixtures()}
    # Mach-O bytes in a .py file, SVG/HTML/PDF active content, and an AWS secret key assignment are
    # accepted by the real guards; the benchmark must report that outcome, not a forced block.
    for case_id in ("B-atk-11-macho", "B-atk-18-svg-script", "B-atk-19-html-poly", "B-atk-20-pdf-js", "D-atk-18-aws-secret"):
        blocked, reason = adapter.decide(by_id[case_id])
        assert blocked is False, (case_id, reason)
    # Marker-only archive fixtures are decided by the thin adapter and labelled as such.
    for case_id in ("B-atk-16-zipbomb-marker", "B-atk-17-jar-polyglot"):
        blocked, reason = adapter.decide(by_id[case_id])
        assert blocked is True and "ArchiveFixtureAdapter" in reason, (case_id, reason)


@pytest.mark.security
def test_sec_trajectory_verdicts_do_not_depend_on_fixture_kind(tmp_path: Path) -> None:
    """[Vector F.2 & F.3: Benchmark Integrity] Trajectory verdicts are identical when every trajectory's kind is flipped."""
    scenarios = list(load_trajectory_fixtures())
    flipped = [dataclasses.replace(s, kind=("benign" if s.kind == "attack" else "attack")) for s in scenarios]
    adapter = bs.Ring0Adapter(str(tmp_path / "ws"))
    for original, relabelled in zip(scenarios, flipped):
        adapter.reset_session()
        ledger_original = bs._evaluate_trajectory_activesec_product_ledger(original, adapter)
        adapter.reset_session()
        ledger_relabelled = bs._evaluate_trajectory_activesec_product_ledger(relabelled, adapter)
        assert ledger_original[:2] == ledger_relabelled[:2], original.trajectory_id
        adapter.reset_session()
        boolean_original = bs._evaluate_trajectory_coarse_boolean_taint(original, adapter)
        adapter.reset_session()
        boolean_relabelled = bs._evaluate_trajectory_coarse_boolean_taint(relabelled, adapter)
        assert boolean_original[:2] == boolean_relabelled[:2], original.trajectory_id


@pytest.mark.security
def test_sec_trajectories_are_blocked_at_the_step_they_demonstrate(tmp_path: Path) -> None:
    """[Vector F.3 & A.4: Trajectory Ablation] KC-T11 is blocked by the cross-agent ledger at step 5, KC-T09 at the hook write."""
    adapter = bs.Ring0Adapter(str(tmp_path / "ws"))
    by_id = {s.trajectory_id: s for s in load_trajectory_fixtures()}

    # KC-T11: agent A reads a sensitive file and writes notes.txt; agent B reads it and tries egress.
    adapter.reset_session()
    blocked, step, reason = bs._evaluate_trajectory_activesec_product_ledger(by_id["KC-T11-exfil-trifecta"], adapter)
    assert blocked is True and step == 5
    assert reason.startswith("product_ledger_block:ToxicCombinationError")

    # KC-T09: the test run at step 3 is harmless; the attack is the .git/hooks write at step 5.
    adapter.reset_session()
    blocked, step, reason = bs._evaluate_trajectory_activesec_product_ledger(by_id["KC-T09-persist-hook"], adapter)
    assert blocked is True and step == 5

    # KC-T05: a harmless-looking command is refused only because of what the agent read before.
    adapter.reset_session()
    blocked, step, reason = bs._evaluate_trajectory_activesec_product_ledger(by_id["KC-T05-exploit-ipi"], adapter)
    assert blocked is True and step == 3
    assert reason.startswith("product_ledger_block:")


@pytest.mark.security
def test_sec_llm_judge_fallback_is_not_an_oracle(tmp_path: Path) -> None:
    """[Vector F.1: Benchmark Integrity] The judge fallback blocks every case and never reads the fixture's kind."""
    judge = bs.LiveLLMJudge(cache_path=tmp_path / "cache.json")
    cases = list(load_fixtures())
    benign = next(c for c in cases if c.kind == "benign")
    attack = next(c for c in cases if c.kind == "attack")
    assert judge._fallback(benign, "unreachable") == (True, "llm_fallback_block:unreachable")
    assert judge._fallback(attack, "unreachable") == (True, "llm_fallback_block:unreachable")
    assert judge.stats["fallbacks"] == 2


@pytest.mark.security
def test_sec_confidence_intervals_are_clopper_pearson_without_scipy(monkeypatch: pytest.MonkeyPatch) -> None:
    """[Benchmark Integrity] Without scipy the interval is still exact Clopper-Pearson, not a different method."""
    real_import = builtins.__import__

    def import_without_scipy(name: str, *args: object, **kwargs: object) -> object:
        if name.startswith("scipy"):
            raise ImportError("scipy hidden for this test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_without_scipy)
    # Reference values of the exact Clopper-Pearson 95% interval.
    expected = {(58, 132): (0.3532, 0.5283), (8, 12): (0.3489, 0.9008), (10, 12): (0.5159, 0.9791), (0, 120): (0.0, 0.0303), (132, 132): (0.9724, 1.0)}
    for (k, n), (low, high) in expected.items():
        got_low, got_high = bs._clopper_pearson(k, n)
        assert got_low == pytest.approx(low, abs=1e-4)
        assert got_high == pytest.approx(high, abs=1e-4)
