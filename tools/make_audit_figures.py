#!/usr/bin/env python3
"""Render the figures of docs/05_audit_fixes_and_corrected_results.md from the benchmark results.

Reads ``results/lotlimmune_benchmark.json`` (the corrected run) and writes four SVG figures, each in
a light and a dark variant, to ``docs/audit_figures/``. The "published" values the figures compare
against are the ones printed in the paper and stored in the results file before the fixes; they are
constants below, with their source stated.

Usage:
    python3 tools/make_audit_figures.py [--results PATH] [--out-dir DIR] [--preview-dir DIR]

Requires matplotlib (not a dependency of the harness itself).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.axes import Axes  # noqa: E402
from matplotlib.figure import Figure  # noqa: E402
from matplotlib.patches import PathPatch  # noqa: E402
from matplotlib.path import Path as MplPath  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]

# Colour roles per theme. Categorical order is fixed (blue, orange, aqua, yellow, magenta) and was
# checked for colour-vision-deficiency separation in both themes; text always uses the ink roles.
THEMES: Dict[str, Dict[str, object]] = {
    "light": {
        "surface": "#fcfcfb",
        "ink": "#0b0b0b",
        "ink_secondary": "#52514e",
        "ink_muted": "#898781",
        "grid": "#e1e0d9",
        "axis": "#c3c2b7",
        "categorical": ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"],
        "label_on_fill": ["#ffffff", "#ffffff", "#ffffff", "#0b0b0b", "#ffffff"],
        "shade_before": "#86b6ef",
        "shade_after": "#1c5cab",
    },
    "dark": {
        "surface": "#1a1a19",
        "ink": "#f0efec",
        "ink_secondary": "#c3c2b7",
        "ink_muted": "#898781",
        "grid": "#2c2c2a",
        "axis": "#383835",
        "categorical": ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181"],
        "label_on_fill": ["#ffffff", "#ffffff", "#ffffff", "#ffffff", "#ffffff"],
        "shade_before": "#256abf",
        "shade_after": "#86b6ef",
    },
}

DOMAIN_NAMES: Mapping[str, str] = {
    "A": "A  LotL binary abuse",
    "B": "B  Artifacts and archives",
    "C": "C  Network and SSRF",
    "D": "D  Credentials and secrets",
    "E": "E  Sandbox escape",
    "F": "F  Injection and multi-agent",
}

# Source: paper Table 4 / Figure 3 and the results file at commit 5ff33c8 (Ring 0: 1.000 in every domain).
PUBLISHED_RING0_ABR_PER_DOMAIN = 1.0

# Source: audit of commit 5ff33c8 (see section 2 of the report). How the 132 attack verdicts of the
# Ring-0 regime were reached before the fixes.
DECISIONS_BEFORE: Mapping[str, int] = {
    "real": 99,
    "adapter_check": 22,
    "archive_marker": 2,
    "label_or_forced": 9,
    "not_blocked": 0,
}
DECISION_LABELS: Sequence[Tuple[str, str]] = (
    ("real", "A real component decides"),
    ("adapter_check", "Adapter path check (the kernel agrees)"),
    ("archive_marker", "Archive marker, no archive bytes"),
    ("label_or_forced", "Fixture label or forced verdict"),
    ("not_blocked", "Not blocked"),
)
ADAPTER_CHECK_SUFFIXES = (
    "workspace_escape",
    "sensitive_path",
    "null_byte_path",
    "path_escape",
    "fork_bomb",
    "ld_preload",
    "destructive",
    "reverse_shell",
)


def _new_figure(theme: Mapping[str, object], *, width: float, height: float) -> Tuple[Figure, Axes]:
    fig, ax = plt.subplots(figsize=(width, height), dpi=100)
    fig.patch.set_facecolor(str(theme["surface"]))
    ax.set_facecolor(str(theme["surface"]))
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(str(theme["axis"]))
    ax.spines["bottom"].set_linewidth(1.0)
    ax.tick_params(axis="both", length=0, colors=str(theme["ink_muted"]), labelsize=9)
    return fig, ax


def _title(fig: Figure, theme: Mapping[str, object], title: str, subtitle: str) -> None:
    fig.text(0.035, 0.955, title, fontsize=12.5, fontweight="bold", color=str(theme["ink"]), ha="left", va="top")
    fig.text(0.035, 0.885, subtitle, fontsize=9.5, color=str(theme["ink_secondary"]), ha="left", va="top")


def _legend(fig: Figure, theme: Mapping[str, object], entries: Sequence[Tuple[str, str]], *, y: float, x: float = 0.035) -> None:
    """Draw a one-row legend of (colour, label) swatches in figure coordinates."""
    cursor = x
    for colour, label in entries:
        fig.patches.append(
            plt.Rectangle((cursor, y - 0.012), 0.014, 0.024, transform=fig.transFigure, facecolor=colour, edgecolor="none")
        )
        text = fig.text(cursor + 0.02, y, label, fontsize=9, color=str(theme["ink_secondary"]), ha="left", va="center")
        fig.canvas.draw()
        bbox = text.get_window_extent()
        cursor += 0.02 + bbox.width / fig.bbox.width + 0.03


def _data_per_point(ax: Axes) -> Tuple[float, float]:
    """Return how many data units one point (1/72 inch) spans on each axis."""
    fig = ax.figure
    origin = ax.transData.transform((0.0, 0.0))
    unit = ax.transData.transform((1.0, 1.0))
    px_per_x = abs(unit[0] - origin[0])
    px_per_y = abs(unit[1] - origin[1])
    px_per_point = fig.dpi / 72.0
    return (px_per_point / px_per_x, px_per_point / px_per_y)


def _column(ax: Axes, x_left: float, width: float, height: float, colour: str, *, radius_pt: float = 3.0) -> None:
    """Vertical bar with a rounded data end and a square baseline."""
    if height <= 0:
        return
    dx, dy = _data_per_point(ax)
    rx = min(radius_pt * dx, width / 2.0)
    ry = min(radius_pt * dy, height)
    x0, x1, y1 = x_left, x_left + width, height
    verts = [(x0, 0.0), (x0, y1 - ry), (x0, y1), (x0 + rx, y1), (x1 - rx, y1), (x1, y1), (x1, y1 - ry), (x1, 0.0), (x0, 0.0)]
    codes = [MplPath.MOVETO, MplPath.LINETO, MplPath.CURVE3, MplPath.CURVE3, MplPath.LINETO, MplPath.CURVE3, MplPath.CURVE3, MplPath.LINETO, MplPath.CLOSEPOLY]
    ax.add_patch(PathPatch(MplPath(verts, codes), facecolor=colour, edgecolor="none", zorder=3))


def _save(fig: Figure, out_dir: Path, name: str, theme_name: str, preview_dir: Optional[Path]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_dir / f"{name}_{theme_name}.svg", facecolor=fig.get_facecolor())
    if preview_dir is not None:
        preview_dir.mkdir(parents=True, exist_ok=True)
        fig.savefig(preview_dir / f"{name}_{theme_name}.png", facecolor=fig.get_facecolor(), dpi=160)
    plt.close(fig)


def _grouped_rate_chart(
    theme: Mapping[str, object],
    *,
    groups: Sequence[str],
    attack: Sequence[Tuple[int, int]],
    benign: Sequence[Tuple[int, int]],
    title: str,
    subtitle: str,
    as_counts: bool,
) -> Figure:
    """Two columns per group: attacks blocked and benign blocked."""
    fig, ax = _new_figure(theme, width=7.8, height=4.0)
    fig.subplots_adjust(left=0.085, right=0.975, top=0.70, bottom=0.13)
    colours = theme["categorical"]
    assert isinstance(colours, list)
    y_max = float(attack[0][1]) if as_counts else 100.0
    ax.set_xlim(-0.6, len(groups) - 0.4)
    ax.set_ylim(0.0, y_max * 1.13)
    ticks = [0, 3, 6, 9, 12] if as_counts else [0, 25, 50, 75, 100]
    ax.set_yticks(ticks)
    ax.set_yticklabels([str(t) if as_counts else f"{t}%" for t in ticks])
    ax.yaxis.grid(True, color=str(theme["grid"]), linewidth=1.0)
    ax.set_axisbelow(True)
    ax.set_xticks(range(len(groups)))
    ax.set_xticklabels(groups, fontsize=9.5, color=str(theme["ink_secondary"]))

    dx, _ = _data_per_point(ax)
    bar_w = 22.0 * dx
    # The two columns of a group stand apart far enough for a value label over each.
    gap = 16.0 * dx
    for idx, (att, ben) in enumerate(zip(attack, benign)):
        for series, (k, n), offset in ((0, att, -(bar_w + gap / 2.0)), (1, ben, gap / 2.0)):
            value = float(k) if as_counts else 100.0 * k / n
            _column(ax, idx + offset, bar_w, value, str(colours[series]))
            label = f"{k}/{n}" if as_counts else f"{100.0 * k / n:.1f}%".replace(".0%", "%")
            ax.text(idx + offset + bar_w / 2.0, value + y_max * 0.018, label, ha="center", va="bottom", fontsize=8.5, color=str(theme["ink"]))
    _title(fig, theme, title, subtitle)
    _legend(fig, theme, [(str(colours[0]), "Attacks blocked"), (str(colours[1]), "Benign cases blocked")], y=0.79)
    return fig


def figure_regimes(results: Mapping[str, object], theme: Mapping[str, object]) -> Figure:
    summary = results["summary"]
    assert isinstance(summary, dict)
    order = (("unguarded", "Unguarded"), ("regex", "Regex list"), ("live_llm_judge", "LLM judge (qwen3:4b)"), ("activesec_ring0", "Ring 0"))
    attack = [(int(summary[key]["blocked_attacks"]), int(summary[key]["n_attack"])) for key, _ in order]
    benign = [(int(summary[key]["blocked_benign"]), int(summary[key]["n_benign"])) for key, _ in order]
    return _grouped_rate_chart(
        theme,
        groups=[label for _, label in order],
        attack=attack,
        benign=benign,
        title="Block rates per regime after the fixes",
        subtitle="252 pre-written tool calls: 132 attacks and 120 benign. The hybrid regime returns Ring 0's verdict.",
        as_counts=False,
    )


def figure_trajectories(results: Mapping[str, object], theme: Mapping[str, object]) -> Figure:
    trajectory = results["trajectory_ablation"]
    assert isinstance(trajectory, dict)
    summary = trajectory["summary"]
    order = (("stateless_task_policy", "Stateless task policy"), ("coarse_boolean_taint", "Boolean taint lock"), ("activesec_product_ledger", "Lattice and ledger"))
    attack = [(int(summary[key]["blocked_attack_trajectories"]), int(summary[key]["n_attack_trajectories"])) for key, _ in order]
    benign = [(int(summary[key]["blocked_benign_trajectories"]), int(summary[key]["n_benign_trajectories"])) for key, _ in order]
    return _grouped_rate_chart(
        theme,
        groups=[label for _, label in order],
        attack=attack,
        benign=benign,
        title="Multi-step trajectories blocked per regime after the fixes",
        subtitle="24 scripted five-step trajectories: 12 attacks and 12 benign. The counts match the published table.",
        as_counts=True,
    )


def figure_domains(results: Mapping[str, object], theme: Mapping[str, object]) -> Figure:
    """Dumbbell per domain: published Ring-0 attack block rate versus the corrected one."""
    summary = results["summary"]
    assert isinstance(summary, dict)
    by_domain = summary["activesec_ring0"]["by_domain"]
    domains = sorted(by_domain.keys())
    fig, ax = _new_figure(theme, width=7.8, height=3.9)
    fig.subplots_adjust(left=0.30, right=0.90, top=0.70, bottom=0.14)
    ax.set_xlim(70.0, 101.5)
    ax.set_ylim(-0.6, len(domains) - 0.4)
    ax.invert_yaxis()
    ax.set_xticks([70, 80, 90, 100])
    ax.set_xticklabels(["70%", "80%", "90%", "100%"])
    ax.xaxis.grid(True, color=str(theme["grid"]), linewidth=1.0)
    ax.set_axisbelow(True)
    ax.set_yticks(range(len(domains)))
    ax.set_yticklabels([DOMAIN_NAMES[d] for d in domains], fontsize=9.5, color=str(theme["ink_secondary"]))
    ax.spines["bottom"].set_visible(False)
    before_colour, after_colour = str(theme["shade_before"]), str(theme["shade_after"])
    for row, domain in enumerate(domains):
        stats = by_domain[domain]
        n_attack = int(stats["n_attack"])
        blocked = round(float(stats["abr"]) * n_attack)
        before = 100.0 * PUBLISHED_RING0_ABR_PER_DOMAIN
        after = 100.0 * blocked / n_attack
        if after < before:
            ax.plot([after, before], [row, row], color=before_colour, linewidth=2.0, solid_capstyle="round", zorder=2)
        ax.scatter([before], [row], s=64, color=before_colour, edgecolors=str(theme["surface"]), linewidths=2.0, zorder=3)
        ax.scatter([after], [row], s=64, color=after_colour, edgecolors=str(theme["surface"]), linewidths=2.0, zorder=4)
        ax.text(102.3, row, f"{blocked}/{n_attack}", ha="left", va="center", fontsize=9, color=str(theme["ink"]), clip_on=False)
    _title(
        fig,
        theme,
        "Ring 0 attack block rate per domain: published and corrected",
        "The axis starts at 70%. Counts on the right are attacks blocked in the corrected run.",
    )
    _legend(fig, theme, [(before_colour, "Published (100% in every domain)"), (after_colour, "Corrected")], y=0.79)
    return fig


def _decision_counts(results: Mapping[str, object]) -> Dict[str, int]:
    counts = {key: 0 for key, _ in DECISION_LABELS}
    verdicts = results["verdicts"]
    assert isinstance(verdicts, list)
    for verdict in verdicts:
        if verdict["regime"] != "activesec_ring0" or verdict["kind"] != "attack":
            continue
        reason = str(verdict["reason"])
        if not verdict["blocked"]:
            counts["not_blocked"] += 1
        elif "ArchiveFixtureAdapter" in reason:
            counts["archive_marker"] += 1
        elif reason.startswith("ring0_block:SandboxGuard:") and reason.split(":")[2] in ADAPTER_CHECK_SUFFIXES:
            counts["adapter_check"] += 1
        else:
            counts["real"] += 1
    return counts


def figure_decisions(results: Mapping[str, object], theme: Mapping[str, object]) -> Figure:
    """Two stacked bars on one axis: how the 132 attack verdicts are reached, before and after."""
    after = _decision_counts(results)
    rows: List[Tuple[str, Mapping[str, int]]] = [("Before the fixes", DECISIONS_BEFORE), ("After the fixes", after)]
    colours = theme["categorical"]
    on_fill = theme["label_on_fill"]
    assert isinstance(colours, list) and isinstance(on_fill, list)
    fig, ax = _new_figure(theme, width=7.8, height=3.5)
    fig.subplots_adjust(left=0.17, right=0.965, top=0.52, bottom=0.17)
    total = sum(DECISIONS_BEFORE.values())
    ax.set_xlim(0.0, float(total))
    ax.set_ylim(-0.6, len(rows) - 0.4)
    ax.invert_yaxis()
    ax.set_xticks([0, 33, 66, 99, 132])
    ax.xaxis.grid(True, color=str(theme["grid"]), linewidth=1.0)
    ax.set_axisbelow(True)
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([name for name, _ in rows], fontsize=9.5, color=str(theme["ink_secondary"]))
    ax.set_xlabel("Attack fixtures (132 in total)", fontsize=9, color=str(theme["ink_muted"]))
    dx, dy = _data_per_point(ax)
    thickness = 22.0 * dy
    gap = 2.0 * dx
    for row, (_, counts) in enumerate(rows):
        left = 0.0
        for idx, (key, _label) in enumerate(DECISION_LABELS):
            value = float(counts[key])
            if value <= 0:
                continue
            width = max(value - gap, 0.0)
            ax.add_patch(plt.Rectangle((left, row - thickness / 2.0), width, thickness, facecolor=str(colours[idx]), edgecolor="none", zorder=3))
            if value >= 7:
                ax.text(left + width / 2.0, row, f"{int(value)}", ha="center", va="center", fontsize=9, color=str(on_fill[idx]), zorder=4)
            left += value
    _title(
        fig,
        theme,
        "How the Ring 0 regime reaches its 132 attack verdicts",
        "Before: 9 verdicts came from the fixture's own label or were forced after a real guard accepted. After: none.",
    )
    half = (len(DECISION_LABELS) + 1) // 2
    entries = [(str(colours[i]), label) for i, (_, label) in enumerate(DECISION_LABELS)]
    _legend(fig, theme, entries[:half], y=0.715)
    _legend(fig, theme, entries[half:], y=0.625)
    return fig


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Render the audit report figures from the benchmark results")
    parser.add_argument("--results", type=Path, default=REPO_ROOT / "results" / "lotlimmune_benchmark.json")
    parser.add_argument("--out-dir", type=Path, default=REPO_ROOT / "docs" / "audit_figures")
    parser.add_argument("--preview-dir", type=Path, default=None, help="Also write PNG previews to this directory")
    args = parser.parse_args(list(argv) if argv is not None else None)

    plt.rcParams["font.family"] = "sans-serif"
    plt.rcParams["font.sans-serif"] = ["Inter", "Segoe UI", "Helvetica Neue", "Arial", "DejaVu Sans"]
    plt.rcParams["svg.hashsalt"] = "activesec-audit-figures"

    results = json.loads(args.results.read_text(encoding="utf-8"))
    builders = (
        ("ring0_regimes", figure_regimes),
        ("ring0_domains", figure_domains),
        ("ring0_decision_sources", figure_decisions),
        ("trajectory_regimes", figure_trajectories),
    )
    for theme_name, theme in THEMES.items():
        for name, build in builders:
            _save(build(results, theme), args.out_dir, name, theme_name, args.preview_dir)
            print(f"wrote {args.out_dir / f'{name}_{theme_name}.svg'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
