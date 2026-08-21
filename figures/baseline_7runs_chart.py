from __future__ import annotations

import sys
import statistics as st
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
from common import figtheme              

OUT = _ROOT / "results" / "baseline_7runs" / "images" / "baseline_7runs_comparison.png"

RUNS = [1, 2, 3, 4, 5, 6, 7]
ACC = [76.0, 80.0, 60.0, 80.0, 60.0, 60.0, 60.0]
N = [25, 50, 50, 50, 50, 50, 50]


def render():
    figtheme.apply()
    fig, ax = plt.subplots(figsize=(9, 5))
    colors = [figtheme.PALETTE["warn"] if n != 50 else figtheme.PALETTE["accent"] for n in N]
    bars = ax.bar([str(r) for r in RUNS], ACC, color=colors,
                  edgecolor=figtheme.GRID, linewidth=0.5)
    for b, a, n in zip(bars, ACC, N):
        ax.text(b.get_x() + b.get_width() / 2, a + 1.5, "%.0f%%\n(N=%d)" % (a, n),
                ha="center", va="bottom", fontsize=8, color=figtheme.FG)

    mean_all = st.mean(ACC)
    mean_n50 = st.mean([a for a, n in zip(ACC, N) if n == 50])
    ax.axhline(mean_all, color=figtheme.PALETTE["muted"], linestyle="--", linewidth=1,
              label="mean, all 7 runs = %.1f%%" % mean_all)
    ax.axhline(mean_n50, color=figtheme.PALETTE["ok"], linestyle=":", linewidth=1.3,
              label="mean, N=50 runs only (2-7) = %.1f%%" % mean_n50)

    ax.set_ylim(0, 100)
    ax.set_xlabel("independent run # (separate process launches, identical code/settings)")
    ax.set_ylabel("accuracy (%)")
    ax.set_title("\"Ours\" + llama3.2:3b deterministic baseline: 7 independent launches\n"
                "orange = N=25 (5 trials), blue = N=50 (10 trials) -- real variance, not selected")
    ax.legend(loc="upper right", fontsize=8)
    fig.tight_layout()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT, dpi=140); plt.close(fig)
    print("wrote", OUT)


if __name__ == "__main__":
    render()
