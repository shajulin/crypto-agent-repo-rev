from __future__ import annotations

import csv
import statistics as st
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
from common import figtheme                                                

RESULTS = _ROOT / "results"
_PAL = figtheme.PALETTE
_SERIES = figtheme.SERIES

METHODS = ["SHAP", "LIME", "Grad-CFA", "FairXAI", "Latent-CF"]
DEVICES = ["dev1", "dev2", "dev3", "dev4", "dev5"]
FRAMEWORKS = ["own", "akka", "crewai"]
FRAMEWORK_LABEL = {"own": "Ours", "akka": "Akka", "crewai": "CrewAI"}
                                                                           
FRAMEWORK_COLOR = {"own": _PAL["accent"], "akka": _PAL["llm"], "crewai": _PAL["warn"]}


def _read_csv(name):
    path = RESULTS / name
    if not path.exists():
        return []
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def render_xai_reliability():
    rows = _read_csv("xai_trials.csv")
    if not rows:
        print("skip xai_trial_reliability.png: results/xai_trials.csv not found")
        return
    figtheme.apply()
    fig, axes = plt.subplots(1, 5, figsize=(18, 4), sharey=True)
    fig.suptitle("XAI composite score reliability across 10 repeated trials "
                 "(mean ± std, per device)")
    for ax, dev in zip(axes, DEVICES):
        means, stds = [], []
        for m in METHODS:
            vals = [float(r["composite_score"]) for r in rows
                    if r["device"] == dev and r["method"] == m]
            means.append(st.mean(vals) if vals else 0.0)
            stds.append(st.pstdev(vals) if len(vals) > 1 else 0.0)
        x = np.arange(len(METHODS))
        ax.bar(x, means, yerr=stds, capsize=3, color=_SERIES[:len(METHODS)],
              edgecolor=figtheme.GRID, linewidth=0.5)
        ax.set_xticks(x); ax.set_xticklabels(METHODS, rotation=40, ha="right", fontsize=8)
        ax.set_title(dev, fontsize=10)
        ax.set_ylim(0, 1.08)
    axes[0].set_ylabel("composite score")
    fig.tight_layout(rect=(0, 0, 1, 0.93))
    out = RESULTS / "xai_trial_reliability.png"
    fig.savefig(out, dpi=140); plt.close(fig)
    print("wrote", out)


def _framework_stats(fname):
    rows = _read_csv(fname)
    if not rows:
        return None
    sys.path.insert(0, str(_ROOT / "multi_agent_experiments"))
    from shared import llm_eval
    hits = [int(r["accuracy_hit"]) for r in rows if r["accuracy_hit"] not in ("", None)]
    hall = [float(r["hallucination_rate"]) for r in rows]
    correct = [float(r["explanation_correct"]) for r in rows]
    comp_vals = [float(r["compliance_accuracy"]) for r in rows
                if r.get("compliance_accuracy") not in ("", None)]
    cons_by_dev = {}
    for r in rows:
        cons_by_dev.setdefault(r["device"], []).append(
            r["raw_risk_level"] if r["raw_risk_level"] != "unparseable" else None)
    cons_vals = []
    for guesses in cons_by_dev.values():
        c, n = llm_eval.consistency(guesses)
        if c is not None:
            cons_vals.append(c)
    return {
        "n": len(rows),
        "accuracy": (sum(hits) / len(hits)) if hits else 0.0,
        "accuracy_n": len(hits),
        "hallucination": st.mean(hall) if hall else 0.0,
        "correctness": st.mean(correct) if correct else 0.0,
        "consistency": st.mean(cons_vals) if cons_vals else 0.0,
        "compliance_acc": st.mean(comp_vals) if comp_vals else None,                               
    }


def render_framework_comparison():
    stats = {"own": _framework_stats("llm_eval_trials.csv"),
             "akka": _framework_stats("akka_eval_trials.csv"),
             "crewai": _framework_stats("crewai_eval_trials.csv")}
    if not any(stats.values()):
        print("skip framework_llm_comparison.png: no eval trial CSVs found")
        return
    figtheme.apply()
    metrics = [("accuracy", "LLM-Accuracy"), ("hallucination", "Hallucination rate\n(lower=better)"),
               ("correctness", "Explanation\ncorrectness"),
               ("compliance_acc", "Compliance\naccuracy"), ("consistency", "Consistency")]
    fig, ax = plt.subplots(figsize=(10.5, 5))
    n_fw = len(FRAMEWORKS)
    width = 0.8 / n_fw
    x = np.arange(len(metrics))
    for i, fw in enumerate(FRAMEWORKS):
        s = stats.get(fw)
                                                                    
                                                                           
        vals = [(s[m] if s else None) for m, _ in metrics]
        offset = (i - (n_fw - 1) / 2) * width
        n_label = "N=%d" % s["n"] if s else "n/a"
        plot_x = [x[j] + offset for j, v in enumerate(vals) if v is not None]
        plot_vals = [v for v in vals if v is not None]
        bars = ax.bar(plot_x, plot_vals, width, label="%s (%s)" % (FRAMEWORK_LABEL[fw], n_label),
                      color=FRAMEWORK_COLOR[fw], edgecolor=figtheme.GRID, linewidth=0.5)
        for b, v in zip(bars, plot_vals):
            ax.text(b.get_x() + b.get_width() / 2, v + 0.02, "%.2f" % v,
                    ha="center", va="bottom", fontsize=7, color=figtheme.FG)
        for j, v in enumerate(vals):
            if v is None:
                ax.text(x[j] + offset, 0.03, "n/a", ha="center", va="bottom",
                        fontsize=7, color=figtheme.PALETTE["muted"], rotation=90)
    ax.set_xticks(x); ax.set_xticklabels([lbl for _, lbl in metrics])
    ax.set_ylim(0, 1.15)
    ax.set_ylabel("fraction (0-1)")
    ax.set_title("Real local-LLM (llama3.2:3b) evaluation across all 3 frameworks\n"
                "5 devices x 10 repeated trials per framework")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=3, fontsize=9)
    fig.tight_layout()
    out = RESULTS / "framework_llm_comparison.png"
    fig.savefig(out, dpi=140); plt.close(fig)
    print("wrote", out)


MODEL_COLOR = {"llama3.2:3b": _PAL["accent"], "qwen2.5:14b": _PAL["warn"]}


def render_model_comparison():
    files = {
        ("own", "llama3.2:3b"): "llm_eval_trials.csv",
        ("own", "qwen2.5:14b"): "llm_eval_trials_qwen2_5_14b.csv",
        ("akka", "llama3.2:3b"): "akka_eval_trials.csv",
        ("akka", "qwen2.5:14b"): "akka_eval_trials_qwen2_5_14b.csv",
        ("crewai", "llama3.2:3b"): "crewai_eval_trials.csv",
        ("crewai", "qwen2.5:14b"): "crewai_eval_trials_qwen2_5_14b.csv",
    }
    stats = {k: _framework_stats(v) for k, v in files.items()}
    if not any(stats.values()):
        print("skip model_comparison.png: no data found")
        return
    figtheme.apply()
    fig, axes = plt.subplots(1, 2, figsize=(11, 5))
    models = ["llama3.2:3b", "qwen2.5:14b"]
    x = np.arange(len(FRAMEWORKS))
    width = 0.35
    for ax, (metric, title) in zip(axes, [("accuracy", "LLM-Accuracy"),
                                          ("hallucination", "Hallucination rate\n(lower=better)")]):
        for i, model in enumerate(models):
            vals = [stats[(fw, model)][metric] if stats.get((fw, model)) else 0.0 for fw in FRAMEWORKS]
            ns = [stats[(fw, model)]["n"] if stats.get((fw, model)) else 0 for fw in FRAMEWORKS]
            offset = (i - 0.5) * width
            bars = ax.bar(x + offset, vals, width, label=model, color=MODEL_COLOR[model],
                          edgecolor=figtheme.GRID, linewidth=0.5)
            for b, v, n in zip(bars, vals, ns):
                ax.text(b.get_x() + b.get_width() / 2, v + 0.02, "%.2f\n(n=%d)" % (v, n),
                        ha="center", va="bottom", fontsize=6.5, color=figtheme.FG)
        ax.set_xticks(x); ax.set_xticklabels([FRAMEWORK_LABEL[fw] for fw in FRAMEWORKS])
        ax.set_ylim(0, 1.2)
        ax.set_title(title, fontsize=10)
    axes[0].set_ylabel("fraction (0-1)")
    axes[0].legend(loc="upper center", bbox_to_anchor=(1.05, -0.1), ncol=2, fontsize=9)
    fig.suptitle("Model comparison: llama3.2:3b vs qwen2.5:14b per framework\n"
                 "(mixed results -- see NOTES.md for the full 5-metric table + caveats)")
    fig.tight_layout(rect=(0, 0.02, 1, 0.92))
    out = RESULTS / "model_comparison.png"
    fig.savefig(out, dpi=140); plt.close(fig)
    print("wrote", out)


def render():
    render_xai_reliability()
    render_framework_comparison()
    render_model_comparison()


if __name__ == "__main__":
    render()
