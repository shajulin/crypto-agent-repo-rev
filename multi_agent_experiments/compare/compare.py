import sys
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from shared import evidence as ev_mod, task                       
from own_framework import agent_runtime                            
from crewai_framework import crew                                  


def fmt_ms(value_ms):
    if abs(value_ms) < 1e-12:
        return "0.00 us"
    return "%.2f ms" % value_ms


def _write_markdown(path, lines):
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _load_akka(ref_risk):
    p = ROOT / "akka_framework" / "akka_result.json"
    if not p.exists():
        return None
    data = json.loads(p.read_text(encoding="utf-8"))
    reports = data.get("reports", {})
    per, mean = task.score_all(reports, ref_risk)
    meta = data.get("meta", {"framework": "akka"})
    meta["mean_score"] = mean
    return reports, meta, per


def main():
    print("[compare] building shared evidence (Modules 1-3) ...")
    evidence, ref = ev_mod.build_evidence()
    ref_risk = ref["risk"]

    rows = []
    device_scores = {}

                         
    reports, meta = agent_runtime.run(evidence)
    per, mean = task.score_all(reports, ref_risk)
    rows.append(("Own (ours)", meta, mean))
    device_scores["Own (ours)"] = {d: per[d]["overall"] for d in per}

                           
    reports_c, meta_c = crew.run(evidence)
    per_c, mean_c = task.score_all(reports_c, ref_risk)
    rows.append(("CrewAI", meta_c, mean_c))
    device_scores["CrewAI"] = {d: per_c[d]["overall"] for d in per_c}

                                                 
    akka = _load_akka(ref_risk)
    if akka:
        rows.append(("Akka.io", akka[1], akka[1]["mean_score"]))
        device_scores["Akka.io"] = {d: akka[2][d]["overall"] for d in akka[2]}

                     
    print("\n" + "=" * 92)
    print(" MULTI-AGENT FRAMEWORK COMPARISON (same task, same evidence, %d devices)"
          % len(evidence))
    print("=" * 92)
    hdr = ("framework", "task_score", "llm", "tools", "autonomy", "memory",
           "multi_agent", "jvm_free", "latency_ms")
    print("%-12s %-10s %-4s %-6s %-9s %-7s %-11s %-9s %-10s" % hdr)
    print("-" * 92)
    for name, meta, score in rows:
        f = meta.get("features", {})
        print("%-12s %-10.3f %-4s %-6s %-9s %-7s %-11s %-9s %-10s" % (
            name, score,
            _b(f.get("llm")), _b(f.get("tools")), _b(f.get("autonomy")),
            _b(f.get("memory")), _b(f.get("multi_agent")), _b(f.get("jvm_free")),
            meta.get("total_latency_ms", "n/a")))
    if not akka:
        print("\n(Akka.io not run yet — build & run the Scala project, then re-run compare.)")

    out = {"frameworks": [{"name": n, "task_score": s,
                           "meta": {k: v for k, v in m.items() if k != "trace"}}
                          for n, m, s in rows]}
    (HERE / "comparison.json").write_text(json.dumps(out, indent=2, default=str),
                                          encoding="utf-8")
    print("\n[compare] wrote", HERE / "comparison.json")

    write_comparison_tables(rows, device_scores, ref_risk)
    print("[compare] wrote", HERE / "comparison.md")

    fig_comparison(rows)
    print("[compare] wrote", HERE / "fig_multiagent_comparison.png")


FEATURES = ["llm", "tools", "autonomy", "memory", "multi_agent", "jvm_free"]


def fig_comparison(rows):
    names = [n for n, _, _ in rows]
    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(16, 4.8))
    colors = {"Own (ours)": "#c0392b", "CrewAI": "#3b6ea5", "Akka.io": "#4c9a6a"}
    cols = [colors.get(n, "#888888") for n in names]

                         
    scores = [s for _, _, s in rows]
    ax1.bar(names, scores, color=cols)
    ax1.set_ylim(0, 1.08); ax1.set_ylabel("task score vs reference")
    ax1.set_title("Task accuracy (offline fallback\n= deterministic, so tied)")
    for i, s in enumerate(scores):
        ax1.text(i, s, "%.2f" % s, ha="center", va="bottom", fontsize=9)

                                                     
    grid = np.array([[1 if rows[j][1].get("features", {}).get(f) else 0
                      for f in FEATURES] for j in range(len(rows))])
    ax2.imshow(grid, cmap="RdYlGn", vmin=0, vmax=1, aspect="auto")
    ax2.set_xticks(range(len(FEATURES)))
    ax2.set_xticklabels(FEATURES, rotation=40, ha="right", fontsize=8)
    ax2.set_yticks(range(len(names))); ax2.set_yticklabels(names)
    for j in range(len(names)):
        for k in range(len(FEATURES)):
            ax2.text(k, j, "Y" if grid[j, k] else "N", ha="center", va="center",
                     fontsize=9, fontweight="bold")
    ax2.set_title("Capability matrix (agentic features)")

                      
    lat = [rows[j][1].get("total_latency_ms") or 0 for j in range(len(rows))]
    ax3.bar(names, lat, color=cols)
    ax3.set_ylabel("total latency (ms)")
    ax3.set_title("Runtime latency (offline)")
    for i, v in enumerate(lat):
        ax3.text(i, v, fmt_ms(v), ha="center", va="bottom", fontsize=9)

    fig.suptitle("Multi-Agent Framework Comparison — CrewAI vs Akka.io vs Ours "
                 "(same task, same evidence)", fontsize=12)
    fig.tight_layout(rect=[0, 0, 1, 0.95])
    fig.savefig(HERE / "fig_multiagent_comparison.png", dpi=140)
    plt.close(fig)


def write_comparison_tables(rows, device_scores, ref_risk):
    lines = ["# Multi-Agent Framework Comparison", ""]
    lines.append("## Framework summary")
    lines.append("| framework | task_score | total_latency | per_device_latency | concurrency | tool_autonomy | llm_native | memory |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for name, meta, score in rows:
        features = meta.get("features", {})
        lines.append("| %s | %.3f | %s | %s | %s | %s | %s | %s |" % (
            name, score, fmt_ms(meta.get("total_latency_ms") or 0),
            fmt_ms(meta.get("per_device_latency_ms") or 0),
            _b(features.get("concurrency")), _b(features.get("tool_autonomy")),
            _b(features.get("llm_native")), features.get("memory", "?")))

    lines.append("")
    lines.append("## Per-device task scores")
    names = [n for n, _, _ in rows]
    lines.append("| device | " + " | ".join(names) + " |")
    lines.append("|---|" + "---|" * len(names))
    for dev_id in sorted(ref_risk.keys()):
        per_scores = ["%.3f" % device_scores.get(name, {}).get(dev_id, float("nan"))
                      if dev_id in device_scores.get(name, {}) else "n/a"
                      for name in names]
        lines.append("| %s | %s |" % (dev_id, " | ".join(per_scores)))

    lines.append("")
    lines.append("## Feature matrix")
    lines.append("| criterion | " + " | ".join(names) + " |")
    lines.append("|---|" + "---|" * len(names))
    features_order = ["llm", "tools", "autonomy", "memory", "multi_agent", "jvm_free"]
    for crit in features_order:
        row = [crit]
        for name, meta, _ in rows:
            feat = meta.get("features", {})
            row.append(str(feat.get(crit, "—")))
        lines.append("| " + " | ".join(row) + " |")

    lines.append("")
    lines.append("## Performance notes")
    fastest = min(rows, key=lambda r: r[1].get("total_latency_ms") or 0)
    highest = max(rows, key=lambda r: r[2])
    lines.append("- fastest execution: %s (%s)" % (fastest[0], fmt_ms(fastest[1].get("total_latency_ms") or 0)))
    lines.append("- highest task score: %s (%.3f)" % (highest[0], highest[2]))

    _write_markdown(HERE / "comparison.md", lines)


def _b(v):
    return "yes" if v else ("no" if v is False else "?")


if __name__ == "__main__":
    main()
