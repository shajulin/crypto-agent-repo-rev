from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np

import sys
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
from common import figtheme                                                

DATA = _ROOT / "data"
AGENTS = DATA / "agents" / "own"
OUT = _ROOT / "results" / "phase2"
_PAL = figtheme.PALETTE


def _load(name: str) -> dict:
    p = AGENTS / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def _load_local(name: str) -> dict:
    p = OUT / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def _dsort(devs):
    def key(d):
        num = "".join(c for c in d if c.isdigit())
        return (int(num) if num else 0, d)
    return sorted(devs, key=key)


                                                                                
def fig_agent_times():
    files = [("config", "config.json"), ("crypto", "crypto.json"),
             ("threat", "threat.json"), ("xai", "xai.json"),
             ("kg", "kg.json"), ("recommend", "recommendations.json")]
    names, times, mems = [], [], []
    for label, fn in files:
        meta = _load(fn).get("_meta", {})
        if not meta:
            continue
        names.append(label)
        times.append(max(meta.get("compute_ms", 0.0), 1e-3))
        mems.append(meta.get("memory_rss_mb", 0.0))
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 4.6))
    ax1.bar(names, times, color=_PAL["accent"])
    ax1.set_yscale("log"); ax1.set_ylabel("compute time (ms, log)")
    ax1.set_title("Phase 2 — time to finish per agent")
    for i, v in enumerate(times):
        ax1.text(i, v, _fmt_ms(v), ha="center", va="bottom", fontsize=7, color=figtheme.FG)
    ax2.bar(names, mems, color=_PAL["purple"])
    ax2.set_ylabel("memory RSS (MB)"); ax2.set_title("Phase 2 — memory per agent")
    for i, v in enumerate(mems):
        ax2.text(i, v, "%.0f" % v, ha="center", va="bottom", fontsize=7, color=figtheme.FG)
    for ax in (ax1, ax2):
        ax.tick_params(axis="x", rotation=30, labelsize=8)
    fig.tight_layout(); fig.savefig(OUT / "phase2_agent_times.png", dpi=140); plt.close(fig)


def _fmt_ms(ms):
    return "%.2fs" % (ms / 1000.0) if ms >= 1000 else "%.2fms" % ms


                                                                                
def fig_threat_attacks():
    ar = _load("threat.json").get("attack_results", {})
    per = ar.get("per_device", {})
    if not per:
        return
                                                                       
    all_devs = _dsort(ar.get("all_devices") or list(per))
    targeted = set(ar.get("targeted_devices") or list(per))
    attacks = [a["attack"] for a in next(iter(per.values()))["attacks"]]
                                             
    M = np.full((len(attacks), len(all_devs)), -1.0)
    for j, d in enumerate(all_devs):
        if d in per:
            for i, a in enumerate(per[d]["attacks"]):
                M[i, j] = 1.0 if a.get("success") else 0.0
    from matplotlib.colors import ListedColormap
    cmap = ListedColormap(["#3a3d4a", figtheme.PALETTE["ok"], figtheme.PALETTE["problem"]])
    fig, ax = plt.subplots(figsize=(0.55 * len(all_devs) + 4, 0.6 * len(attacks) + 2))
    ax.imshow(M, aspect="auto", cmap=cmap, vmin=-1, vmax=1)
    ax.set_xticks(range(len(all_devs)))
    ax.set_xticklabels(all_devs, fontsize=7, rotation=45, ha="right")
    ax.set_yticks(range(len(attacks)))
    ax.set_yticklabels([a.replace("_", " ") for a in attacks], fontsize=8)
    for i in range(len(attacks)):
        for j, d in enumerate(all_devs):
            if M[i, j] < 0:
                sym, col = "–", figtheme.PALETTE["muted"]
            else:
                sym, col = ("✓", "#0b1020") if M[i, j] else ("·", figtheme.FG)
            ax.text(j, i, sym, ha="center", va="center", color=col, fontsize=10)
    ax.set_title("Phase 2 — Threat agent: %d of %d devices targeted "
                 "(✓ succeeded · failed · – not targeted)"
                 % (len(targeted), len(all_devs)))
    ax.grid(False)
    fig.tight_layout(); fig.savefig(OUT / "phase2_threat_attacks.png", dpi=140); plt.close(fig)


                                                                                
def fig_kg_trees():
    kg = {k: v for k, v in _load("kg.json").items() if k != "_meta"}
    for dev, g in kg.items():
        chain = g.get("chain", [])
        if not chain:
            continue
        G = nx.DiGraph(); G.add_edges_from(g.get("edges", []))
        pos = {n: (0, -i) for i, n in enumerate(chain)}
        status = g.get("node_status", {}); root = g.get("root_cause_node")
        face = [_PAL["problem"] if status.get(n) == "problem" else _PAL["ok"] for n in chain]
        edge = ["#ffffff" if n == root else figtheme.GRID for n in chain]
        lw = [3.5 if n == root else 1.0 for n in chain]
        fig, ax = plt.subplots(figsize=(7, 9))
        nx.draw_networkx_edges(G, pos, ax=ax, arrows=True, arrowstyle="-|>",
                               arrowsize=20, edge_color="#555", width=1.4)
        nx.draw_networkx_nodes(G, pos, ax=ax, nodelist=chain, node_color=face,
                               edgecolors=edge, linewidths=lw, node_size=3400)
        for n, (x, y) in pos.items():
            ax.text(x, y, n.replace(" ", "\n"), ha="center", va="center",
                    fontsize=8, color="white", fontweight="bold")
            ax.text(x - 0.18, y, str(g.get("values", {}).get(n, "")), ha="right",
                    va="center", fontsize=8, color=figtheme.FG)
            if n == root:
                ax.annotate("⚠ ROOT CAUSE", xy=(x + 0.06, y), xytext=(0.35, y),
                            fontsize=10, color=_PAL["problem"], fontweight="bold",
                            va="center", arrowprops=dict(arrowstyle="->",
                            color=_PAL["problem"], lw=2))
        ax.set_title("Phase 2 — Knowledge-Graph tree · %s (risk=%.2f)"
                     % (dev, g.get("risk", 0.0)), fontsize=10)
        ax.set_xlim(-1.0, 0.7); ax.axis("off")
        fig.tight_layout(); fig.savefig(OUT / ("phase2_kg_%s.png" % dev), dpi=140)
        plt.close(fig)


                                                                                
def fig_xai():
    agents = _load("xai.json").get("agents", {})
    devs = _dsort([d for d in agents if isinstance(agents[d], dict) and "xai" in agents[d]])
    if not devs:
        return
    feats = list(next(iter(agents.values()))["xai"]["feature_values"])
    M = np.zeros((len(feats), len(devs)))
    best = {}
    for j, d in enumerate(devs):
        xai = agents[d]["xai"]
        best[d] = xai.get("best_method", "?")
        attr = xai.get("best_attribution", {})
        for i, f in enumerate(feats):
            M[i, j] = attr.get(f, 0.0)
    vmax = max(abs(M).max(), 1e-6)
    fig, ax = plt.subplots(figsize=(max(8, 0.5 * len(devs) + 4), 5.2))
    im = ax.imshow(M, aspect="auto", cmap="RdBu_r", vmin=-vmax, vmax=vmax)
    ax.set_xticks(range(len(devs)))
    ax.set_xticklabels(["%s\n%s" % (d, best[d]) for d in devs], fontsize=7)
    ax.set_yticks(range(len(feats))); ax.set_yticklabels(feats, fontsize=8)
    ax.set_title("Phase 2 — XAI best-method feature attribution (features × devices)")
    fig.colorbar(im, ax=ax, shrink=0.8, label="attribution (risk share)")
    ax.grid(False)
    fig.tight_layout(); fig.savefig(OUT / "phase2_xai.png", dpi=140); plt.close(fig)


                                                                                
def fig_recommend():
    per = _load("recommendations.json").get("per_device", {})
    if not per:
        return
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    cols = {"CRITICAL": _PAL["problem"], "HIGH": _PAL["warn"],
            "MEDIUM": _PAL["accent"], "LOW": _PAL["ok"]}
    devs = _dsort(per)
    counts = {p: [sum(1 for r in per[d]["recommendations"] if r.get("priority") == p)
                  for d in devs] for p in order}
    fig, ax = plt.subplots(figsize=(max(7, 1.1 * len(devs) + 3), 4.4))
    bottom = np.zeros(len(devs))
    for p in order:
        ax.bar(devs, counts[p], bottom=bottom, label=p, color=cols[p])
        bottom += np.array(counts[p])
    ax.set_ylabel("# recommendations")
    ax.set_title("Phase 2 — Recommendation agent: fixes per device by priority")
    ax.legend(fontsize=8)
    for i, d in enumerate(devs):
        ax.text(i, bottom[i], "risk %.2f" % per[d].get("risk", 0.0),
                ha="center", va="bottom", fontsize=7, color=figtheme.FG)
    fig.tight_layout(); fig.savefig(OUT / "phase2_recommend.png", dpi=140); plt.close(fig)


                                                                                
def fig_monitor():
    agents = json.loads((DATA / "monitor_report.json").read_text("utf-8")).get("agents", {}) \
        if (DATA / "monitor_report.json").exists() else {}
    if not agents:
        return
    names = list(agents)
    times = [max(agents[a].get("compute_ms", 0.0), 1e-3) for a in names]
    mems = [agents[a].get("memory_rss_mb", 0.0) for a in names]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 4.8))
    ax1.barh(names, times, color=_PAL["llm"]); ax1.set_xscale("log")
    ax1.set_xlabel("compute time (ms, log)")
    ax1.set_title("Monitor — time per agent/container")
    ax2.barh(names, mems, color=_PAL["purple"]); ax2.set_xlabel("memory RSS (MB)")
    ax2.set_title("Monitor — memory per agent/container")
    fig.tight_layout(); fig.savefig(OUT / "phase2_monitor.png", dpi=140); plt.close(fig)


                                                                                
def fig_frameworks(n_devices: int = 5):
    fc = _load("framework_comparison.json")
    rows = fc.get("rows", [])
    if not rows:
        return
    fw = [r["framework"] for r in rows]
    def num(v):
        return float(v) if isinstance(v, (int, float)) else np.nan
    def _lat(r):
                                                                                
        if r["framework"] == "akka":
            am = DATA / "frameworks" / "akka_mem.json"
            if am.exists():
                try:
                    v = json.loads(am.read_text("utf-8")).get("latency_ms")
                    if v and float(v) > 0:
                        return float(v)
                except (ValueError, OSError):
                    pass
        v = num(r.get("latency_ms"))
        return v if (v == v and v > 0) else np.nan
    latency = [_lat(r) for r in rows]
    per_dev = [l / n_devices if l == l else np.nan for l in latency]
    cap = [num(r.get("capability_coverage")) for r in rows]
                                                                                   
    seeds = _load_local("framework_seeds.json").get("aggregate", {})
    if seeds:
        overall = [seeds.get(f, {}).get("quality_mean", num(r.get("overall")))
                   for f, r in zip(fw, rows)]
        qstd = [seeds.get(f, {}).get("quality_std", 0.0) for f in fw]
        n_seeds = _load_local("framework_seeds.json").get("seeds", 1)
    else:
        overall = [num(r.get("overall")) for r in rows]
        qstd = [num(r.get("task_quality_std", 0.0)) for r in rows]
        n_seeds = 1
                                                                 
    res = json.loads((DATA / "monitor_report.json").read_text("utf-8")).get("resources", {}) \
        if (DATA / "monitor_report.json").exists() else {}
    _mem_ctr = {"own": "distributed-agent-compare-1", "crewai": "distributed-crewai-1",
                "akka": "distributed-akka-1"}
    _row_by_fw = {r["framework"]: r for r in rows}

    def _mem(f):
                                                                                   
                                                                                  
        r = _row_by_fw.get(f, {})
        v = r.get("peak_memory_mb")
        if isinstance(v, (int, float)) and v > 0:
            return float(v)
        if f == "akka":
            p = DATA / "frameworks" / "akka_mem.json"
            if p.exists():
                try:
                    b = json.loads(p.read_text("utf-8")).get("peak_bytes", 0)
                    if b:
                        return round(b / 1e6, 1)
                except (ValueError, TypeError):
                    pass
        v = res.get(_mem_ctr.get(f, ""), {}).get("mem_peak_mb", np.nan)
        return v if v else np.nan
    mem = [_mem(f) for f in fw]

    fig, axes = plt.subplots(1, 5, figsize=(19, 4.8), constrained_layout=True)
    qtitle = ("raw LLM tier accuracy\n(mean±std, %d seeds)" % n_seeds) if n_seeds > 1 \
        else "raw LLM tier accuracy"
    panels = [("total latency (s)", [l / 1000 for l in latency], _PAL["accent"], None),
              ("per-device time (s)", [p / 1000 for p in per_dev], _PAL["warn"], None),
              ("peak memory (MB)", mem, _PAL["purple"], None),
              ("capability coverage", cap, _PAL["llm"], None),
              (qtitle, overall, _PAL["ok"], qstd)]
    def _ok(v):
        return v is not None and v == v                                  
    for ax, (title, vals, col, err) in zip(axes, panels):
        plotv = [v if _ok(v) else 0 for v in vals]
        yerr = [e if _ok(v) else 0 for v, e in zip(vals, err)] if err else None
        ax.bar(fw, plotv, color=col, yerr=yerr, capsize=5,
               error_kw={"ecolor": figtheme.FG})
        top = max([(v + (err[i] if err and _ok(err[i]) else 0))
                   for i, v in enumerate(vals) if _ok(v)], default=1)
        ax.set_ylim(0, top * 1.18)
        for i, v in enumerate(vals):
            ax.text(i, plotv[i], ("%.2f" % v) if _ok(v) else "n/a", ha="center",
                    va="bottom", fontsize=8, color=figtheme.FG)
        ax.set_title(title, fontsize=10); ax.tick_params(axis="x", labelsize=8)
    fig.suptitle("Phase 2 — 3-framework comparison (Own / CrewAI / Akka), "
                 "%d devices per cycle · quality = task performance only "
                 "(capabilities shown separately)" % n_devices)
    fig.savefig(OUT / "phase2_frameworks.png", dpi=140); plt.close(fig)


def _device_count() -> int:
    ar = _load("threat.json").get("attack_results", {})
    if ar.get("all_devices"):
        return len(ar["all_devices"])
    per = _load("recommendations.json").get("per_device", {})
    return len(per) or 5


def render(n_devices: int | None = None):
    if n_devices is None:
        n_devices = _device_count()
    OUT.mkdir(parents=True, exist_ok=True)
    figtheme.apply()
    for fn in (fig_agent_times, fig_threat_attacks, fig_kg_trees, fig_xai,
               fig_recommend, fig_monitor):
        try:
            fn()
        except Exception as e:                                        
            print("[phase2] %s skipped: %s" % (fn.__name__, e))
    try:
        fig_frameworks(n_devices)
    except Exception as e:                                            
        print("[phase2] fig_frameworks skipped:", e)
    print("[phase2] wrote figures to", OUT)


if __name__ == "__main__":
    render()
