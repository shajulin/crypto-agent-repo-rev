import os
import csv
import json
import time
from pathlib import Path

import docker
import requests

DATA_DIR = Path("/app/data")
AGG = os.environ.get("AGGREGATOR_URL", "http://aggregator:8000")
SAMPLES = int(os.environ.get("MONITOR_SAMPLES", "12"))
INTERVAL = int(os.environ.get("MONITOR_INTERVAL", "5"))
PROJECT = os.environ.get("MONITOR_PROJECT_PREFIX", "")                          


def _cpu_percent(stats):
    try:
        cpu = stats["cpu_stats"]; pre = stats["precpu_stats"]
        cd = cpu["cpu_usage"]["total_usage"] - pre["cpu_usage"]["total_usage"]
        sd = cpu["system_cpu_usage"] - pre.get("system_cpu_usage", 0)
        ncpu = cpu.get("online_cpus") or len(cpu["cpu_usage"].get("percpu_usage") or [1])
        if sd > 0 and cd > 0:
            return round((cd / sd) * ncpu * 100.0, 2)
    except Exception:                                              
        pass
    return 0.0


def _mem_mb(stats):
    try:
        return round(stats["memory_stats"]["usage"] / 1e6, 1)
    except Exception:                                              
        return 0.0


def _make_figure(resources, devices, agents):
    try:
        import sys
        sys.path.insert(0, "/app")
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from common import figtheme
        figtheme.apply()
        P = figtheme.PALETTE
    except Exception as e:                                          
        print("[monitor] figure skipped: %s" % e, flush=True)
        return
    fig, (a1, a2, a3) = plt.subplots(1, 3, figsize=(17, 5.5))

    names = sorted(resources, key=lambda n: resources[n]["mem_mean_mb"])
    a1.barh(names, [resources[n]["mem_mean_mb"] for n in names], color=P["purple"])
    a1.set_xlabel("mean memory (MB)"); a1.set_title("Memory per container")
    a1.tick_params(labelsize=7)

    dv = sorted(devices)
    a2.bar(dv, [devices[d].get("compute_ms") or 0 for d in dv], color=P["accent"])
    a2.set_ylabel("ms"); a2.set_title("Module-1 compute time per device")
    a2.tick_params(axis="x", rotation=30, labelsize=8)

    ag = sorted(agents, key=lambda n: agents[n]["compute_ms"])
    vals = [max(agents[n]["compute_ms"], 0.01) for n in ag]                
    colors = [P["llm"] if "xai" in n else P["problem"] for n in ag]
    a3.barh(ag, vals, color=colors)
    a3.set_xscale("log")                                               
    a3.set_xlabel("compute (ms, log scale)")
    a3.set_title("Agent compute time\n(xai = local LLM; others are rule/crypto)")
    a3.tick_params(labelsize=7)
    for i, v in enumerate(vals):
        a3.text(v, i, " %.0f" % v, va="center", fontsize=6)

    fig.suptitle("Monitor — real time + memory per container / device / agent",
                 fontsize=13)
    fig.tight_layout(rect=[0, 0, 1, 0.96])
    fig.savefig(DATA_DIR / "fig_monitor_system.png", dpi=140)
    plt.close(fig)
    print("[monitor] wrote fig_monitor_system.png", flush=True)


def main():
    DATA_DIR.mkdir(exist_ok=True)
    client = docker.from_env()
    agg = {}                                         

                                                                             
                                                                          
    done_marker = DATA_DIR / "agents" / "own" / "final_report.json"
    max_samples = int(os.environ.get("MONITOR_MAX_SAMPLES", "120"))
    print("[monitor] sampling every %ds until the pipeline completes ..." % INTERVAL,
          flush=True)
    i = 0
    while i < max_samples:
        for c in client.containers.list():
            if PROJECT and PROJECT not in c.name:
                continue
            try:
                s = c.stats(stream=False)
            except Exception:                                      
                continue
            agg.setdefault(c.name, []).append((_cpu_percent(s), _mem_mb(s)))
        i += 1
                                                              
        if done_marker.exists() and i >= SAMPLES:
            print("[monitor] pipeline complete, finishing after %d samples" % i, flush=True)
            break
        time.sleep(INTERVAL)

                                    
    resources = {}
    for name, seq in agg.items():
        cpus = [x[0] for x in seq]; mems = [x[1] for x in seq]
        resources[name] = {
            "samples": len(seq),
            "mem_mean_mb": round(sum(mems) / len(mems), 1) if mems else 0,
            "mem_peak_mb": max(mems) if mems else 0,
            "cpu_mean_pct": round(sum(cpus) / len(cpus), 2) if cpus else 0,
            "cpu_peak_pct": max(cpus) if cpus else 0,
        }

                                                          
    devices = {}
    try:
        data = requests.get(AGG + "/devices", timeout=10).json()
        for dev_id, blob in data.items():
            m = blob["meta"]
            devices[dev_id] = {"compute_ms": m.get("compute_ms"),
                               "self_rss_mb": m.get("memory_rss_mb"),
                               "device_type": m.get("device_type")}
    except Exception as e:                                         
        print("[monitor] could not reach aggregator: %s" % e, flush=True)

                                                                 
    agents = {}
    agents_dir = DATA_DIR / "agents"
    if agents_dir.exists():
        for fwdir in agents_dir.iterdir():
            if not fwdir.is_dir():
                continue
            for jf in fwdir.glob("*.json"):
                try:
                    meta = json.loads(jf.read_text(encoding="utf-8")).get("_meta")
                    if meta and "compute_ms" in meta:
                        agents["%s/%s" % (fwdir.name, meta.get("agent", jf.stem))] = {
                            "compute_ms": meta["compute_ms"],
                            "memory_rss_mb": meta.get("memory_rss_mb")}
                except Exception:                                  
                    continue

    report = {"generated_at": time.time(), "resources": resources,
              "devices": devices, "agents": agents}
    (DATA_DIR / "monitor_report.json").write_text(
        json.dumps(report, indent=2, default=str), encoding="utf-8")
    _make_figure(resources, devices, agents)
    with open(DATA_DIR / "monitor_report.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["container", "samples", "mem_mean_mb", "mem_peak_mb",
                    "cpu_mean_pct", "cpu_peak_pct"])
        for name, r in sorted(resources.items()):
            w.writerow([name, r["samples"], r["mem_mean_mb"], r["mem_peak_mb"],
                        r["cpu_mean_pct"], r["cpu_peak_pct"]])
    print("[monitor] wrote monitor_report.json/.csv | containers=%d devices=%d"
          % (len(resources), len(devices)), flush=True)
                                            
    time.sleep(5)


if __name__ == "__main__":
    main()
