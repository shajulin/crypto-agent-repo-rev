from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
DATA = _ROOT / "data"
BASE = "distributed/docker-compose.yml"
OV = "distributed/docker-compose.20.yml"


def _services(n: int):
    devs = ["dev%d" % i for i in range(1, n + 1)]
    return ["mqtt", *devs, "aggregator", "ollama", "crewai", "akka", "agent-compare"]


def _dc(args, files, extra=()):
    fs = []
    for f in files:
        fs += ["-f", f]
    return subprocess.run(["docker", "compose", *fs, *args, *extra],
                          cwd=str(_ROOT), capture_output=True, text=True)


def run_seed(n: int, files) -> dict:
                                           
    for p in (DATA / "frameworks").glob("*.json"):
        p.unlink()
    fc = DATA / "agents" / "own" / "framework_comparison.json"
    if fc.exists():
        fc.unlink()
    _dc(["up", "--build", "-d"], files, tuple(_services(n)))
                                
    deadline = time.time() + 1800
    while time.time() < deadline:
        st = subprocess.run(["docker", "inspect", "-f", "{{.State.Status}}",
                             "distributed-agent-compare-1"], capture_output=True, text=True)
        if st.stdout.strip() == "exited" and fc.exists():
            break
        time.sleep(10)
    rows = json.loads(fc.read_text("utf-8"))["rows"] if fc.exists() else []
                                      
    akka_mem = None
    amp = DATA / "frameworks" / "akka_mem.json"
    if amp.exists():
        try:
            akka_mem = json.loads(amp.read_text("utf-8")).get("peak_bytes")
        except ValueError:
            pass
    _dc(["down"], files)
    return {"rows": rows, "akka_mem_bytes": akka_mem}


def aggregate(seed_results: list) -> dict:
    import statistics as st
    fws = [r["framework"] for r in seed_results[0]["rows"]] if seed_results else []
    out = {}
    for fw in fws:
        qs, lats = [], []
        for sr in seed_results:
            row = next((x for x in sr["rows"] if x["framework"] == fw), None)
            if not row:
                continue
            ov = row.get("overall")
            if isinstance(ov, (int, float)):
                qs.append(float(ov))
            lv = row.get("latency_ms")
            if isinstance(lv, (int, float)):
                lats.append(float(lv))
        out[fw] = {
            "quality_mean": round(st.mean(qs), 3) if qs else None,                     
            "quality_std": round(st.pstdev(qs), 3) if len(qs) > 1 else 0.0,
            "latency_ms_mean": round(st.mean(lats), 1) if lats else None,
            "n_seeds": len(qs),
        }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--devices", type=int, default=20)
    args = ap.parse_args()
    files = [BASE, OV] if args.devices > 5 else [BASE]

    seed_results = []
    for s in range(1, args.seeds + 1):
        print("\n=== SEED %d/%d ===" % (s, args.seeds), flush=True)
        seed_results.append(run_seed(args.devices, files))
        last = seed_results[-1]["rows"]
        print("   ", [(r["framework"], r["overall"]) for r in last], flush=True)

    agg = aggregate(seed_results)
    out = _ROOT / "results" / "phase2"
    out.mkdir(parents=True, exist_ok=True)
    (out / "framework_seeds.json").write_text(
        json.dumps({"seeds": args.seeds, "devices": args.devices,
                    "per_seed": [sr["rows"] for sr in seed_results],
                    "aggregate": agg}, indent=2), encoding="utf-8")
    print("\n=== MULTI-SEED framework quality (mean ± std over %d seeds) ===" % args.seeds)
    for fw, a in agg.items():
        print("   %-7s quality=%.3f ± %.3f  (latency ~%.0fs)" %
              (fw, a["quality_mean"], a["quality_std"],
               (a["latency_ms_mean"] or 0) / 1000))
                                                                        
    from figures import phase2
    phase2.render(args.devices)


if __name__ == "__main__":
    main()
