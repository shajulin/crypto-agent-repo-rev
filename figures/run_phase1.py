from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import sys
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
from common import figtheme                                                
from figures import phase1                                                 

DATA = _ROOT / "data"
COMPOSE = _ROOT / ".phase1_run.yml"
_DEVICE_TYPES = ["ESP32", "ESP32-S3", "RaspberryPi", "RaspberryPi", "ESP32"]


def _compose_yaml(n: int) -> str:
    svc = ["services:",
           "  mqtt:",
           "    image: eclipse-mosquitto:2",
           "    volumes:",
           "      - ./distributed/mqtt/mosquitto.conf:/mosquitto/config/mosquitto.conf:ro"]
    for i in range(1, n + 1):
        svc += [
            "  dev%d:" % i,
            "    image: iiot-node:latest",
            "    build: {context: ., dockerfile: distributed/Dockerfile}",
            "    depends_on: [mqtt]",
            "    environment: {DEVICE_ID: dev%d, DEVICE_TYPE: %s, PUBLISH_INTERVAL: '3600'}"
            % (i, _DEVICE_TYPES[(i - 1) % len(_DEVICE_TYPES)]),
            '    command: ["python", "distributed/device_agent.py"]',
        ]
    svc += [
        "  aggregator:",
        "    image: iiot-node:latest",
        "    build: {context: ., dockerfile: distributed/Dockerfile}",
        "    depends_on: [mqtt]",
        "    environment: {EXPECTED_DEVICES: '%d'}" % n,
        '    command: ["python", "distributed/aggregator.py"]',
        "    volumes: [./data:/app/data]",
    ]
    return "\n".join(svc) + "\n"


def _dc(*args, **kw):
    return subprocess.run(["docker", "compose", "-f", str(COMPOSE), *args],
                          cwd=str(_ROOT), capture_output=True, text=True, **kw)


def run_once(n: int, build: bool = True) -> dict:
    COMPOSE.write_text(_compose_yaml(n), encoding="utf-8")
    (DATA).mkdir(exist_ok=True)
    timing_file = DATA / "phase1_timing.json"
    if timing_file.exists():
        timing_file.unlink()

    t0 = time.perf_counter()
    build_s = None
    if build:
        _dc("build")
        build_s = round(time.perf_counter() - t0, 2)

    t_up = time.perf_counter()
    _dc("up", "-d")
    mqtt_up_s = round(time.perf_counter() - t_up, 2)

                                                           
    ready_wall = None
    deadline = time.perf_counter() + 180
    while time.perf_counter() < deadline:
        if timing_file.exists():
            try:
                t = json.loads(timing_file.read_text(encoding="utf-8"))
                if t.get("n_devices", 0) >= n:
                    ready_wall = round(time.perf_counter() - t_up, 2)
                    break
            except Exception:                                                
                pass
        time.sleep(0.5)
    total_wall = round(time.perf_counter() - t0, 2)
    _dc("down")

    t = json.loads(timing_file.read_text(encoding="utf-8")) if timing_file.exists() else \
        {"n_devices": n, "per_device": {}, "total_data_mb": 0.0,
         "aggregator_ready_elapsed_s": 0.0}
    t.update({"build_seconds": build_s, "mqtt_up_elapsed_s": mqtt_up_s,
              "collect_wall_s": ready_wall, "wall_seconds": total_wall,
              "collected": "docker"})
    timing_file.write_text(json.dumps(t, indent=2, default=str), encoding="utf-8")
    return t


def scale(lo: int, hi: int) -> None:
    rows = []
    for n in range(lo, hi + 1):
        print("\n=== scaling round: %d device(s) ===" % n, flush=True)
        t = run_once(n, build=(n == lo))                                        
        rows.append({
            "n": n, "build_s": t.get("build_seconds"),
            "up_s": t.get("mqtt_up_elapsed_s"), "collect_s": t.get("collect_wall_s"),
            "total_s": t.get("wall_seconds"), "data_mb": t.get("total_data_mb"),
        })
        print("   n=%d total=%ss data=%sMB" % (n, t.get("wall_seconds"),
                                               t.get("total_data_mb")), flush=True)
    (_ROOT / "results" / "scaling").mkdir(parents=True, exist_ok=True)
    (_ROOT / "results" / "scaling" / "scaling.json").write_text(
        json.dumps(rows, indent=2), encoding="utf-8")
    _fig_scaling(rows)


def _fig_scaling(rows: list) -> None:
    figtheme.apply()
    ns = [r["n"] for r in rows]
    out = _ROOT / "results" / "scaling"
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))
    for key, label, col in [("up_s", "containers up", "llm"),
                            ("collect_s", "aggregator collect", "warn"),
                            ("total_s", "total (excl. build)", "accent")]:
        ys = [r[key] if r[key] is not None else float("nan") for r in rows]
        ax1.plot(ns, ys, "-o", color=figtheme.PALETTE[col], label=label)
    ax1.set_xlabel("number of devices"); ax1.set_ylabel("seconds")
    ax1.set_title("Phase-1 scaling — time vs device count"); ax1.legend(fontsize=8)
    ax1.set_xticks(ns)
    ax2.plot(ns, [r["data_mb"] for r in rows], "-o", color=figtheme.PALETTE["ok"])
    ax2.set_xlabel("number of devices"); ax2.set_ylabel("total data (MB)")
    ax2.set_title("Phase-1 scaling — data volume vs device count"); ax2.set_xticks(ns)
    fig.suptitle("Scaling experiment — 1..%d devices (real Docker per round)" % ns[-1])
    fig.tight_layout(rect=[0, 0, 1, 0.94])
    fig.savefig(out / "scaling_devices.png", dpi=140); plt.close(fig)
    print("[scaling] wrote", out / "scaling_devices.png")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--devices", type=int, default=5)
    ap.add_argument("--scale", nargs=2, type=int, metavar=("LO", "HI"))
    args = ap.parse_args()
    if args.scale:
        scale(args.scale[0], args.scale[1])
    else:
        t = run_once(args.devices)
        phase1.render(t)
        print("[run_phase1] real %d-device run done: total=%ss data=%sMB"
              % (t["n_devices"], t.get("wall_seconds"), t.get("total_data_mb")))


if __name__ == "__main__":
    main()
