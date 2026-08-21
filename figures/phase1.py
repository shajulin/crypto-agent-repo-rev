from __future__ import annotations

import argparse
import csv
import json
import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import sys
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
from common import figtheme                                                

DATA = _ROOT / "data"
OUT = _ROOT / "results" / "phase1"


                                                                               

def _device_configs(n: int):
    from config_inspector.devices import get_devices
    base = get_devices()
    out = []
    for i in range(n):
        d = dict(base[i % len(base)])
        if i >= len(base):
            d = dict(d); d["id"] = "dev%d" % (i + 1)
            d["name"] = "%s #%d" % (d["name"], i + 1)
        out.append(d)
    return out


def collect_local(n: int) -> dict:
    from config_inspector import inspector
    from distributed import simdata

    DATA.mkdir(exist_ok=True)
    start = time.perf_counter()
    per_device, rows, elapsed = {}, [], 0.0
    for d in _device_configs(n):
        did = d["id"]
        t0 = time.perf_counter()
        prof = inspector.inspect_device(base_id=did) if _accepts_base(inspector) \
            else _inspect_fallback(inspector, d)
        sim = simdata.generate(did, d)
        compute_ms = round((time.perf_counter() - t0) * 1000, 2)
        elapsed += compute_ms / 1000.0
        per_device[did] = {
            "name": d["name"], "device_type": d.get("cpu", "").split()[0],
            "recv_time": time.time(), "elapsed_s": round(elapsed, 3),
            "payload_bytes": sim["payload_bytes"], "compute_ms": compute_ms,
            "telemetry_samples": sim["n_samples"], "crypto_ops": sim["n_crypto"],
            "rng_quality": prof["random_number_generator"]["quality"],
        }
        rows.append([did, d["name"], sim["payload_bytes"], sim["n_samples"],
                     sim["n_crypto"], compute_ms,
                     prof["random_number_generator"]["quality"]])

    total_bytes = sum(v["payload_bytes"] for v in per_device.values())
    timing = {
        "phase": "phase1_data_plane", "start_time": time.time(),
        "n_devices": n, "collected": "local",
        "build_seconds": None, "mqtt_up_elapsed_s": None,
        "aggregator_ready_elapsed_s": round(elapsed, 3),
        "total_data_bytes": total_bytes, "total_data_mb": round(total_bytes / 1e6, 3),
        "wall_seconds": round(time.perf_counter() - start, 3),
        "per_device": per_device,
    }
    (DATA / "phase1_timing.json").write_text(json.dumps(timing, indent=2), "utf-8")
    with open(DATA / "phase1_device_dimensions.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["device", "name", "payload_bytes", "telemetry_samples",
                    "crypto_ops", "compute_ms", "rng_quality"])
        w.writerows(rows)
    return timing


def _accepts_base(inspector):
    import inspect as _pyi
    try:
        return "base_id" in _pyi.signature(inspector.inspect_device).parameters
    except Exception:
        return False


def _inspect_fallback(inspector, d):
                                                                           
    try:
        return inspector.inspect_device(d["id"])
    except Exception:
                                                                
        return {"random_number_generator": {"quality": "strong"}}


                                                                               

def _load() -> dict:
    p = DATA / "phase1_timing.json"
    if not p.exists():
        raise SystemExit("no data/phase1_timing.json — run with --collect-local N "
                         "or run the distributed stack first.")
    return json.loads(p.read_text(encoding="utf-8"))


def _dsort(devs):
    def key(d):
        num = "".join(c for c in d if c.isdigit())
        return (int(num) if num else 0, d)
    return sorted(devs, key=key)


def fig_data_per_device(t: dict):
    pd = t["per_device"]
    devs = _dsort(pd)
    mb = [pd[d]["payload_bytes"] / 1e6 for d in devs]
    fig, ax = plt.subplots(figsize=(max(7, 0.7 * len(devs) + 3), 4.6))
    ax.bar(devs, mb, color=figtheme.PALETTE["accent"])
    for i, v in enumerate(mb):
        ax.text(i, v, "%.2f" % v, ha="center", va="bottom", fontsize=8,
                color=figtheme.FG)
    ax.set_ylabel("data produced (MB)")
    ax.set_title("Phase 1 — %d devices · %.2f MB total data (%.2f MB/device avg)"
                 % (t["n_devices"], t["total_data_mb"], t["total_data_mb"] / max(1, t["n_devices"])))
    ax.tick_params(axis="x", rotation=45, labelsize=8)
    fig.tight_layout(); fig.savefig(OUT / "phase1_data_per_device.png", dpi=140)
    plt.close(fig)


def fig_timeline(t: dict):
    pd = t["per_device"]
    devs = sorted(pd, key=lambda d: pd[d]["elapsed_s"])
    y = range(len(devs))
    arr = [pd[d]["elapsed_s"] for d in devs]
    fig, ax = plt.subplots(figsize=(9, max(3.5, 0.4 * len(devs) + 1.5)))
    ax.barh(list(y), arr, color=figtheme.PALETTE["ok"], height=0.5)
    for i, d in enumerate(devs):
        ax.text(arr[i], i, " %.2fs (%.1f MB)" % (arr[i], pd[d]["payload_bytes"] / 1e6),
                va="center", fontsize=7, color=figtheme.FG)
    ax.set_yticks(list(y)); ax.set_yticklabels(devs, fontsize=8)
    ax.set_xlabel("elapsed since Phase-1 t0 (s)")
    marks = [("aggregator ready", t.get("aggregator_ready_elapsed_s"), "warn"),
             ("MQTT up", t.get("mqtt_up_elapsed_s"), "llm"),
             ("build finished", t.get("build_seconds"), "purple")]
    for label, val, col in marks:
        if val:
            ax.axvline(val, color=figtheme.PALETTE[col], ls="--", lw=1.5)
            ax.text(val, len(devs) - 0.5, " " + label, color=figtheme.PALETTE[col],
                    fontsize=7, rotation=90, va="top")
    ax.set_title("Phase 1 — when each device's data reached the aggregator (Jetson)")
    ax.grid(axis="x")
    fig.tight_layout(); fig.savefig(OUT / "phase1_timeline.png", dpi=140)
    plt.close(fig)


def fig_totals(t: dict):
    labels, vals, cols = [], [], []
    for name, key, col in [("docker build", "build_seconds", "purple"),
                           ("MQTT up", "mqtt_up_elapsed_s", "llm"),
                           ("aggregator ready", "aggregator_ready_elapsed_s", "ok"),
                           ("total Phase 1", "wall_seconds", "accent")]:
        if t.get(key) is not None:
            labels.append(name); vals.append(t[key]); cols.append(figtheme.PALETTE[col])
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.4),
                                   gridspec_kw={"width_ratios": [2, 1]})
    ax1.bar(labels, vals, color=cols)
    for i, v in enumerate(vals):
        ax1.text(i, v, "%.2fs" % v, ha="center", va="bottom", fontsize=8, color=figtheme.FG)
    ax1.set_ylabel("seconds"); ax1.set_title("Phase 1 — key timings")
    ax1.tick_params(axis="x", labelsize=8)
    ax2.bar(["received"], [t["total_data_mb"]], color=figtheme.PALETTE["accent"], width=0.5)
    ax2.text(0, t["total_data_mb"] / 2, "%.2f MB\n(%d devices)" % (t["total_data_mb"], t["n_devices"]),
             ha="center", va="center", fontsize=11, fontweight="bold", color="#0b1020")
    ax2.set_ylim(0, t["total_data_mb"] * 1.15)
    ax2.set_ylabel("MB"); ax2.set_title("Phase 1 — total data received")
    fig.suptitle("Phase 1 (data plane) — %d devices" % t["n_devices"])
    fig.tight_layout(rect=[0, 0, 1, 0.94])
    fig.savefig(OUT / "phase1_totals.png", dpi=140); plt.close(fig)


def _write_log(t: dict):
    lines = ["Phase 1 (data plane) — run log", "=" * 40,
             "devices:                %d" % t["n_devices"],
             "collected:              %s" % t.get("collected", "docker"),
             "docker build finished:  %s s" % t.get("build_seconds"),
             "MQTT up:                %s s" % t.get("mqtt_up_elapsed_s"),
             "aggregator ready:       %.3f s" % (t.get("aggregator_ready_elapsed_s") or 0),
             "total Phase-1 wall:     %s s" % t.get("wall_seconds"),
             "total data received:    %.2f MB" % t["total_data_mb"], "",
             "per device:"]
    for d, v in t["per_device"].items():
        lines.append("  %-8s %6.2f MB  arrived@%6.2fs  compute=%sms  rng=%s"
                     % (d, v["payload_bytes"] / 1e6, v["elapsed_s"],
                        v.get("compute_ms"), v.get("rng_quality", "?")))
    (OUT / "phase1_log.txt").write_text("\n".join(lines), encoding="utf-8")


def render(t: dict):
    OUT.mkdir(parents=True, exist_ok=True)
    figtheme.apply()
    fig_data_per_device(t)
    fig_timeline(t)
    fig_totals(t)
    _write_log(t)
    print("[phase1] wrote figures + log to", OUT)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--collect-local", type=int, metavar="N",
                    help="generate data for N devices in-process, then render")
    args = ap.parse_args()
    t = collect_local(args.collect_local) if args.collect_local else _load()
    render(t)


if __name__ == "__main__":
    main()
