import os
import sys
import csv
import json
import time
import threading
from pathlib import Path

import paho.mqtt.client as mqtt
from flask import Flask, jsonify

sys.path.insert(0, "/app")

BROKER = os.environ.get("MQTT_BROKER", "mqtt")
PORT = int(os.environ.get("MQTT_PORT", "1883"))
EXPECTED = int(os.environ.get("EXPECTED_DEVICES", "5"))
DATA_DIR = Path("/app/data")

app = Flask(__name__)
STORE = {}                                     
ARRIVAL = {}                                                         
START_TIME = time.time()                                 
LOCK = threading.Lock()


def _persist():
    DATA_DIR.mkdir(exist_ok=True)
    with LOCK:
        store = dict(STORE)
    (DATA_DIR / "aggregator_snapshot.json").write_text(
        json.dumps({"captured_at": time.time(), "devices": store}, indent=2, default=str),
        encoding="utf-8")

                                                                                 
                                                                                   
                                                                                 
    dev_dir = DATA_DIR / "devices"
    dev_dir.mkdir(exist_ok=True)
    index = []
    for dev_id, blob in store.items():
        (dev_dir / ("%s_input.json" % dev_id)).write_text(
            json.dumps(blob, indent=2, default=str), encoding="utf-8")
        index.append({
            "device": dev_id,
            "name": blob.get("meta", {}).get("name"),
            "payload_bytes": blob.get("meta", {}).get("payload_bytes"),
            "telemetry_samples": blob.get("meta", {}).get("telemetry_samples"),
            "crypto_ops": blob.get("meta", {}).get("crypto_ops"),
            "file": "devices/%s_input.json" % dev_id,
        })
    (dev_dir / "index.json").write_text(
        json.dumps({"n_devices": len(index), "devices": index}, indent=2),
        encoding="utf-8")

    headers = ["device", "device_type",
               "hw_declared_cpu", "hw_ram_kb", "hw_flash_mb",
               "mem_verdict", "mem_constrained",
               "cpu_class", "cpu_measured_aes_MBps",
               "rng_generator", "rng_quality", "rng_tests_passed",
               "os_declared_os", "os_tls", "os_updatable",
               "compute_ms", "memory_rss_mb",
               "payload_bytes", "telemetry_samples", "crypto_ops",
               "arrival_elapsed_s"]
    rows = []
    for dev_id in sorted(store):
        b = store[dev_id]; m = b["meta"]; p = b["profile"]
        hw = p["hardware_profiling"]; mem = p["memory_analysis"]
        cpu = p["cpu_capability"]; rng = p["random_number_generator"]
        osf = p["os_fingerprinting"]
        arr = ARRIVAL.get(dev_id, {})
        rows.append([
            dev_id, m.get("device_type"),
            hw["declared_cpu"], hw["ram_kb"], hw["flash_mb"],
            mem["verdict"], mem["constrained"],
            cpu["class"], cpu["measured_aes_MBps"],
            rng["generator"], rng["quality"],
            "%d/%d" % (rng["tests_passed"], rng["tests_total"]),
            osf["declared_os"], osf["tls"], osf["updatable"],
            m.get("compute_ms"), m.get("memory_rss_mb"),
            m.get("payload_bytes"), m.get("telemetry_samples"), m.get("crypto_ops"),
            arr.get("elapsed_s"),
        ])
    with open(DATA_DIR / "phase1_device_dimensions.csv", "w", newline="",
              encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(headers); w.writerows(rows)

                                                                       
    total_bytes = sum(ARRIVAL.get(d, {}).get("payload_bytes", 0) for d in store)
    ready_elapsed = max((ARRIVAL.get(d, {}).get("elapsed_s", 0.0) for d in store),
                        default=0.0)
    timing = {
        "phase": "phase1_data_plane",
        "start_time": START_TIME,
        "n_devices": len(store),
        "aggregator_ready_elapsed_s": round(ready_elapsed, 3),
        "total_data_bytes": total_bytes,
        "total_data_mb": round(total_bytes / 1e6, 3),
        "per_device": {d: ARRIVAL.get(d, {}) for d in sorted(store)},
    }
    (DATA_DIR / "phase1_timing.json").write_text(
        json.dumps(timing, indent=2, default=str), encoding="utf-8")
    print("[aggregator] persisted snapshot + phase1_device_dimensions.csv + "
          "phase1_timing.json (%d devices, %.2f MB total, ready@%.2fs)"
          % (len(rows), total_bytes / 1e6, ready_elapsed), flush=True)


def _on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode("utf-8"))
        dev_id = payload["meta"]["device"]
        now = time.time()
        with LOCK:
            STORE[dev_id] = payload
            if dev_id not in ARRIVAL:                                                     
                m = payload["meta"]
                rngq = payload.get("profile", {}).get(
                    "random_number_generator", {}).get("quality")
                ARRIVAL[dev_id] = {
                    "name": m.get("name"),
                    "recv_time": now,
                    "elapsed_s": round(now - START_TIME, 3),
                    "payload_bytes": m.get("payload_bytes", len(msg.payload)),
                    "compute_ms": m.get("compute_ms"),
                    "rng_quality": rngq,
                }
            n = len(STORE)
        print("[aggregator] got profile from %s (%d/%d)" % (dev_id, n, EXPECTED),
              flush=True)
        if n >= EXPECTED:
            _persist()                                                 
    except Exception as e:                                         
        print("[aggregator] bad message: %s" % e, flush=True)


def _mqtt_loop():
    client = mqtt.Client(client_id="aggregator")
    client.on_message = _on_message
    for _ in range(30):
        try:
            client.connect(BROKER, PORT, keepalive=60)
            break
        except Exception:                                          
            time.sleep(2)
    client.subscribe("iiot/devices/+/profile", qos=1)
    client.loop_forever()


@app.get("/health")
def health():
    with LOCK:
        return jsonify({"devices_seen": sorted(STORE.keys()), "expected": EXPECTED,
                        "ready": len(STORE) >= EXPECTED})


@app.get("/devices")
def devices():
    with LOCK:
        return jsonify(dict(STORE))


@app.get("/devices/<dev_id>")
def device(dev_id):
    with LOCK:
        return (jsonify(STORE[dev_id]) if dev_id in STORE
                else (jsonify({"error": "unknown device"}), 404))


@app.get("/snapshot")
def snapshot():
    DATA_DIR.mkdir(exist_ok=True)
    with LOCK:
        snap = {"captured_at": time.time(), "devices": dict(STORE)}
    (DATA_DIR / "aggregator_snapshot.json").write_text(
        json.dumps(snap, indent=2, default=str), encoding="utf-8")
    return jsonify({"written": str(DATA_DIR / "aggregator_snapshot.json"),
                    "device_count": len(snap["devices"])})


def main():
    threading.Thread(target=_mqtt_loop, daemon=True).start()
    print("[aggregator] HTTP API on :8000, collecting from MQTT ...", flush=True)
    app.run(host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
