from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any, Dict

import numpy as np

                                                                                  
_SENSOR_MODEL = {
    "flame":    ("irradiance_W_m2", 40.0, 30.0, 6.0),
    "ir":       ("ir_counts",       512.0, 180.0, 25.0),
    "soil":     ("moisture_pct",    35.0, 12.0, 3.0),
    "sound":    ("spl_dB",          55.0, 18.0, 4.0),
    "temp":     ("temp_C",          24.0, 6.0, 0.8),
    "humidity": ("humidity_pct",    50.0, 15.0, 2.5),
    "default":  ("value",           50.0, 20.0, 5.0),
}


def _seeded_rng(device_id: str) -> np.random.Generator:
    h = hashlib.sha256(device_id.encode()).digest()
    return np.random.default_rng(int.from_bytes(h[:8], "big"))


def _sensor_kind(name: str) -> str:
    n = (name or "").lower()
    for key in _SENSOR_MODEL:
        if key in n:
            return key
    return "default"


def _telemetry(rng, kind: str, n_samples: int, period_s: float) -> Dict[str, Any]:
    unit, base, amp, noise = _SENSOR_MODEL[kind]
    t = np.arange(n_samples, dtype=float) * period_s
    daily = amp * np.sin(2 * np.pi * t / 86400.0)                     
    signal = base + daily + rng.normal(0.0, noise, n_samples)
                                                     
    n_spikes = rng.poisson(max(1, n_samples // 500))
    spike_idx = rng.integers(0, n_samples, size=n_spikes)
    signal[spike_idx] += rng.uniform(3 * noise, 8 * noise, size=n_spikes)
    start = time.time() - n_samples * period_s
    return {
        "unit": unit, "sampling_period_s": period_s, "n_samples": n_samples,
        "t_start": round(start, 3),
        "readings": [round(float(v), 4) for v in signal],                          
        "n_spikes": int(n_spikes),
    }


def _crypto_log(rng, dev: Dict[str, Any], n_ops: int) -> list:
    cipher = "AES-%d-%s" % (dev.get("cipher_bits", 128), dev.get("cipher_mode", "GCM"))
    hashalg = dev.get("hash", "SHA-256")
    curve = dev.get("curve", "P-256")
                                                                                  
    base_lat = 0.4 if dev.get("cipher_bits", 128) >= 256 else 0.25
    ops = []
    for i in range(n_ops):
        pt = int(rng.integers(64, 4096))
        ops.append({
            "op": i, "cipher": cipher, "hash": hashalg, "sign_curve": curve,
            "plaintext_bytes": pt,
            "nonce_hex": rng.integers(0, 256, size=12).tobytes().hex(),
            "ciphertext_bytes": pt + 16,                           
            "signature_bytes": {"P-224": 56, "P-256": 64, "P-384": 96}.get(curve, 64),
            "latency_ms": round(base_lat + float(rng.exponential(0.15)), 3),
        })
    return ops


def generate(device_id: str, dev: Dict[str, Any],
             n_samples: int | None = None,
             n_crypto: int | None = None) -> Dict[str, Any]:
    rng = _seeded_rng(device_id)
    n_samples = n_samples or int(os.environ.get("SIM_TELEMETRY_SAMPLES", "20000"))
    if os.environ.get("SIM_TELEMETRY_MB"):
                                                                                  
        target = float(os.environ["SIM_TELEMETRY_MB"]) * 1e6
        n_samples = max(1000, int(target / 9))
    n_crypto = n_crypto or int(os.environ.get("SIM_CRYPTO_OPS", "2000"))
    period = float(os.environ.get("SIM_SAMPLE_PERIOD_S", "1.0"))

    kind = _sensor_kind(dev.get("name", "") + " " + dev.get("sensor", ""))
    record = {
        "identity": {
            "device": device_id, "name": dev.get("name"),
            "declared_cpu": dev.get("cpu"), "ram_kb": dev.get("ram_kb"),
            "flash_mb": dev.get("flash_mb"), "rng_source": dev.get("rng_gen"),
            "tls": dev.get("tls"), "cipher_bits": dev.get("cipher_bits"),
            "cipher_mode": dev.get("cipher_mode"), "curve": dev.get("curve"),
            "hash": dev.get("hash"), "cert_valid_days": dev.get("cert_valid_days"),
            "sensor_kind": kind,
        },
        "telemetry": _telemetry(rng, kind, n_samples, period),
        "crypto_log": _crypto_log(rng, dev, n_crypto),
        "network": {
            "mqtt_messages": int(rng.integers(50, 500)),
            "reconnects": int(rng.integers(0, 4)),
        },
    }
    blob = json.dumps(record, default=str)
    payload_bytes = len(blob.encode("utf-8"))
    record["network"]["bytes_on_wire"] = payload_bytes
    return {"record": record, "payload_bytes": payload_bytes,
            "n_samples": n_samples, "n_crypto": n_crypto}


if __name__ == "__main__":                                     
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from config_inspector.devices import get_devices
    for d in get_devices():
        out = generate(d["id"], d)
        print("%-6s %-16s samples=%d crypto=%d payload=%.1f KB" % (
            d["id"], d["name"], out["n_samples"], out["n_crypto"],
            out["payload_bytes"] / 1024.0))
