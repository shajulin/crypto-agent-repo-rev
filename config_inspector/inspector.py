import platform

import psutil

from common.timing import timed
from common import rng_tests, cryptolib
from .devices import get_devices, get_device

MODULE = "ConfigInspector"


def _hardware_pooling(dev):
    feats = {"secure_boot": dev["secure_boot"], "tpm": dev["tpm"],
             "puf": dev["puf"], "secure_element": dev["secure_element"]}
    score = sum(bool(v) for v in feats.values()) / len(feats)
    return {"features": feats, "hw_root_of_trust_score": round(score, 2),
            "host_logical_cpus": psutil.cpu_count(),
            "host_total_ram_mb": round(psutil.virtual_memory().total / 1e6)}


def _memory_analysis(dev):
    budget = dev["ram_kb"]
    tight = budget < 64
    return {"ram_kb": budget, "flash_mb": dev["flash_mb"],
            "host_available_ram_mb": round(psutil.virtual_memory().available / 1e6),
            "constrained": tight,
            "verdict": "constrained - PSK/ECC only" if tight else "AES+ECC+TLS feasible"}


def _cpu_capability(dev):
                                                                           
    flags = ""
    try:
        if platform.system() == "Linux":
            with open("/proc/cpuinfo") as fh:
                flags = fh.read()
    except Exception:
        pass
    hw_aes_host = "aes" in flags.lower()
    bench = cryptolib.aes_roundtrip(dev["cipher_bits"], dev["cipher_mode"], iters=100)
    return {"declared_cpu": dev["cpu"], "host_has_aes_ni": hw_aes_host,
            "measured_aes_MBps": bench["throughput_MBps"],
            "class": "gateway" if "a72" in dev["cpu"].lower() else "mcu"}


def _rng_quality(dev):
                                                                   
    result = rng_tests.assess_generator(dev["rng_gen"], nbytes=131072)
    return result


def _os_fingerprint(dev):
    return {"declared_os": dev["os"], "tls": dev["tls"],
            "host_platform": platform.platform(),
            "host_python": platform.python_version(),
            "updatable": dev["os"] not in ("bare-metal",)}


RESPONSIBILITIES = [
    ("hardware_pooling", _hardware_pooling),
    ("memory_analysis", _memory_analysis),
    ("cpu_capability_detection", _cpu_capability),
    ("random_number_generator", _rng_quality),
    ("os_fingerprinting", _os_fingerprint),
]


def inspect_device(dev_id):
    dev = get_device(dev_id)
    profile = {"meta": {"id": dev["id"], "name": dev["name"], "sensor": dev["sensor"]}}
    for resp_name, fn in RESPONSIBILITIES:
        with timed(MODULE, f"{dev['id']}/{resp_name}"):
            profile[resp_name] = fn(dev)
    return profile


def inspect_all():
    results = {}
    with timed(MODULE):
        for dev in get_devices():
            results[dev["id"]] = inspect_device(dev["id"])
    return results
