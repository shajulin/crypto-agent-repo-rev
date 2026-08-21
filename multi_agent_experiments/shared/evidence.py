import sys
from pathlib import Path

                                         
CRYPTO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CRYPTO_ROOT))

from config_inspector import inspector as m1                      
from crypto_inspector import inspector as m2                      
from threat_risk import assessment as m3                          
from config_inspector.devices import get_device                   


def build_evidence():
    r1 = m1.inspect_all()
    r2 = m2.inspect(r1)
    r3 = m3.assess(r1, r2)

    evidence = {}
    for dev_id, prof in r1.items():
        dev = get_device(dev_id)
        rng = prof["random_number_generator"]
        m2col = {m: r2["table"][m][dev_id] for m in r2["methods"]}
        evidence[dev_id] = {
            "device": dev_id,
            "name": dev["name"],
            "config": {
                "secure_boot": dev["secure_boot"],
                "secure_element": dev["secure_element"],
                "updatable": prof["os_fingerprinting"]["updatable"],
                "tls": dev["tls"], "curve": dev["curve"], "hash": dev["hash"],
                "cipher": "AES-%d-%s" % (dev["cipher_bits"], dev["cipher_mode"]),
                "cert_valid_days": dev["cert_valid_days"],
            },
            "measurements": {
                "rng_quality": rng["quality"],
                "rng_tests_passed": "%d/%d" % (rng["tests_passed"], rng["tests_total"]),
                "aes_throughput_MBps": prof["cpu_capability_detection"]["measured_aes_MBps"],
                "cert_status": "EXPIRED" if dev["cert_valid_days"] < 0 else "valid",
            },
            "crypto_findings": m2col,
            "risk_metrics": {mname: r3["metrics"][mname][dev_id]
                             for mname in r3["metric_names"]},
            "aggregate_risk": r3["risk"][dev_id],
            "reference_threats": [t["attack"] for t in r3["threats"].get(dev_id, [])],
        }
                                                                         
    return evidence, {"risk": r3["risk"]}


if __name__ == "__main__":
    import json
    ev, ref = build_evidence()
    print(json.dumps(ev["dev2"], indent=2, default=str))
