from common.timing import timed
from config_inspector.devices import get_device

MODULE = "RuleEngine"

                                                      
RULES = [
    ("R1", lambda m1, d: m1["random_number_generator"]["quality"] == "weak",
     "Replace software PRNG with a hardware TRNG / secure element", "CRITICAL"),
    ("R2", lambda m1, d: d["cert_valid_days"] < 0,
     "Renew the expired X.509 certificate and rotate keys", "CRITICAL"),
    ("R3", lambda m1, d: not d["secure_boot"],
     "Enable verified/secure boot to establish a root of trust", "HIGH"),
    ("R4", lambda m1, d: not m1["os_fingerprinting"]["updatable"],
     "Add a signed OTA firmware-update path", "HIGH"),
    ("R5", lambda m1, d: d["hash"] == "SHA-1",
     "Migrate away from deprecated SHA-1 to SHA-256+", "HIGH"),
    ("R6", lambda m1, d: d["curve"] == "P-224",
     "Upgrade to >=128-bit ECC (P-256) key strength", "MEDIUM"),
    ("R7", lambda m1, d: d["tls"] != "1.3",
     "Upgrade transport to TLS 1.3", "MEDIUM"),
    ("R8", lambda m1, d: not d["secure_element"],
     "Provision a secure element (ATECC608A) for key storage", "LOW"),
]

_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def suggest(module1_results, module2_result):
    out = {}
    with timed(MODULE):
        for dev_id, m1 in module1_results.items():
            dev = get_device(dev_id)
            with timed(MODULE, f"evaluate/{dev_id}"):
                fired = [{"rule": rid, "priority": pri, "suggestion": msg}
                         for rid, pred, msg, pri in RULES if pred(m1, dev)]
                fired.sort(key=lambda x: _ORDER[x["priority"]])
                out[dev_id] = fired
    return out
