from common.timing import timed
from common.crypto_threats import threats_for
from config_inspector.devices import get_device

MODULE = "ThreatRisk"

METRIC_NAMES = ["CVSS", "EPSS", "AttackSurface",
                "KeyExposureProb", "FirmwareVulnScore", "CryptoCompliance"]


def _real_signals(dev_id, m1):
    dev = get_device(dev_id)
    rng = m1["random_number_generator"]
    return {
        "rng_failed_tests": rng["tests_total"] - rng["tests_passed"],
        "rng_weak": rng["quality"] == "weak",
        "cert_expired": dev["cert_valid_days"] < 0,
        "hash_deprecated": dev["hash"] == "SHA-1",
        "curve_below_par": dev["curve"] == "P-224",
        "cipher_ok": m1["cpu_capability_detection"]["measured_aes_MBps"] > 0,
        "secure_boot": dev["secure_boot"],
        "secure_element": dev["secure_element"],
        "updatable": m1["os_fingerprinting"]["updatable"],
        "gateway": m1["cpu_capability_detection"]["class"] == "gateway",
        "tls13": dev["tls"] == "1.3",
    }


def _cvss(s):
    score = 1.0
    score += 4.0 * (s["rng_failed_tests"] > 1)
    score += 2.0 * s["cert_expired"]
    score += 1.5 * s["hash_deprecated"]
    score += 1.0 * s["curve_below_par"]
    score += 1.0 * (not s["tls13"])
    return round(min(score, 10.0), 1)


def _epss(s):
    p = 0.05
    p += 0.4 * s["rng_weak"]
    p += 0.25 * (not s["secure_boot"])
    p += 0.15 * s["cert_expired"]
    return round(min(p, 0.99), 2)


def _attack_surface(s):
    return 8 if s["gateway"] else 3


def _key_exposure(s):
    p = 0.05 + 0.55 * s["rng_weak"]
    if not s["secure_element"]:
        p += 0.15
    return round(min(p, 0.95), 2)


def _firmware_vuln(s):
    score = 2.0 + 4.0 * (not s["updatable"]) + 2.0 * (not s["secure_boot"])
    return round(min(score, 10.0), 1)


def _crypto_compliance(s):
    checks = [not s["rng_weak"], not s["cert_expired"], not s["hash_deprecated"],
              not s["curve_below_par"], s["cipher_ok"], s["tls13"]]
    return round(sum(checks) / len(checks), 2)


def assess(module1_results, module2_result):
    metrics = {name: {} for name in METRIC_NAMES}
    threats = {}
    with timed(MODULE):
        for dev_id, m1 in module1_results.items():
            with timed(MODULE, f"metrics/{dev_id}"):
                s = _real_signals(dev_id, m1)
                metrics["CVSS"][dev_id] = _cvss(s)
                metrics["EPSS"][dev_id] = _epss(s)
                metrics["AttackSurface"][dev_id] = _attack_surface(s)
                metrics["KeyExposureProb"][dev_id] = _key_exposure(s)
                metrics["FirmwareVulnScore"][dev_id] = _firmware_vuln(s)
                metrics["CryptoCompliance"][dev_id] = _crypto_compliance(s)
                                                                              
                threats[dev_id] = threats_for({
                    "rng_weak": s["rng_weak"],
                    "cert_expired": s["cert_expired"],
                    "hash_deprecated": s["hash_deprecated"],
                    "curve_below_par": s["curve_below_par"],
                    "tls_outdated": not s["tls13"],
                    "no_root_of_trust": not s["secure_boot"] and not s["secure_element"],
                })

    risk = {}
    for dev_id in module1_results:
        r = (0.25 * metrics["CVSS"][dev_id] / 10
             + 0.20 * metrics["EPSS"][dev_id]
             + 0.15 * metrics["AttackSurface"][dev_id] / 10
             + 0.20 * metrics["KeyExposureProb"][dev_id]
             + 0.10 * metrics["FirmwareVulnScore"][dev_id] / 10
             + 0.10 * (1 - metrics["CryptoCompliance"][dev_id]))
        risk[dev_id] = round(r, 2)

    return {"metrics": metrics, "risk": risk, "threats": threats,
            "metric_names": METRIC_NAMES}
