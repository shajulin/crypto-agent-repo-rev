import socket

from common import rng_tests, cryptolib
from config_inspector.devices import get_device


def attack_weak_rng_prediction(device):
    dev = get_device(device)
    gen = dev["rng_gen"]
    a = rng_tests.GENERATORS[gen](64)
    b = rng_tests.GENERATORS[gen](64)
    predictable = a == b
    return {"attack": "weak_rng_key_prediction", "success": predictable,
            "impact": "attacker predicts keys/nonces" if predictable else "none",
            "evidence": "generator output reproducible" if predictable
                        else "CSPRNG output non-reproducible"}


def attack_nonce_reuse(device):
    dev = get_device(device)
    if dev["rng_gen"] == "weak_lcg":
        d = cryptolib.demonstrate_nonce_reuse()
        return {"attack": "nonce_reuse_plaintext_recovery",
                "success": d["keystream_cancels"],
                "impact": "plaintext recovery" if d["keystream_cancels"] else "none",
                "evidence": d["verdict"]}
    return {"attack": "nonce_reuse_plaintext_recovery", "success": False,
            "impact": "none", "evidence": "unique nonces from CSPRNG"}


def attack_expired_cert_mitm(device):
    dev = get_device(device)
    bad = dev["cert_valid_days"] < 0
    return {"attack": "expired_cert_mitm", "success": bad,
            "impact": "impersonation / MITM" if bad else "none",
            "evidence": "certificate expired" if bad else "certificate valid"}


def attack_sha1_forgery(device):
    dev = get_device(device)
    bad = dev["hash"] == "SHA-1"
    return {"attack": "sha1_signature_forgery", "success": bad,
            "impact": "signature/collision forgery (SHAttered)" if bad else "none",
            "evidence": "SHA-1 in use" if bad else "SHA-256+"}


def attack_tls_downgrade(device):
    dev = get_device(device)
    bad = dev["tls"] in ("1.0", "1.1", "1.2")
    return {"attack": "tls_downgrade", "success": bad,
            "impact": "downgrade / legacy-cipher attack" if bad else "none",
            "evidence": "TLS %s" % dev["tls"]}


def attack_weak_curve(device):
    dev = get_device(device)
    bad = dev["curve"] in ("P-192", "P-224")
    return {"attack": "weak_ecc_curve", "success": bad,
            "impact": "reduced ECDLP security / key recovery" if bad else "none",
            "evidence": "ECC curve %s" % dev["curve"]}


def attack_no_root_of_trust(device):
    dev = get_device(device)
    bad = not dev.get("secure_boot") and not dev.get("secure_element")
    return {"attack": "firmware_tamper_no_root_of_trust", "success": bad,
            "impact": "firmware tamper / key extraction" if bad else "none",
            "evidence": "no secure boot / secure element" if bad
                        else "hardware root of trust present"}


DEVICE_ATTACKS = [attack_weak_rng_prediction, attack_nonce_reuse,
                  attack_expired_cert_mitm, attack_sha1_forgery, attack_tls_downgrade,
                  attack_weak_curve, attack_no_root_of_trust]


def port_scan(targets):
    common_ports = [22, 80, 443, 1883, 8000, 8883, 5000]
    results = {}
    for host, ports in targets.items():
        open_ports = []
        for p in (ports or common_ports):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            try:
                if s.connect_ex((host, p)) == 0:
                    open_ports.append(p)
            except Exception:                                       
                pass
            finally:
                s.close()
        results[host] = open_ports
    return results


                                                                                
REMEDIATION = {
    "weak_rng_key_prediction": {
        "fix": "Replace the software PRNG with a hardware TRNG / secure element.",
        "prevention": "Seed all keys/nonces from a CSPRNG; ban LCG/rand() in firmware; "
                      "add a boot-time NIST SP800-90B health test."},
    "nonce_reuse_plaintext_recovery": {
        "fix": "Use a unique random nonce per AEAD message (or a monotonic counter).",
        "prevention": "Enforce nonce uniqueness in the crypto layer; reject reused nonces; "
                      "prefer XChaCha20-Poly1305 / AES-GCM-SIV."},
    "expired_cert_mitm": {
        "fix": "Renew the X.509 certificate and rotate the key pair now.",
        "prevention": "Automate certificate rotation before expiry and alert < 30 days."},
    "sha1_signature_forgery": {
        "fix": "Migrate signatures/certs off SHA-1 to SHA-256 or better.",
        "prevention": "Disable SHA-1 in the TLS/crypto policy; pin SHA-256+ everywhere."},
    "tls_downgrade": {
        "fix": "Require TLS 1.3 and disable legacy protocol versions/ciphers.",
        "prevention": "Set a minimum-TLS-1.3 policy and drop downgrade handshakes."},
    "weak_ecc_curve": {
        "fix": "Upgrade the ECC curve to P-256 or stronger (P-384/P-521).",
        "prevention": "Pin a >=128-bit-security curve in the crypto policy; ban P-192/P-224."},
    "firmware_tamper_no_root_of_trust": {
        "fix": "Enable verified/secure boot or add a secure element to anchor trust.",
        "prevention": "Require a hardware root of trust and signed firmware for all devices."},
}


def run_attacks(device_ids, scan_targets=None):
    per_device = {}
    for dev_id in device_ids:
        outcomes = []
        for fn in DEVICE_ATTACKS:
            o = fn(dev_id)
            rem = REMEDIATION.get(o["attack"], {})
            o["remediation"] = rem.get("fix", "") if o["success"] else ""
            o["prevention"] = rem.get("prevention", "") if o["success"] else ""
            outcomes.append(o)
        succeeded = [o["attack"] for o in outcomes if o["success"]]
        per_device[dev_id] = {"attacks": outcomes, "succeeded": succeeded,
                              "vulnerable": len(succeeded) > 0}
    recon = port_scan(scan_targets or {}) if scan_targets else {}
    return {"per_device": per_device, "network_recon": recon}


def to_rows(attack_results):
    rows = []
    for dev_id, r in attack_results["per_device"].items():
        for o in r["attacks"]:
            rows.append({"device": dev_id, "attack": o["attack"],
                         "success": o["success"], "impact": o["impact"],
                         "evidence": o["evidence"],
                         "remediation": o.get("remediation", ""),
                         "prevention": o.get("prevention", "")})
    return rows
