from common.timing import timed
from common import cryptolib
from config_inspector.devices import get_device

MODULE = "CryptoInspector"


def m_cipher_suite(dev, m1):
    r = cryptolib.aes_roundtrip(dev["cipher_bits"], dev["cipher_mode"], iters=150)
    return "%s verified=%s %sMB/s" % (r["suite"], r["verified"], r["throughput_MBps"])


def m_key_length(dev, m1):
    r = cryptolib.ecdsa_roundtrip(dev["curve"], iters=1)
    tag = "" if r["key_bits"] >= 256 else " *below-par*"
    return "%s (%d-bit)%s" % (r["curve"], r["key_bits"], tag)


def m_certificate(dev, m1):
    r = cryptolib.build_and_validate_cert("iiot-" + dev["id"], dev["cert_valid_days"])
    return "X.509/%s %s (%dB)" % (r["sig_algo"], r["status"], r["der_bytes"])


def m_randomness(dev, m1):
    rng = m1["random_number_generator"]
    return "%s %d/%d tests" % (rng["quality"], rng["tests_passed"], rng["tests_total"])


def m_nonce_reuse(dev, m1):
                                                                             
    if m1["random_number_generator"]["quality"] == "weak":
        d = cryptolib.demonstrate_nonce_reuse()
        return "reuse DETECTED (%s)" % d["verdict"]
    return "unique nonces OK"


def m_hash_algo(dev, m1):
    r = cryptolib.hash_benchmark(dev["hash"], iters=300)
    weak = " *deprecated*" if dev["hash"] == "SHA-1" else ""
    return "%s %sMB/s%s" % (r["algo"], r["throughput_MBps"], weak)


def m_signature(dev, m1):
    r = cryptolib.ecdsa_roundtrip(dev["curve"], iters=50)
    return "ECDSA verified=%s %s/s" % (r["verified"], r["sign_verify_per_s"])


def m_auth_protocol(dev, m1):
    r = cryptolib.hmac_auth_check()
    kind = "mutual-TLS+X.509" if dev["secure_element"] else "PSK/HMAC"
    return "%s hmac=%s tamper=%s" % (kind, r["hmac_valid"], r["tamper_detected"])


METHODS = [
    ("M2.1_cipher_suite", m_cipher_suite),
    ("M2.2_key_length", m_key_length),
    ("M2.3_certificate", m_certificate),
    ("M2.4_randomness", m_randomness),
    ("M2.5_nonce_reuse", m_nonce_reuse),
    ("M2.6_hash_algo", m_hash_algo),
    ("M2.7_signature", m_signature),
    ("M2.8_auth_protocol", m_auth_protocol),
]


def inspect(module1_results):
    table = {}
    dev_ids = list(module1_results.keys())
    with timed(MODULE):
        for method_name, fn in METHODS:
            with timed(MODULE, method_name):
                col = {}
                for dev_id in dev_ids:
                    dev = get_device(dev_id)
                    col[dev_id] = fn(dev, module1_results[dev_id])
                table[method_name] = col
    return {"devices": dev_ids, "methods": [m[0] for m in METHODS], "table": table}
