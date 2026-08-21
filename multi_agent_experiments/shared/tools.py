import sys
from pathlib import Path

CRYPTO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(CRYPTO_ROOT))

from common import cryptolib, rng_tests                                    
from config_inspector.devices import get_device                    


def tool_rng_test(device):
    dev = get_device(device)
    r = rng_tests.assess_generator(dev["rng_gen"], nbytes=16384)
    return {"quality": r["quality"], "tests_passed": r["tests_passed"],
            "tests_total": r["tests_total"]}


def tool_check_certificate(device):
    dev = get_device(device)
    r = cryptolib.build_and_validate_cert("iiot-" + device, dev["cert_valid_days"])
    return {"status": r["status"], "sig_algo": r["sig_algo"]}


def tool_security_bits(device):
    dev = get_device(device)
    r = cryptolib.measure_security_bits(dev["cipher_bits"], dev["curve"], dev["hash"])
    return {"overall_min_bits": r["overall_min_bits"], "ecc_bits": r["ecc_bits"],
            "hash_bits": r["hash_bits"]}


TOOLS = {
    "rng_test": {"fn": tool_rng_test,
                 "desc": "Run NIST SP800-22 randomness tests on the device RNG."},
    "check_certificate": {"fn": tool_check_certificate,
                          "desc": "Build and validate the device's X.509 certificate."},
    "security_bits": {"fn": tool_security_bits,
                      "desc": "Measure the device's effective cryptographic strength in bits."},
}


def run_tool(name, device):
    if name not in TOOLS:
        return {"error": "unknown tool %s" % name}
    return TOOLS[name]["fn"](device)
