import math
import os
import secrets

import numpy as np


                                                                              
def gen_os_urandom(nbytes):
    return os.urandom(nbytes)


def gen_secrets(nbytes):
    return secrets.token_bytes(nbytes)


def gen_aes_ctr_drbg(nbytes, seed=None):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key = seed or os.urandom(32)
    nonce = b"\x00" * 16
    enc = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    return enc.update(b"\x00" * nbytes)


def gen_weak_lcg(nbytes, seed=12345):
    a, c, m = 1103515245, 12345, 2 ** 31
    x = seed
    out = bytearray()
    for _ in range(nbytes):
        b = 0
        for bit in range(8):
            x = (a * x + c) % m
            b = (b << 1) | (x & 1)                         
        out.append(b)
    return bytes(out)


GENERATORS = {
    "os_urandom": gen_os_urandom,
    "secrets_csprng": gen_secrets,
    "aes_ctr_drbg": gen_aes_ctr_drbg,
    "weak_lcg": gen_weak_lcg,
}


                                                                             
def _bits(data):
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))


def monobit_test(data):
    bits = _bits(data)
    n = len(bits)
    s = np.sum(2 * bits.astype(np.int64) - 1)
    p = math.erfc(abs(s) / math.sqrt(2 * n))
    return {"name": "monobit", "p_value": round(p, 5), "pass": p >= 0.01}


def runs_test(data):
    bits = _bits(data)
    n = len(bits)
    pi = np.mean(bits)
    if abs(pi - 0.5) >= (2 / math.sqrt(n)):
        return {"name": "runs", "p_value": 0.0, "pass": False}
    vobs = 1 + int(np.sum(bits[1:] != bits[:-1]))
    num = abs(vobs - 2 * n * pi * (1 - pi))
    den = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    p = math.erfc(num / den)
    return {"name": "runs", "p_value": round(p, 5), "pass": p >= 0.01}


def shannon_entropy(data):
    arr = np.frombuffer(data, dtype=np.uint8)
    counts = np.bincount(arr, minlength=256)
    probs = counts[counts > 0] / len(arr)
    h = float(-np.sum(probs * np.log2(probs)))
    return {"name": "entropy_bits_per_byte", "value": round(h, 4), "pass": h >= 7.9}


def chi_square_test(data):
    arr = np.frombuffer(data, dtype=np.uint8)
    counts = np.bincount(arr, minlength=256)
    expected = len(arr) / 256.0
    chi = float(np.sum((counts - expected) ** 2 / expected))
                                          
    return {"name": "chi_square", "statistic": round(chi, 2), "pass": chi <= 330.0}


def assess_generator(gen_name, nbytes=131072):
    data = GENERATORS[gen_name](nbytes)
    tests = [monobit_test(data), runs_test(data),
             shannon_entropy(data), chi_square_test(data)]
    passed = sum(1 for t in tests if t["pass"])
                                                                                 
                                                                             
                                                                                  
                                                                               
                                                                            
                                                                                 
                                                         
    if passed >= len(tests) - 1:                     
        quality = "strong"
    elif passed == len(tests) - 2:                      
        quality = "good"
    else:                                            
        quality = "weak"
    return {"generator": gen_name, "bytes_tested": nbytes,
            "tests": tests, "tests_passed": passed,
            "tests_total": len(tests), "quality": quality}
