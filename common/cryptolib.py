import os
import time
import datetime

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography import x509
from cryptography.x509.oid import NameOID


                                                                                 
def aes_roundtrip(key_bits=256, mode="GCM", data=None, iters=200):
    data = data or os.urandom(4096)
    key = os.urandom(key_bits // 8)
    ok = True
    t0 = time.perf_counter()
    for _ in range(iters):
        if mode == "GCM":
            nonce = os.urandom(12)
            aead = AESGCM(key)
            ct = aead.encrypt(nonce, data, None)
            pt = aead.decrypt(nonce, ct, None)
        else:       
            iv = os.urandom(16)
            padder = PKCS7(128).padder()
            padded = padder.update(data) + padder.finalize()
            enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
            ct = enc.update(padded) + enc.finalize()
            dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
            unpadder = PKCS7(128).unpadder()
            pt = unpadder.update(dec.update(ct) + dec.finalize()) + unpadder.finalize()
        ok = ok and (pt == data)
    dt = time.perf_counter() - t0
    mbps = round((iters * len(data)) / dt / 1e6, 1) if dt else 0.0
    return {"suite": "AES-%d-%s" % (key_bits, mode), "verified": ok,
            "throughput_MBps": mbps, "iters": iters}


def demonstrate_nonce_reuse():
    key = os.urandom(32)
    nonce = os.urandom(12)                                          
    aead = AESGCM(key)
    p1 = b"transfer 0001 amount 100 to acct A"
    p2 = b"transfer 9999 amount 999 to acct B!"
    c1 = aead.encrypt(nonce, p1, None)[:len(p1)]                                
    c2 = aead.encrypt(nonce, p2, None)[:len(p2)]
    xor_ct = bytes(a ^ b for a, b in zip(c1, c2))
    xor_pt = bytes(a ^ b for a, b in zip(p1, p2))
    leaked = xor_ct == xor_pt
    return {"reused_nonce": nonce.hex(), "keystream_cancels": leaked,
            "verdict": "nonce reuse LEAKS plaintext XOR" if leaked else "safe"}


                                                                                   
CURVES = {"P-256": ec.SECP256R1, "P-224": ec.SECP224R1, "P-384": ec.SECP384R1}


def ecdsa_roundtrip(curve="P-256", iters=100):
    priv = ec.generate_private_key(CURVES[curve]())
    pub = priv.public_key()
    msg = os.urandom(256)
    ok = True
    t0 = time.perf_counter()
    for _ in range(iters):
        sig = priv.sign(msg, ec.ECDSA(hashes.SHA256()))
        try:
            pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        except Exception:
            ok = False
    dt = time.perf_counter() - t0
    return {"curve": curve, "key_bits": priv.key_size, "verified": ok,
            "sign_verify_per_s": round(iters / dt, 1) if dt else 0.0}


                                                                              
def build_and_validate_cert(cn="iiot-device", valid_days=365):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
                                                                                 
    not_before = now - datetime.timedelta(days=400)
    not_after = now + datetime.timedelta(days=valid_days)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .sign(key, hashes.SHA256()))
    der = cert.public_bytes(serialization.Encoding.DER)
    parsed = x509.load_der_x509_certificate(der)
    expired = parsed.not_valid_after_utc < now
    return {"subject": cn, "sig_algo": parsed.signature_hash_algorithm.name,
            "valid_days": valid_days, "expired": expired,
            "der_bytes": len(der),
            "status": "EXPIRED" if expired else "valid"}


                                                                           
def hash_benchmark(algo="SHA-256", data=None, iters=500):
    data = data or os.urandom(8192)
    t0 = time.perf_counter()
    digest = None
    for _ in range(iters):
        h = hashes.Hash(_HASH_CLASSES[algo]())
        h.update(data)
        digest = h.finalize()
    dt = time.perf_counter() - t0
    return {"algo": algo, "digest_hex": digest.hex()[:16] + "...",
            "throughput_MBps": round(iters * len(data) / dt / 1e6, 1) if dt else 0.0}


_HASH_CLASSES = {"SHA-256": hashes.SHA256, "SHA-384": hashes.SHA384,
                 "SHA-512": hashes.SHA512, "SHA-1": hashes.SHA1}


                                                                                
def measure_security_bits(cipher_bits, curve, hash_algo):
    sym_bits = int(cipher_bits)

    priv = ec.generate_private_key(CURVES[curve]())
    ecc_field_bits = priv.key_size                                         
    ecc_bits = ecc_field_bits // 2                                          

    h = hashes.Hash(_HASH_CLASSES[hash_algo]())
    h.update(b"iiot-security-probe")
    digest_bits = len(h.finalize()) * 8                                
    hash_bits = digest_bits // 2                                            
    if hash_algo == "SHA-1":
        hash_bits = 63                                                             

    overall = min(sym_bits, ecc_bits, hash_bits)
    return {"symmetric_bits": sym_bits, "ecc_field_bits": ecc_field_bits,
            "ecc_bits": ecc_bits, "digest_bits": digest_bits,
            "hash_bits": hash_bits, "overall_min_bits": overall}


                                                                               
def hmac_auth_check():
    key = os.urandom(32)
    msg = b"iiot telemetry frame"
    h = hmac.HMAC(key, hashes.SHA256()); h.update(msg)
    tag = h.finalize()
    v = hmac.HMAC(key, hashes.SHA256()); v.update(msg)
    try:
        v.verify(tag); good = True
    except Exception:
        good = False
    v2 = hmac.HMAC(key, hashes.SHA256()); v2.update(msg + b"x")
    try:
        v2.verify(tag); tamper_detected = False
    except Exception:
        tamper_detected = True
    return {"hmac_valid": good, "tamper_detected": tamper_detected}
