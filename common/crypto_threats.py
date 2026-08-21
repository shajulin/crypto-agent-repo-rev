
                                                                     
CRYPTO_THREATS = {
    "rng_weak": ("Private-key / nonce recovery",
                 "predictable randomness lets an attacker reconstruct keys or nonces",
                 "NIST SP800-90A/B"),
    "nonce_reuse": ("Plaintext recovery (keystream reuse)",
                    "reused AEAD nonce leaks XOR of plaintexts and breaks integrity",
                    "NIST SP800-38D"),
    "cert_expired": ("Impersonation / MITM",
                     "expired or invalid certificate lets an attacker impersonate the peer",
                     "RFC 5280"),
    "hash_deprecated": ("Signature / collision forgery",
                        "SHA-1 collisions allow certificate and signature forgery",
                        "NIST SP800-131A"),
    "curve_below_par": ("Reduced security margin",
                        "P-224 gives <128-bit strength, vulnerable to future attacks",
                        "NIST SP800-186"),
    "tls_outdated": ("Protocol downgrade",
                     "TLS <1.3 exposes downgrade and legacy-cipher attacks",
                     "RFC 8446"),
    "no_root_of_trust": ("Firmware implant / persistence",
                         "no secure boot or secure element means no anchor to detect tampering",
                         "NIST SP800-193"),
}


def threats_for(signals):
    out = []
    for key, present in signals.items():
        if present and key in CRYPTO_THREATS:
            name, effect, ref = CRYPTO_THREATS[key]
            out.append({"condition": key, "attack": name,
                        "effect": effect, "reference": ref})
    return out
