from threat_risk.assessment import _cvss, _epss, _crypto_compliance


def _signals(**overrides):
    base = {
        "rng_failed_tests": 0, "rng_weak": False, "cert_expired": False,
        "hash_deprecated": False, "curve_below_par": False, "cipher_ok": True,
        "secure_boot": True, "secure_element": True, "updatable": True,
        "gateway": False, "tls13": True,
    }
    base.update(overrides)
    return base


def test_cvss_clean_device_is_baseline():
    assert _cvss(_signals()) == 1.0


def test_cvss_rng_failure_adds_four_points():
    assert _cvss(_signals(rng_failed_tests=2)) == 5.0


def test_cvss_rng_single_failure_does_not_trigger_penalty():
                                                                                   
    assert _cvss(_signals(rng_failed_tests=1)) == 1.0


def test_cvss_caps_at_ten():
    worst = _signals(rng_failed_tests=4, cert_expired=True, hash_deprecated=True,
                     curve_below_par=True, tls13=False)
    assert _cvss(worst) == 10.0


def test_epss_baseline_is_point_zero_five():
    assert _epss(_signals()) == 0.05


def test_epss_weak_rng_dominates_weight():
    weak = _epss(_signals(rng_weak=True))
    boot = _epss(_signals(secure_boot=False))
    assert weak > boot                            


def test_epss_max_with_current_weights_is_point_eight_five():
                                                                            
                                                                           
                                                                       
    worst = _signals(rng_weak=True, secure_boot=False, cert_expired=True)
    assert _epss(worst) == 0.85


def test_crypto_compliance_all_good_is_one():
    assert _crypto_compliance(_signals()) == 1.0


def test_crypto_compliance_all_bad_is_zero():
    worst = _signals(rng_weak=True, cert_expired=True, hash_deprecated=True,
                     curve_below_par=True, cipher_ok=False, tls13=False)
    assert _crypto_compliance(worst) == 0.0
