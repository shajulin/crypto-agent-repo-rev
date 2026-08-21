from common import rng_tests


def test_weak_lcg_is_deterministically_weak():
    r = rng_tests.assess_generator("weak_lcg", nbytes=32768)
    assert r["quality"] == "weak"
    assert r["tests_passed"] <= 1


def test_os_urandom_is_strong():
    r = rng_tests.assess_generator("os_urandom", nbytes=131072)
    assert r["quality"] in ("strong", "good")
    assert r["tests_passed"] >= 2


def test_secrets_csprng_is_strong():
    r = rng_tests.assess_generator("secrets_csprng", nbytes=131072)
    assert r["quality"] in ("strong", "good")


def test_aes_ctr_drbg_is_strong():
    r = rng_tests.assess_generator("aes_ctr_drbg", nbytes=131072)
    assert r["quality"] in ("strong", "good")


def test_tests_total_is_four():
    r = rng_tests.assess_generator("os_urandom", nbytes=4096)
    assert r["tests_total"] == 4
    assert r["tests_passed"] == sum(1 for t in r["tests"] if t["pass"])


def test_monobit_perfectly_balanced_passes():
    balanced = bytes([0b10101010] * 1000)
    result = rng_tests.monobit_test(balanced)
    assert result["pass"] is True


def test_shannon_entropy_constant_byte_is_zero():
    constant = bytes([0x42] * 1000)
    result = rng_tests.shannon_entropy(constant)
    assert result["value"] == 0.0
    assert result["pass"] is False


def test_chi_square_uniform_distribution_passes():
    uniform = bytes(range(256)) * 100
    result = rng_tests.chi_square_test(uniform)
    assert result["pass"] is True
