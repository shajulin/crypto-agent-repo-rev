import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "multi_agent_experiments"))
from shared import llm_eval              

CLEAN_TRUTH = {"rng_weak": False, "cert_expired": False, "hash_deprecated": False,
               "curve_below_par": False, "no_root_of_trust": False,
               "not_updatable": False, "tls_outdated": False}
WEAK_RNG_TRUTH = dict(CLEAN_TRUTH, rng_weak=True)


def test_hedged_claim_still_detected():
                                                                           
                                                                             
    report = {"root_cause": "", "reasoning": "There might be a weak RNG issue here."}
    rate, n = llm_eval.hallucination_rate(report, CLEAN_TRUTH)
    assert n == 1 and rate == 1.0


def test_comparative_phrasing_detected():
    report = {"root_cause": "", "reasoning": "Compared to modern standards, this hash "
             "algorithm is deprecated and should be replaced."}
    rate, n = llm_eval.hallucination_rate(report, CLEAN_TRUTH)
    assert n == 1 and rate == 1.0


def test_case_insensitive():
    report = {"root_cause": "", "reasoning": "THE CERTIFICATE HAS EXPIRED."}
    rate, n = llm_eval.hallucination_rate(report, CLEAN_TRUTH)
    assert n == 1 and rate == 1.0


def test_multiple_true_claims_all_grounded():
    truth = dict(CLEAN_TRUTH, rng_weak=True, cert_expired=True)
    report = {"root_cause": "weak rng and expired cert",
              "reasoning": "The RNG is weak and the certificate has expired."}
    rate, n = llm_eval.hallucination_rate(report, truth)
    assert n == 2 and rate == 0.0


def test_mixed_true_and_false_claims_partial_rate():
                                                           
    report = {"root_cause": "", "reasoning": "The RNG is weak. The hash algorithm "
             "is deprecated."}
    rate, n = llm_eval.hallucination_rate(report, WEAK_RNG_TRUTH)
    assert n == 2 and rate == 0.5


def test_praise_only_report_makes_no_claims():
    report = {"root_cause": "none", "reasoning": "This device follows security best "
             "practices with a modern cipher suite and valid configuration."}
    rate, n = llm_eval.hallucination_rate(report, CLEAN_TRUTH)
    assert n == 0 and rate == 0.0


def test_explanation_correctness_case_and_whitespace_insensitive():
    truth = dict(CLEAN_TRUTH, tls_outdated=True)
    assert llm_eval.explanation_correctness({"root_cause": "  OUTDATED TLS  "}, truth) == 1.0


def test_explanation_correctness_wrong_but_plausible_sounding_cause():
                                                                              
                                                                       
                                                                 
    truth = dict(CLEAN_TRUTH, tls_outdated=True)
    result = llm_eval.explanation_correctness({"root_cause": "insecure protocol version"}, truth)
    assert result == 0.0                                                         


def test_consistency_all_different_is_low():
    cons, n = llm_eval.consistency(["low", "medium", "high", "critical"])
    assert cons == 0.25 and n == 4
