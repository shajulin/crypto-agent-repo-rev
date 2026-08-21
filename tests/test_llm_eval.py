import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "multi_agent_experiments"))
from shared import llm_eval              

CLEAN_TRUTH = {"rng_weak": False, "cert_expired": False, "hash_deprecated": False,
               "curve_below_par": False, "no_root_of_trust": False,
               "not_updatable": False, "tls_outdated": False}


def test_positive_mention_is_not_a_false_claim():
    report = {"root_cause": "The device's cipher suite meets the recommended standard.",
              "reasoning": "It is important to verify that the secure boot "
                           "mechanism is functioning correctly."}
    rate, n_claims = llm_eval.hallucination_rate(report, CLEAN_TRUTH)
    assert n_claims == 0
    assert rate == 0.0


def test_genuine_false_claim_is_detected():
    report = {"root_cause": "weak RNG", "reasoning": "The RNG is weak and predictable."}
    rate, n_claims = llm_eval.hallucination_rate(report, CLEAN_TRUTH)
    assert n_claims == 1
    assert rate == 1.0


def test_true_claim_is_not_hallucinated():
    truth = dict(CLEAN_TRUTH, rng_weak=True)
    report = {"root_cause": "weak RNG", "reasoning": "The RNG is weak and predictable."}
    rate, n_claims = llm_eval.hallucination_rate(report, truth)
    assert n_claims == 1
    assert rate == 0.0


def test_no_claims_made_gives_zero_rate_not_perfect_score():
    report = {"root_cause": "none", "reasoning": "Device looks fine."}
    rate, n_claims = llm_eval.hallucination_rate(report, CLEAN_TRUTH)
    assert n_claims == 0 and rate == 0.0


def test_explanation_correctness_none_for_clean_device():
    assert llm_eval.explanation_correctness({"root_cause": "none"}, CLEAN_TRUTH) == 1.0
    assert llm_eval.explanation_correctness({"root_cause": "weak RNG"}, CLEAN_TRUTH) == 0.0


def test_explanation_correctness_names_active_weakness():
    truth = dict(CLEAN_TRUTH, cert_expired=True)
    assert llm_eval.explanation_correctness({"root_cause": "expired certificate"}, truth) == 1.0
    assert llm_eval.explanation_correctness({"root_cause": "weak RNG"}, truth) == 0.0


def test_consistency_perfect_agreement():
    cons, n = llm_eval.consistency(["low", "low", "low"])
    assert cons == 1.0 and n == 3


def test_consistency_partial_agreement():
    cons, n = llm_eval.consistency(["low", "low", "medium"])
    assert round(cons, 3) == round(2 / 3, 3) and n == 3


def test_consistency_excludes_unparseable():
    cons, n = llm_eval.consistency(["low", None, "low"])
    assert cons == 1.0 and n == 2


def test_explanation_correctness_handles_snake_case_root_cause():
                                                                         
                                                                      
    truth = dict(CLEAN_TRUTH, no_root_of_trust=True)
    assert llm_eval.explanation_correctness({"root_cause": "no_root_of_trust"}, truth) == 1.0


def test_explanation_correctness_snake_case_wrong_flag_still_fails():
    truth = dict(CLEAN_TRUTH, cert_expired=True)
    assert llm_eval.explanation_correctness({"root_cause": "no_root_of_trust"}, truth) == 0.0


def test_negated_problem_word_is_not_a_claim():
    report = {"root_cause": "", "reasoning": "The certificate is not expired."}
    rate, n = llm_eval.hallucination_rate(report, CLEAN_TRUTH)
    assert n == 0 and rate == 0.0


def test_negated_with_contraction_is_not_a_claim():
    report = {"root_cause": "", "reasoning": "The RNG isn't weak."}
    rate, n = llm_eval.hallucination_rate(report, CLEAN_TRUTH)
    assert n == 0 and rate == 0.0


def test_unnegated_claim_still_detected_after_negation_fix():
    report = {"root_cause": "", "reasoning": "The RNG is weak and predictable."}
    rate, n = llm_eval.hallucination_rate(report, CLEAN_TRUTH)
    assert n == 1 and rate == 1.0


def test_negation_far_before_problem_word_does_not_suppress_it():
                                                                          
                                                                         
                                                                         
                                                                       
                                                                 
    report = {"root_cause": "", "reasoning": "It is not clear whether that helps, "
             "but the certificate has expired regardless."}
    rate, n = llm_eval.hallucination_rate(report, CLEAN_TRUTH)
    assert n == 1 and rate == 1.0


def test_sentence_level_granularity_FIXED_by_clause_splitting():
                                                                         
                                                                          
                                                                           
                                                          
    report = {"root_cause": "", "reasoning": "It is not clear whether patching helps, "
             "but the certificate has expired regardless."}
    rate, n = llm_eval.hallucination_rate(report, CLEAN_TRUTH)
    assert n == 1 and rate == 1.0                     


def test_compliance_accuracy_matches_clean_device():
    assert llm_eval.compliance_accuracy({"compliance": "COMPLIANT"}, CLEAN_TRUTH) == 1.0
    assert llm_eval.compliance_accuracy({"compliance": "NON-COMPLIANT"}, CLEAN_TRUTH) == 0.0


def test_compliance_accuracy_matches_weak_device():
    truth = dict(CLEAN_TRUTH, rng_weak=True)
    assert llm_eval.compliance_accuracy({"compliance": "NON-COMPLIANT"}, truth) == 1.0
    assert llm_eval.compliance_accuracy({"compliance": "COMPLIANT"}, truth) == 0.0


def test_compliance_accuracy_none_when_unparseable():
    assert llm_eval.compliance_accuracy({"compliance": ""}, CLEAN_TRUTH) is None
    assert llm_eval.compliance_accuracy({}, CLEAN_TRUTH) is None


def test_no_detected_issues_is_not_a_claim():
                                                                              
                                                                          
                                                                           
                                                                
    report = {"root_cause": "none", "reasoning": (
        "aggregate_risk is low, rng_quality and cert_status are strong, "
        "TLS version 1.3 is secure, secure boot and secure element are "
        "enabled, no detected issues")}
    rate, n = llm_eval.hallucination_rate(report, CLEAN_TRUTH)
    assert n == 0 and rate == 0.0


def test_no_problems_found_is_not_a_claim():
    report = {"root_cause": "", "reasoning": "The scan found no problems in this device."}
    rate, n = llm_eval.hallucination_rate(report, CLEAN_TRUTH)
    assert n == 0 and rate == 0.0


def test_no_root_of_trust_still_detected_as_genuine_claim():
    report = {"root_cause": "", "reasoning": "The device has no root of trust."}
    rate, n = llm_eval.hallucination_rate(report, CLEAN_TRUTH)
    assert n == 1 and rate == 1.0                                      


def test_decimal_version_number_does_not_split_sentence():
                                                                        
                                                                             
                                                           
    sentences = llm_eval._sentences("tls version 1.3 is secure and modern.")
    assert len(sentences) == 1
    assert "1.3" in sentences[0]


def test_decimal_number_inside_longer_report_still_one_sentence():
    sentences = llm_eval._sentences(
        "aggregate_risk is 0.78, which is high. secure_boot is enabled.")
    assert len(sentences) == 2
    assert "0.78" in sentences[0]


def test_sentence_ending_after_a_number_still_splits():
                                                                    
                                                                       
                                                                       
    sentences = llm_eval._sentences(
        "the certificate is valid and signed using sha-256. no immediate "
        "threats or vulnerabilities are identified.")
    assert len(sentences) == 2
    assert "certificate" in sentences[0] and "certificate" not in sentences[1]


def test_no_immediate_threats_identified_is_not_a_claim():
                                                                          
                                                                           
                                                                  
                                                                        
                   
    report = {"root_cause": "Strong cryptographic configurations and no "
             "immediate threats identified.",
              "reasoning": ("The certificate is valid and signed using SHA-256. "
                           "No immediate threats or vulnerabilities are "
                           "identified based on the provided evidence.")}
    rate, n = llm_eval.hallucination_rate(report, CLEAN_TRUTH)
    assert n == 0 and rate == 0.0


def test_despite_clause_does_not_over_attribute_to_good_properties():
                                                                      
                                                                          
                                                                          
                                                                             
    report = {"root_cause": "outdated TLS", "reasoning": (
        "The device uses an outdated TLS version (1.2), which is vulnerable "
        "to newer attacks despite having a strong RNG and valid certificates.")}
    truth = dict(CLEAN_TRUTH, tls_outdated=True)
    rate, n = llm_eval.hallucination_rate(report, truth)
    assert n == 1 and rate == 0.0                                            


def test_however_clause_also_splits():
    report = {"root_cause": "", "reasoning": (
        "The RNG is strong, however the certificate has expired.")}
    rate, n = llm_eval.hallucination_rate(report, CLEAN_TRUTH)
    assert n == 1 and rate == 1.0                                       


def test_leading_although_is_a_known_remaining_gap():
                                                                          
                                                                    
                                                                         
                                                                         
                                                                         
                                                                         
                                                                     
    report = {"root_cause": "", "reasoning": (
        "Although the RNG is strong, the certificate has expired.")}
    rate, n = llm_eval.hallucination_rate(report, CLEAN_TRUTH)
    assert n == 2                                                                  


def test_proximity_still_catches_close_together_claims_across_words():
    report = {"root_cause": "", "reasoning": (
        "The hash algorithm SHA-1 is deprecated and should be replaced.")}
    rate, n = llm_eval.hallucination_rate(report, CLEAN_TRUTH)
    assert n == 1 and rate == 1.0
