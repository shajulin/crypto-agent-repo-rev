from collections import Counter

_CLAIM_KEYWORDS = {
    "rng_weak": ["rng", "random number generator", "prng", "predictable key",
                "predictable nonce", "randomness"],
    "cert_expired": ["certificate", "cert "],
    "hash_deprecated": ["sha-1", "sha1", "hash"],
    "curve_below_par": ["p-224", "curve", "curve strength"],
    "no_root_of_trust": ["root of trust", "secure boot", "secure element"],
    "not_updatable": ["update path", "updatable", "firmware update", "patch"],
    "tls_outdated": ["tls"],
}

                                                                             
                                                                              
                                                                          
                                                                            
                                                                             
                                                                        
                                                 
 
                                                                              
                                                                           
                                                                            
                                                                            
                                                                             
                                                                           
                                                                            
                                                                             
                                                                        
                                                                          
                                                                         
                                                                    
                                                                            
                                                    
 
                                                                        
                                        
                                                                            
                                                                             
                                                                         
                                                               
                                       
                                                                  
                                                                         
                                         
                                                                            
                                         
_PROBLEM_INDICATORS = [
    "weak", "expired", "deprecated", "outdated", "below-par", "below par",
    "vulnerable", "insufficient", "lacks", "lacking", "missing", "no ",
    "not present", "invalid", "compromised", "predictable", "downgrade",
    "unpatchable", "stuck", "broken", "fails", "failed", "poor", "insecure",
]

                                                                          
                                                                              
_NEGATION_CUES = ["not ", "n't ", "no longer", "never ", "without ", "free of",
                  "free from", "isn't", "aren't", "doesn't", "don't", "wasn't"]
_NEGATION_WINDOW = 20


def ground_truth_flags(ev):
    cfg, meas = ev["config"], ev["measurements"]
    return {
        "rng_weak": meas["rng_quality"] == "weak",
        "cert_expired": meas["cert_status"] == "EXPIRED",
        "hash_deprecated": cfg["hash"] == "SHA-1",
        "curve_below_par": cfg["curve"] == "P-224",
        "no_root_of_trust": not cfg["secure_boot"] and not cfg["secure_element"],
        "not_updatable": not cfg["updatable"],
        "tls_outdated": cfg["tls"] != "1.3",
    }


def _norm(text):
    return text.replace("_", " ")


def _sentences(text):
    import re
    parts = re.split(r"[.;\n](?!\d)", text)
    out = []
    for p in parts:
                                                                             
                                                                           
                                                                 
        out.extend(re.split(r"(?:^|\s+)(?:despite|although|however|but|while)\s+", p))
    return [s for s in out if s.strip()]


                                                                             
                                                                             
                                                                          
                                                                         
                                                                   
                                                                           
                                                       
_BENIGN_NO_FOLLOWUPS = ["issue", "problem", "concern", "weakness", "vulnerabilit", "finding",
                        "threat", "risk identified", "risks identified"]
                                                                            
                                                                          
                                                                        
_BENIGN_NO_WINDOW = 45


                                                                          
                                                                            
                                                                           
                                                                            
                                                      
_PROXIMITY_WINDOW = 55


def _unnegated_problem_word_spans(sentence):
    spans = []
    for p in _PROBLEM_INDICATORS:
        start = 0
        while True:
            idx = sentence.find(p, start)
            if idx == -1:
                break
            if p == "no ":
                after = sentence[idx + len(p):idx + len(p) + _BENIGN_NO_WINDOW]
                if any(w in after for w in _BENIGN_NO_FOLLOWUPS):
                    start = idx + len(p)
                    continue
            window = sentence[max(0, idx - _NEGATION_WINDOW):idx]
            if not any(cue in window for cue in _NEGATION_CUES):
                spans.append((idx, idx + len(p)))
            start = idx + len(p)
    return spans


def _has_unnegated_problem_word(sentence):
    return bool(_unnegated_problem_word_spans(sentence))


def _span_distance(a_start, a_end, b_start, b_end):
    if a_end <= b_start:
        return b_start - a_end
    if b_end <= a_start:
        return a_start - b_end
    return 0               


def _mentioned_claims(text):
    claimed = []
    for sentence in _sentences(_norm(text.lower())):
        problem_spans = _unnegated_problem_word_spans(sentence)
        if not problem_spans:
            continue
        for flag, kws in _CLAIM_KEYWORDS.items():
            if flag in claimed:
                continue
            for kw in kws:
                idx = sentence.find(kw)
                if idx == -1:
                    continue
                kw_end = idx + len(kw)
                if any(_span_distance(idx, kw_end, ps, pe) <= _PROXIMITY_WINDOW
                      for ps, pe in problem_spans):
                    claimed.append(flag)
                    break
    return claimed


def hallucination_rate(report, truth):
    text = "%s %s" % (report.get("root_cause", ""), report.get("reasoning", ""))
    claimed = _mentioned_claims(text)
    if not claimed:
        return 0.0, 0
    false_claims = [f for f in claimed if not truth.get(f, False)]
    return round(len(false_claims) / len(claimed), 3), len(claimed)


def explanation_correctness(report, truth):
    active = [f for f, v in truth.items() if v]
    root_raw = str(report.get("root_cause", "")).strip().lower()
    if not active:
        return 1.0 if root_raw in ("", "none") else 0.0
    root = _norm(root_raw)
    hit = any(any(kw in root for kw in _CLAIM_KEYWORDS[f]) for f in active)
    return 1.0 if hit else 0.0


def compliance_accuracy(report, truth):
    got = str(report.get("compliance", "")).strip().upper()
    if got not in ("COMPLIANT", "NON-COMPLIANT"):
        return None
    ref_compliant = not any(truth.values())
    got_compliant = got == "COMPLIANT"
    return 1.0 if got_compliant == ref_compliant else 0.0


def consistency(raw_tier_guesses):
    valid = [g for g in raw_tier_guesses if g]
    if not valid:
        return None, 0
    modal_count = Counter(valid).most_common(1)[0][1]
    return round(modal_count / len(valid), 3), len(valid)
