
REPORT_KEYS = ["device", "risk_level", "root_cause", "recommendations",
               "compliance", "reasoning"]


def risk_bucket(risk):
    return ("critical" if risk >= 0.6 else "high" if risk >= 0.35
            else "medium" if risk >= 0.2 else "low")


def score_report(report, ref_risk):
    ref_bucket = risk_bucket(ref_risk)
    got_bucket = str(report.get("risk_level", "")).lower()
    level_ok = 1.0 if got_bucket == ref_bucket else (
        0.5 if abs(_ord(got_bucket) - _ord(ref_bucket)) == 1 else 0.0)
    ref_compliant = ref_risk < 0.2
    got_compliant = str(report.get("compliance", "")).upper() == "COMPLIANT"
    compliance_ok = 1.0 if got_compliant == ref_compliant else 0.0
    risky = ref_risk >= 0.2
    root_ok = 1.0 if (not risky or (report.get("root_cause")
                                    and report["root_cause"] != "none")) else 0.0
    has_recs = 1.0 if report.get("recommendations") else 0.0
    schema_ok = 1.0 if all(k in report for k in REPORT_KEYS) else 0.0
    overall = round(0.4 * level_ok + 0.2 * compliance_ok + 0.2 * root_ok
                    + 0.1 * has_recs + 0.1 * schema_ok, 3)
    return {"risk_level_ok": level_ok, "compliance_ok": compliance_ok,
            "root_cause_ok": root_ok, "has_recs": has_recs,
            "schema_ok": schema_ok, "overall": overall}


_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _ord(bucket):
    return _ORDER.get(bucket, 0)


def score_all(reports, ref_risk_map):
    per = {}
    for dev, rep in reports.items():
        per[dev] = score_report(rep, ref_risk_map[dev])
    mean = round(sum(p["overall"] for p in per.values()) / len(per), 3) if per else 0.0
    return per, mean


                                                                             
                                                                               
                                                                               
                                                                          
                                                                         
                                                           
                                                                             
_RELEVANT_TERMS = ["rng", "cert", "sha", "tls", "boot", "curve", "key", "firmware",
                   "root of trust", "update", "nonce", "hash"]


def _recommendation_quality(report):
    recs = report.get("recommendations") or []
    if not recs:
        return 0.0
    actionable = sum(1 for r in recs
                     if any(t in str(r).lower() for t in _RELEVANT_TERMS))
    return round(min(actionable / max(len(recs), 1), 1.0), 3)


def _reasoning_coherence(report):
    text = str(report.get("reasoning", "")).lower()
    if not text:
        return 0.0
    hits = sum(1 for t in _RELEVANT_TERMS if t in text)
    return round(min(hits / 3.0, 1.0), 3)                                          


def _schema_validity(report):
    present = sum(1 for k in REPORT_KEYS if k in report and report.get(k) not in (None, ""))
    return round(present / len(REPORT_KEYS), 3)


def score_report_fair(report, ref_risk):
    base = score_report(report, ref_risk)
                                                                            
                                                                               
    ref_bucket = risk_bucket(ref_risk)
    got_bucket = str(report.get("risk_level", "")).lower()
    exact_tier = 1.0 if got_bucket == ref_bucket else 0.0
    axes = {
        "oracle_agreement": round(0.6 * exact_tier
                                  + 0.2 * base["compliance_ok"]
                                  + 0.2 * base["root_cause_ok"], 3),
        "schema_validity": _schema_validity(report),
        "recommendation_quality": _recommendation_quality(report),
        "reasoning_coherence": _reasoning_coherence(report),
    }
                                                                        
                                                                                 
                                                                                  
    axes["overall"] = round(0.45 * axes["oracle_agreement"]
                            + 0.15 * axes["schema_validity"]
                            + 0.20 * axes["recommendation_quality"]
                            + 0.20 * axes["reasoning_coherence"], 3)
    return axes


def raw_tier_accuracy(reports, ref_risk_map):
    hits = att = 0
    for dev, rep in reports.items():
        raw = rep.get("raw_risk_level")
        if not raw:
            continue
        att += 1
        if str(raw).lower() == risk_bucket(ref_risk_map[dev]):
            hits += 1
    return (round(hits / att, 3) if att else None), att


def score_all_fair(reports, ref_risk_map):
    per = {dev: score_report_fair(rep, ref_risk_map[dev])
           for dev, rep in reports.items()}
    if not per:
        return {}, {}
    axes = ["oracle_agreement", "schema_validity", "recommendation_quality",
            "reasoning_coherence", "overall"]
    means = {a: round(sum(p[a] for p in per.values()) / len(per), 3) for a in axes}
    return per, means
