import argparse
import csv
import json
import statistics as st
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "multi_agent_experiments"))

from shared import evidence as evm, llm_client, llm_eval, task              
from shared import tools                                                     

RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)

N_TRIALS_DEFAULT = 5
_AGENTS = [("ConfigAgent", None), ("CryptoAgent", "security_bits"),
           ("RandomnessAgent", "rng_test"), ("CertAgent", "check_certificate")]

                                                                             
                                                                          
                                                                         
                                                                             
_FEWSHOT = """
Worked examples (for calibration only -- these are NOT the device you are assessing):

Example A - a genuinely clean device:
EVIDENCE: secure_boot=true, secure_element=true, rng_quality=strong, cert_status=valid, hash=SHA-256, curve=P-256, tls=1.3
CORRECT OUTPUT: {"risk_level":"low","root_cause":"none","recommendations":["Maintain posture; monitor cert lifetime"],"compliance":"COMPLIANT","reasoning":"All measured properties are within secure parameters; no weaknesses detected."}

Example B - a genuinely compromised device:
EVIDENCE: secure_boot=false, secure_element=false, rng_quality=weak, cert_status=EXPIRED, hash=SHA-1, curve=P-224, tls=1.2
CORRECT OUTPUT: {"risk_level":"critical","root_cause":"no root of trust","recommendations":["Enable secure boot","Replace PRNG with hardware TRNG","Renew certificate"],"compliance":"NON-COMPLIANT","reasoning":"Multiple simultaneous weaknesses: no root of trust, weak RNG, expired certificate, deprecated hash and curve, outdated TLS."}

A device with NO real weaknesses in its evidence should be labeled "low", not
"medium" -- do not hedge toward a higher tier when the evidence is clean.
"""

SYSTEM_FEWSHOT = ("You are a senior IIoT cryptography security analyst. Reason over the "
                  "provided evidence and specialist findings and return ONLY a JSON object "
                  "with keys: device, risk_level (critical|high|medium|low), root_cause, "
                  "recommendations (list), compliance (COMPLIANT|NON-COMPLIANT), reasoning."
                  + _FEWSHOT)


def _fixed_findings(dev_id):
    findings = []
    for name, tool_name in _AGENTS:
        obs = tools.run_tool(tool_name, dev_id) if tool_name else {}
        findings.append({"agent": name, "tool_used": tool_name, "observation": obs})
    return findings


def run_trials(n_trials):
    ev_all, ref = evm.build_evidence()
    rows = []
    for dev_id, ev in ev_all.items():
        truth = llm_eval.ground_truth_flags(ev)
        findings = _fixed_findings(dev_id)
        recall = "memory: no prior pattern for this RNG class"
        user = ("Specialist findings:\n%s\n\n%s\n\nEVIDENCE_JSON: %s" %
                (json.dumps(findings, default=str), recall, json.dumps(ev, default=str)))
        ref_tier = task.risk_bucket(ref["risk"][dev_id])

        raw_guesses = []
        for trial in range(1, n_trials + 1):
            text, meta = llm_client.complete(SYSTEM_FEWSHOT, user)
            report = llm_client.parse_json(text)
            raw = str(report.get("risk_level", "")).lower()
            raw_tier = raw if raw in ("critical", "high", "medium", "low") else None
            raw_guesses.append(raw_tier)
            hrate, n_claims = llm_eval.hallucination_rate(report, truth)
            correct = llm_eval.explanation_correctness(report, truth)
            rows.append({
                "device": dev_id, "trial": trial, "provider": meta.get("provider"),
                "latency_ms": meta.get("latency_ms"),
                "raw_risk_level": raw_tier or "unparseable",
                "reference_tier": ref_tier,
                "accuracy_hit": (1 if raw_tier == ref_tier else 0) if raw_tier else "",
                "hallucination_rate": hrate, "n_claims": n_claims,
                "explanation_correct": correct,
                "root_cause": report.get("root_cause", ""),
                "reasoning": report.get("reasoning", ""),
            })
            print("  %s trial %d/%d -> %s (ref=%s)" %
                 (dev_id, trial, n_trials, raw_tier or "unparseable", ref_tier), flush=True)
        cons, n_valid = llm_eval.consistency(raw_guesses)
        print("  %s: raw guesses=%s  consistency=%s (n=%d)  ref=%s" %
              (dev_id, raw_guesses, cons, n_valid, ref_tier), flush=True)
    return rows


def write_long_csv(rows):
    path = RESULTS / "llm_eval_trials_fewshot.csv"
    fields = ["device", "trial", "provider", "latency_ms", "raw_risk_level",
              "reference_tier", "accuracy_hit", "hallucination_rate", "n_claims",
              "explanation_correct", "root_cause", "reasoning"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    return path


def write_summary_csv(rows):
    path = RESULTS / "llm_eval_summary_fewshot.csv"
    devices = sorted({r["device"] for r in rows})
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["device", "n_trials", "llm_accuracy", "n_parseable",
                   "hallucination_rate_mean", "explanation_correctness_mean",
                   "consistency", "n_valid_for_consistency"])
        all_hits, all_n = 0, 0
        for dev in devices:
            sub = [r for r in rows if r["device"] == dev]
            hits = [r["accuracy_hit"] for r in sub if r["accuracy_hit"] != ""]
            acc = round(sum(hits) / len(hits), 3) if hits else None
            hall = round(st.mean(r["hallucination_rate"] for r in sub), 3)
            correct = round(st.mean(r["explanation_correct"] for r in sub), 3)
            guesses = [r["raw_risk_level"] if r["raw_risk_level"] != "unparseable" else None
                      for r in sub]
            cons, n_valid = llm_eval.consistency(guesses)
            w.writerow([dev, len(sub), acc, len(hits), hall, correct, cons, n_valid])
            all_hits += sum(hits); all_n += len(hits)
        w.writerow([])
        overall_acc = round(all_hits / all_n, 3) if all_n else None
        w.writerow(["OVERALL", len(rows), overall_acc, all_n, "", "", "", ""])
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=N_TRIALS_DEFAULT)
    args = ap.parse_args()
    print("Few-shot prompting test: %d trials x 5 devices against llama3.2:3b "
          "(SYSTEM prompt includes 2 synthetic worked examples)..." % args.trials)
    rows = run_trials(args.trials)
    long_path = write_long_csv(rows)
    summary_path = write_summary_csv(rows)
    print("\nwrote %s (%d rows)" % (long_path, len(rows)))
    print("wrote %s" % summary_path)


if __name__ == "__main__":
    main()
