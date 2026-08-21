import argparse
import csv
import json
import statistics as st
import sys
import time
from pathlib import Path
from urllib import request as urlrequest

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "multi_agent_experiments"))

from shared import evidence as evm, llm_eval, task              

RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)

N_TRIALS_DEFAULT = 10
_LEVELS = {"critical", "high", "medium", "low"}
OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
MODEL = "llama3.2:3b"


def _actor_causes(ev):
    cfg, meas = ev["config"], ev["measurements"]
    causes = []
    if not cfg["secure_boot"] and not cfg["secure_element"]:
        causes.append("no_root_of_trust")
    if not cfg.get("updatable", True):
        causes.append("not_updatable")
    if meas["rng_quality"] == "weak":
        causes.append("weak_rng")
    if meas["cert_status"] == "EXPIRED":
        causes.append("expired_cert")
    if cfg["hash"] == "SHA-1":
        causes.append("deprecated_hash")
    if cfg["curve"] == "P-224":
        causes.append("below_par_curve")
    if cfg["tls"] != "1.3":
        causes.append("outdated_tls")
    return causes


def _prompt(dev_id, ev, causes):
    cfg, meas = ev["config"], ev["measurements"]
    return (
        "You are an IIoT cryptographic-posture analyst. Assess ONE device from the\n"
        "evidence and reply with ONLY a JSON object, nothing else:\n"
        '{"risk_level":"critical|high|medium|low","reasoning":"<2 sentences naming the\n'
        'concrete weaknesses: rng, cert, hash, curve, tls, secure boot, firmware>"}\n'
        "Device %s evidence:\n"
        "  aggregate_risk=%s\n"
        "  rng_quality=%s, cert_status=%s\n"
        "  hash=%s, curve=%s, tls=%s\n"
        "  secure_boot=%s, secure_element=%s\n"
        "  detected_issues=%s" % (
            dev_id, ev["aggregate_risk"], meas["rng_quality"], meas["cert_status"],
            cfg["hash"], cfg["curve"], cfg["tls"], cfg["secure_boot"], cfg["secure_element"],
            ",".join(causes)))


def _call_llm(prompt):
    body = json.dumps({"model": MODEL, "prompt": prompt, "stream": False,
                       "options": {"temperature": 0}}).encode("utf-8")
    req = urlrequest.Request(OLLAMA_URL, data=body,
                             headers={"Content-Type": "application/json"}, method="POST")
    t0 = time.time()
    try:
        with urlrequest.urlopen(req, timeout=300) as resp:
            text = json.loads(resp.read().decode("utf-8"))["response"]
    except Exception as e:                                                
        return None, "LLM unreachable (%s)" % type(e).__name__, round((time.time() - t0) * 1000, 1)
    latency = round((time.time() - t0) * 1000, 1)
    js, je = text.find("{"), text.rfind("}")
    if js >= 0 and je > js:
        try:
            parsed = json.loads(text[js:je + 1])
            tier = str(parsed.get("risk_level", "")).lower().strip()
            reasoning = str(parsed.get("reasoning", text.strip()))[:400]
            return (tier if tier in _LEVELS else None), reasoning, latency
        except Exception:                                                
            pass
    return None, text.strip()[:400], latency


def run_trials(n_trials):
    ev_all, ref = evm.build_evidence()
    rows = []
    for dev_id, ev in ev_all.items():
        truth = llm_eval.ground_truth_flags(ev)
        ref_tier = task.risk_bucket(ref["risk"][dev_id])
        causes = _actor_causes(ev)                                                
        prompt = _prompt(dev_id, ev, causes)                                          
        raw_guesses = []
        for trial in range(1, n_trials + 1):
            tier, reasoning, latency_ms = _call_llm(prompt)
            raw_guesses.append(tier)
            root_cause = causes[0] if causes else "none"
            report = {"root_cause": root_cause, "reasoning": reasoning}
            hrate, n_claims = llm_eval.hallucination_rate(report, truth)
            correct = llm_eval.explanation_correctness(report, truth)
                                                                                   
                                                                              
                                                                               
                                                                                
            rows.append({
                "device": dev_id, "trial": trial, "latency_ms": latency_ms,
                "raw_risk_level": tier or "unparseable", "reference_tier": ref_tier,
                "accuracy_hit": (1 if tier == ref_tier else 0) if tier else "",
                "hallucination_rate": hrate, "n_claims": n_claims,
                "explanation_correct": correct, "compliance": "", "compliance_accuracy": "",
                "root_cause": root_cause, "reasoning": reasoning,
            })
            print("  %s trial %d/%d -> %s (%.1fs)" %
                 (dev_id, trial, n_trials, tier or "unparseable", latency_ms / 1000), flush=True)
        cons, n_valid = llm_eval.consistency(raw_guesses)
        print("  %s: consistency=%s (n=%d)  ref=%s" % (dev_id, cons, n_valid, ref_tier), flush=True)
    return rows


def write_long_csv(rows, suffix=""):
    path = RESULTS / ("akka_eval_trials%s.csv" % suffix)
    fields = ["device", "trial", "latency_ms", "raw_risk_level", "reference_tier",
              "accuracy_hit", "hallucination_rate", "n_claims", "explanation_correct",
              "compliance", "compliance_accuracy", "root_cause", "reasoning"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    return path


def write_summary_csv(rows, suffix=""):
    path = RESULTS / ("akka_eval_summary%s.csv" % suffix)
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
    global MODEL
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=N_TRIALS_DEFAULT)
    ap.add_argument("--model", type=str, default="llama3.2:3b",
                    help="Ollama model tag. Non-default models write to "
                         "*_<model>.csv so the llama3.2:3b baseline is never overwritten.")
    args = ap.parse_args()
    MODEL = args.model
    suffix = "_%s" % args.model.replace(":", "_").replace(".", "_") if args.model != "llama3.2:3b" else ""
    print("Running %d trials x 5 devices against the REAL Akka Risk-Lead prompt "
          "(reproduced verbatim from Main.scala) + local Ollama (%s)..." % (args.trials, args.model))
    rows = run_trials(args.trials)
    long_path = write_long_csv(rows, suffix=suffix)
    summary_path = write_summary_csv(rows, suffix=suffix)
    print("\nwrote %s (%d rows)" % (long_path, len(rows)))
    print("wrote %s" % summary_path)


if __name__ == "__main__":
    main()
