import argparse
import csv
import json
import statistics as st
import sys
import time
from collections import Counter
from pathlib import Path
from urllib import request as urlrequest

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "multi_agent_experiments"))

from shared import evidence as evm, llm_eval, task              
from own_framework import agent_runtime                          
from shared import tools                                          

RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)

N_TRIALS_DEFAULT = 5
K_DEFAULT = 5
TEMPERATURE = 0.7
OLLAMA_URL = "http://127.0.0.1:11434/api/chat"
MODEL = "llama3.2:3b"
_AGENTS = [("ConfigAgent", None), ("CryptoAgent", "security_bits"),
           ("RandomnessAgent", "rng_test"), ("CertAgent", "check_certificate")]
_LEVELS = ("critical", "high", "medium", "low")


def _fixed_findings(dev_id):
    findings = []
    for name, tool_name in _AGENTS:
        obs = tools.run_tool(tool_name, dev_id) if tool_name else {}
        findings.append({"agent": name, "tool_used": tool_name, "observation": obs})
    return findings


def _sample(system, user, seed):
    body = json.dumps({
        "model": MODEL, "stream": False,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "options": {"temperature": TEMPERATURE, "seed": seed, "top_p": 1},
    }).encode("utf-8")
    req = urlrequest.Request(OLLAMA_URL, data=body,
                             headers={"Content-Type": "application/json"}, method="POST")
    t0 = time.time()
    try:
        with urlrequest.urlopen(req, timeout=300) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            text = data.get("message", {}).get("content", "")
    except Exception as e:                                            
        return {}, round((time.time() - t0) * 1000, 1)
    latency = round((time.time() - t0) * 1000, 1)
    report = llm_eval_parse(text)
    return report, latency


def llm_eval_parse(text):
    import re
    m = re.search(r"\{.*\}", str(text), re.S)
    if not m:
        return {}
    try:
        return json.loads(m.group(0))
    except Exception:                                                 
        return {}


def run_trials(n_trials, k):
    ev_all, ref = evm.build_evidence()
    rows = []
    for dev_id, ev in ev_all.items():
        truth = llm_eval.ground_truth_flags(ev)
        findings = _fixed_findings(dev_id)
        recall = "memory: no prior pattern for this RNG class"
        user = ("Specialist findings:\n%s\n\n%s\n\nEVIDENCE_JSON: %s" %
                (json.dumps(findings, default=str), recall, json.dumps(ev, default=str)))
        ref_tier = task.risk_bucket(ref["risk"][dev_id])

        trial_votes = []
        for trial in range(1, n_trials + 1):
            samples = []
            for ki in range(k):
                seed = trial * 1000 + ki                                                    
                report, latency_ms = _sample(agent_runtime.SYSTEM, user, seed)
                raw = str(report.get("risk_level", "")).lower()
                tier = raw if raw in _LEVELS else None
                samples.append((tier, report, latency_ms))
                print("    %s trial %d sample %d/%d -> %s (%.1fs)" %
                     (dev_id, trial, ki + 1, k, tier or "unparseable", latency_ms / 1000),
                     flush=True)

            valid_tiers = [t for t, _, _ in samples if t]
            if valid_tiers:
                majority_tier, votes = Counter(valid_tiers).most_common(1)[0]
                                                                                
                rep_report = next(r for t, r, _ in samples if t == majority_tier)
                agreement = votes / len(valid_tiers)
            else:
                majority_tier, rep_report, agreement = None, {}, 0.0

            trial_votes.append(majority_tier)
            hrate, n_claims = llm_eval.hallucination_rate(rep_report, truth)
            correct = llm_eval.explanation_correctness(rep_report, truth)
            total_latency = sum(lat for _, _, lat in samples)
            rows.append({
                "device": dev_id, "trial": trial, "k": k,
                "majority_tier": majority_tier or "unparseable",
                "vote_agreement": round(agreement, 3),
                "reference_tier": ref_tier,
                "accuracy_hit": (1 if majority_tier == ref_tier else 0) if majority_tier else "",
                "hallucination_rate": hrate, "n_claims": n_claims,
                "explanation_correct": correct,
                "root_cause": rep_report.get("root_cause", ""),
                "reasoning": rep_report.get("reasoning", ""),
                "total_latency_ms": round(total_latency, 1),
            })
            print("  %s trial %d/%d -> majority=%s (agreement=%.2f)  ref=%s" %
                 (dev_id, trial, n_trials, majority_tier or "unparseable", agreement, ref_tier),
                 flush=True)
        cons, n_valid = llm_eval.consistency(trial_votes)
        print("  %s: consistency across trials=%s (n=%d)" % (dev_id, cons, n_valid), flush=True)
    return rows


def write_long_csv(rows):
    path = RESULTS / "llm_eval_trials_selfconsistency.csv"
    fields = ["device", "trial", "k", "majority_tier", "vote_agreement", "reference_tier",
              "accuracy_hit", "hallucination_rate", "n_claims", "explanation_correct",
              "root_cause", "reasoning", "total_latency_ms"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    return path


def write_summary_csv(rows):
    path = RESULTS / "llm_eval_summary_selfconsistency.csv"
    devices = sorted({r["device"] for r in rows})
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["device", "n_trials", "llm_accuracy", "n_parseable",
                   "mean_vote_agreement", "hallucination_rate_mean",
                   "explanation_correctness_mean"])
        all_hits, all_n = 0, 0
        for dev in devices:
            sub = [r for r in rows if r["device"] == dev]
            hits = [r["accuracy_hit"] for r in sub if r["accuracy_hit"] != ""]
            acc = round(sum(hits) / len(hits), 3) if hits else None
            agree = round(st.mean(r["vote_agreement"] for r in sub), 3)
            hall = round(st.mean(r["hallucination_rate"] for r in sub), 3)
            correct = round(st.mean(r["explanation_correct"] for r in sub), 3)
            w.writerow([dev, len(sub), acc, len(hits), agree, hall, correct])
            all_hits += sum(hits); all_n += len(hits)
        w.writerow([])
        overall_acc = round(all_hits / all_n, 3) if all_n else None
        w.writerow(["OVERALL", len(rows), overall_acc, all_n, "", "", ""])
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=N_TRIALS_DEFAULT)
    ap.add_argument("--k", type=int, default=K_DEFAULT)
    args = ap.parse_args()
    print("Self-consistency voting: %d trials x 5 devices x k=%d samples/trial "
          "(temperature=%.1f, real independent draws) against llama3.2:3b..."
          % (args.trials, args.k, TEMPERATURE))
    print("Total real LLM calls: %d\n" % (args.trials * 5 * args.k))
    rows = run_trials(args.trials, args.k)
    long_path = write_long_csv(rows)
    summary_path = write_summary_csv(rows)
    print("\nwrote %s (%d rows)" % (long_path, len(rows)))
    print("wrote %s" % summary_path)


if __name__ == "__main__":
    main()
