import argparse
import csv
import json
import statistics as st
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "multi_agent_experiments"))

from shared import evidence as evm, llm_client, llm_eval, task              
from own_framework import agent_runtime                                      
from shared import tools                                                     

RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)

N_TRIALS_DEFAULT = 10
_AGENTS = [("ConfigAgent", None), ("CryptoAgent", "security_bits"),
           ("RandomnessAgent", "rng_test"), ("CertAgent", "check_certificate")]


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
            text, meta = llm_client.complete(agent_runtime.SYSTEM, user)
            report = llm_client.parse_json(text)
            raw = str(report.get("risk_level", "")).lower()
            raw_tier = raw if raw in ("critical", "high", "medium", "low") else None
            raw_guesses.append(raw_tier)
            hrate, n_claims = llm_eval.hallucination_rate(report, truth)
            correct = llm_eval.explanation_correctness(report, truth)
            comp_acc = llm_eval.compliance_accuracy(report, truth)
            claimed_flags = llm_eval._mentioned_claims(
                "%s %s" % (report.get("root_cause", ""), report.get("reasoning", "")))
            rows.append({
                "device": dev_id, "trial": trial, "provider": meta.get("provider"),
                "latency_ms": meta.get("latency_ms"),
                "raw_risk_level": raw_tier or "unparseable",
                "reference_tier": ref_tier,
                "accuracy_hit": (1 if raw_tier == ref_tier else 0) if raw_tier else "",
                "hallucination_rate": hrate, "n_claims": n_claims,
                "claimed_flags": ";".join(claimed_flags),
                "explanation_correct": correct,
                "compliance": report.get("compliance", ""),
                "compliance_accuracy": "" if comp_acc is None else comp_acc,
                "root_cause": report.get("root_cause", ""),
                "reasoning": report.get("reasoning", ""),
            })
        cons, n_valid = llm_eval.consistency(raw_guesses)
        print("  %s: raw guesses=%s  consistency=%s (n=%d)  ref=%s" %
              (dev_id, raw_guesses, cons, n_valid, ref_tier), flush=True)
    return rows


def write_long_csv(rows, suffix=""):
    path = RESULTS / ("llm_eval_trials%s.csv" % suffix)
    fields = ["device", "trial", "provider", "latency_ms", "raw_risk_level",
              "reference_tier", "accuracy_hit", "hallucination_rate", "n_claims",
              "claimed_flags", "explanation_correct", "compliance", "compliance_accuracy",
              "root_cause", "reasoning"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    return path


def write_summary_csv(rows, suffix=""):
    path = RESULTS / ("llm_eval_summary%s.csv" % suffix)
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
    import os
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=N_TRIALS_DEFAULT)
    ap.add_argument("--model", type=str, default="llama3.2:3b",
                    help="Ollama model tag. Non-default models write to "
                         "*_<model>.csv so the llama3.2:3b baseline is never overwritten.")
    args = ap.parse_args()
    os.environ["OLLAMA_MODEL"] = args.model
    suffix = "_%s" % args.model.replace(":", "_").replace(".", "_") if args.model != "llama3.2:3b" else ""
    print("Running %d trials x 5 devices against the real local Ollama model "
          "(%s)..." % (args.trials, args.model))
    rows = run_trials(args.trials)
    long_path = write_long_csv(rows, suffix=suffix)
    summary_path = write_summary_csv(rows, suffix=suffix)
    print("\nwrote %s (%d rows)" % (long_path, len(rows)))
    print("wrote %s" % summary_path)


if __name__ == "__main__":
    main()
