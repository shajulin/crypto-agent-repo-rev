import csv
import statistics as st
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "multi_agent_experiments"))
sys.path.insert(0, str(ROOT))

from shared import evidence as evm, llm_eval, task              

RESULTS = ROOT / "results"


def _truths():
    ev_all, ref = evm.build_evidence()
    return {d: llm_eval.ground_truth_flags(ev) for d, ev in ev_all.items()}


def recompute(name, has_compliance):
    path = RESULTS / name
    if not path.exists():
        print("skip %s: not found" % name)
        return
    rows = list(csv.DictReader(open(path, newline="", encoding="utf-8")))
    if not rows:
        return
    truths = _truths()
    for r in rows:
        truth = truths[r["device"]]
        report = {"root_cause": r.get("root_cause", ""), "reasoning": r.get("reasoning", "")}
        if has_compliance:
            report["compliance"] = r.get("compliance", "")
        hrate, n_claims = llm_eval.hallucination_rate(report, truth)
        correct = llm_eval.explanation_correctness(report, truth)
        r["hallucination_rate"] = hrate
        r["n_claims"] = n_claims
        r["explanation_correct"] = correct
        if "claimed_flags" in r:
            claimed = llm_eval._mentioned_claims(
                "%s %s" % (report["root_cause"], report["reasoning"]))
            r["claimed_flags"] = ";".join(claimed)
        if has_compliance:
            comp_acc = llm_eval.compliance_accuracy(report, truth)
            r["compliance_accuracy"] = "" if comp_acc is None else comp_acc
    fields = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    print("recomputed %s (%d rows)" % (name, len(rows)))
    return rows


def rewrite_summary(name, rows, has_raw_valid_rate=False):
    if not rows:
        return
    path = RESULTS / name
    devices = sorted({r["device"] for r in rows})
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        header = ["device", "n_trials"]
        if has_raw_valid_rate:
            header.append("raw_valid_rate")
        header += ["llm_accuracy", "n_parseable", "hallucination_rate_mean",
                   "explanation_correctness_mean", "consistency", "n_valid_for_consistency"]
        w.writerow(header)
        all_hits, all_n = 0, 0
        for dev in devices:
            sub = [r for r in rows if r["device"] == dev]
            hits = [int(r["accuracy_hit"]) for r in sub if r["accuracy_hit"] != ""]
            acc = round(sum(hits) / len(hits), 3) if hits else None
            hall = round(st.mean(float(r["hallucination_rate"]) for r in sub), 3)
            correct = round(st.mean(float(r["explanation_correct"]) for r in sub), 3)
            guesses = [r["raw_risk_level"] if r["raw_risk_level"] != "unparseable" else None
                      for r in sub]
            cons, n_valid = llm_eval.consistency(guesses)
            row = [dev, len(sub)]
            if has_raw_valid_rate:
                valid_rate = round(sum(1 for r in sub if r.get("source") == "llm") / len(sub), 3)
                row.append(valid_rate)
            row += [acc, len(hits), hall, correct, cons, n_valid]
            w.writerow(row)
            all_hits += sum(hits); all_n += len(hits)
        w.writerow([])
        overall_acc = round(all_hits / all_n, 3) if all_n else None
        tail_row = ["OVERALL", len(rows)]
        if has_raw_valid_rate:
            tail_row.append("")
        tail_row += [overall_acc, all_n, "", "", "", ""]
        w.writerow(tail_row)
    print("rewrote %s" % name)


def main():
    ours = recompute("llm_eval_trials.csv", has_compliance=True)
    akka = recompute("akka_eval_trials.csv", has_compliance=False)
    crewai = recompute("crewai_eval_trials.csv", has_compliance=True)
    rewrite_summary("llm_eval_summary.csv", ours)
    rewrite_summary("akka_eval_summary.csv", akka)
    rewrite_summary("crewai_eval_summary.csv", crewai, has_raw_valid_rate=True)


if __name__ == "__main__":
    main()
