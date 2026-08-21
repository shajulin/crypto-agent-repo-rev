import argparse
import contextlib
import csv
import json
import os
import re
import statistics as st
import sys
import time
from pathlib import Path

os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "multi_agent_experiments"))

from shared import evidence as evm, llm_eval, task              

RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)

N_TRIALS_DEFAULT = 10
LEVELS = ("critical", "high", "medium", "low")

_TEMPLATE = (
    '{"device":"<id>","risk_level":"critical|high|medium|low",'
    '"root_cause":"<short phrase>","recommendations":["<fix>","<fix>"],'
    '"compliance":"COMPLIANT|NON-COMPLIANT",'
    '"reasoning":"<2 sentences citing the concrete weaknesses: rng, cert, '
    'hash, curve, tls, secure boot, firmware>"}')


@contextlib.contextmanager
def _quiet():
    devnull = os.open(os.devnull, os.O_WRONLY)
    old_out, old_err = os.dup(1), os.dup(2)
    os.dup2(devnull, 1); os.dup2(devnull, 2)
    try:
        yield
    finally:
        os.dup2(old_out, 1); os.dup2(old_err, 2)
        for fd in (devnull, old_out, old_err):
            os.close(fd)


def _parse_json(text):
    m = re.search(r"\{.*\}", str(text), re.S)
    if not m:
        return {}
    try:
        return json.loads(m.group(0))
    except Exception:                                                  
        return {}


def _valid(rep):
    return isinstance(rep, dict) and str(rep.get("risk_level", "")).lower() in LEVELS


def _derive(dev_id, ev):
    risk = ev.get("aggregate_risk", 0.0)
    level = ("critical" if risk >= 0.6 else "high" if risk >= 0.35
             else "medium" if risk >= 0.2 else "low")
    cfg = ev.get("config", {}); meas = ev.get("measurements", {})
    causes = []
    if meas.get("rng_quality") == "weak":
        causes.append("weak RNG")
    if meas.get("cert_status") == "EXPIRED":
        causes.append("expired cert")
    if cfg.get("hash") == "SHA-1":
        causes.append("SHA-1")
    if cfg.get("tls") != "1.3":
        causes.append("outdated TLS")
    return {"device": dev_id, "risk_level": level,
            "root_cause": causes[0] if causes else "none",
            "recommendations": ["Maintain posture; monitor cert lifetime"],
            "compliance": "NON-COMPLIANT" if causes else "COMPLIANT",
            "reasoning": "Derived from evidence (rng/%s cert/%s hash/%s tls/%s)."
                         % (meas.get("rng_quality"), meas.get("cert_status"),
                            cfg.get("hash"), cfg.get("tls"))}


def _run_crew(llm, dev_id, ev):
    from crewai import Agent, Task, Crew, Process
    with _quiet():
        analyst = Agent(role="Crypto Analyst",
                        goal="Identify the concrete cryptographic weaknesses.",
                        backstory="IIoT security specialist.", llm=llm, verbose=False)
        lead = Agent(role="Risk Lead",
                     goal="Emit the final risk verdict as a single JSON object.",
                     backstory="Lead security auditor.", llm=llm, verbose=False)
        t1 = Task(description=("List the cryptographic weaknesses for this device, "
                               "naming each concrete factor (RNG quality, certificate "
                               "status, hash, ECC curve, TLS version, secure boot, "
                               "firmware update path):\n%s" % json.dumps(ev, default=str)),
                  agent=analyst, expected_output="a short bullet list naming each weakness")
        t2 = Task(description=(
                      "Using the analyst's findings, output ONE JSON object and "
                      "NOTHING else (no markdown, no prose before or after). "
                      "Use EXACTLY this schema:\n%s\n"
                      "The reasoning MUST name the concrete factors "
                      "(rng/cert/hash/curve/tls/secure boot/firmware)."
                      % _TEMPLATE),
                  agent=lead, expected_output="one JSON object matching the schema",
                  context=[t1])
        crew = Crew(agents=[analyst, lead], tasks=[t1, t2],
                    process=Process.sequential, verbose=False)
        out = str(crew.kickoff())
    return _parse_json(out)


def run_trials(n_trials, devices=None, model="llama3.2:3b"):
    from crewai import LLM
    llm = LLM(model="ollama/" + model, base_url="http://127.0.0.1:11434",
              temperature=0, seed=42)

    ev_all, ref = evm.build_evidence()
    if devices:
        ev_all = {d: ev for d, ev in ev_all.items() if d in devices}
    rows = []
    for dev_id, ev in ev_all.items():
        truth = llm_eval.ground_truth_flags(ev)
        ref_tier = task.risk_bucket(ref["risk"][dev_id])
        raw_guesses = []
        for trial in range(1, n_trials + 1):
            t0 = time.time()
            try:
                rep = _run_crew(llm, dev_id, ev)
            except Exception as e:                                     
                print("  %s trial %d: crew error %s" % (dev_id, trial, type(e).__name__),
                      flush=True)
                rep = {}
            latency_ms = round((time.time() - t0) * 1000, 1)
            if _valid(rep):
                raw_tier = str(rep.get("risk_level", "")).lower()
                src = "llm"
            else:
                rep = _derive(dev_id, ev)
                raw_tier = None
                src = "derived"
            raw_guesses.append(raw_tier)
            hrate, n_claims = llm_eval.hallucination_rate(rep, truth)
            correct = llm_eval.explanation_correctness(rep, truth)
            comp_acc = llm_eval.compliance_accuracy(rep, truth)
            rows.append({
                "device": dev_id, "trial": trial, "source": src, "latency_ms": latency_ms,
                "raw_risk_level": raw_tier or "unparseable", "reference_tier": ref_tier,
                "accuracy_hit": (1 if raw_tier == ref_tier else 0) if raw_tier else "",
                "hallucination_rate": hrate, "n_claims": n_claims,
                "explanation_correct": correct,
                "compliance": rep.get("compliance", ""),
                "compliance_accuracy": "" if comp_acc is None else comp_acc,
                "root_cause": rep.get("root_cause", ""), "reasoning": rep.get("reasoning", ""),
            })
            print("  %s trial %d/%d -> %s (%s, %.1fs)" %
                 (dev_id, trial, n_trials, raw_tier or "unparseable", src, latency_ms / 1000),
                 flush=True)
        cons, n_valid = llm_eval.consistency(raw_guesses)
        print("  %s: consistency=%s (n=%d)  ref=%s" % (dev_id, cons, n_valid, ref_tier),
              flush=True)
    return rows


def write_long_csv(rows, suffix=""):
    path = RESULTS / ("crewai_eval_trials%s.csv" % suffix)
    fields = ["device", "trial", "source", "latency_ms", "raw_risk_level", "reference_tier",
              "accuracy_hit", "hallucination_rate", "n_claims", "explanation_correct",
              "compliance", "compliance_accuracy", "root_cause", "reasoning"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    return path


def write_summary_csv(rows, suffix=""):
    path = RESULTS / ("crewai_eval_summary%s.csv" % suffix)
    devices = sorted({r["device"] for r in rows})
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["device", "n_trials", "raw_valid_rate", "llm_accuracy", "n_parseable",
                   "hallucination_rate_mean", "explanation_correctness_mean",
                   "consistency", "n_valid_for_consistency"])
        all_hits, all_n = 0, 0
        for dev in devices:
            sub = [r for r in rows if r["device"] == dev]
            valid_rate = round(sum(1 for r in sub if r["source"] == "llm") / len(sub), 3)
            hits = [r["accuracy_hit"] for r in sub if r["accuracy_hit"] != ""]
            acc = round(sum(hits) / len(hits), 3) if hits else None
            hall = round(st.mean(r["hallucination_rate"] for r in sub), 3)
            correct = round(st.mean(r["explanation_correct"] for r in sub), 3)
            guesses = [r["raw_risk_level"] if r["raw_risk_level"] != "unparseable" else None
                      for r in sub]
            cons, n_valid = llm_eval.consistency(guesses)
            w.writerow([dev, len(sub), valid_rate, acc, len(hits), hall, correct, cons, n_valid])
            all_hits += sum(hits); all_n += len(hits)
        w.writerow([])
        overall_acc = round(all_hits / all_n, 3) if all_n else None
        w.writerow(["OVERALL", len(rows), "", overall_acc, all_n, "", "", "", ""])
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=N_TRIALS_DEFAULT)
    ap.add_argument("--devices", type=str, default="",
                    help="comma-separated device subset, e.g. dev1 (isolation testing). "
                         "Writes to a _isolated-suffixed file, never overwrites the full run.")
    ap.add_argument("--model", type=str, default="llama3.2:3b",
                    help="Ollama model tag. Non-default models write to "
                         "*_<model>.csv so the llama3.2:3b baseline is never overwritten.")
    args = ap.parse_args()
    devices = [d.strip() for d in args.devices.split(",") if d.strip()] or None
    model_suffix = "_%s" % args.model.replace(":", "_").replace(".", "_") if args.model != "llama3.2:3b" else ""
    dev_suffix = "_isolated_%s" % "_".join(devices) if devices else ""
    suffix = dev_suffix + model_suffix
    print("Running %d trials x %s devices against the REAL crewai package + local Ollama "
          "(%s)..." % (args.trials, ",".join(devices) if devices else "5", args.model))
    rows = run_trials(args.trials, devices=devices, model=args.model)
    long_path = write_long_csv(rows, suffix=suffix)
    summary_path = write_summary_csv(rows, suffix=suffix)
    print("\nwrote %s (%d rows)" % (long_path, len(rows)))
    print("wrote %s" % summary_path)


if __name__ == "__main__":
    main()
