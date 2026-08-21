import argparse
import csv
import statistics as st
from pathlib import Path

from config_inspector import inspector as m1_mod
from crypto_inspector import inspector as m2_mod
from threat_risk import assessment as m3_mod
from multi_agent import xai

RESULTS = Path(__file__).resolve().parent / "results"
RESULTS.mkdir(exist_ok=True)

N_TRIALS_DEFAULT = 10


def run_trials(n_trials):
    rows = []
    for trial in range(1, n_trials + 1):
        r1 = m1_mod.inspect_all()
        r2 = m2_mod.inspect(r1)
        r3 = m3_mod.assess(r1, r2)
        population = [xai.feature_vector(
            m1, {m: r2["table"][m][d] for m in r2["methods"]}, r3, d)
            for d, m1 in r1.items()]
        for dev_id, m1 in r1.items():
            m2col = {m: r2["table"][m][dev_id] for m in r2["methods"]}
            result = xai.explain(dev_id, m1, m2col, r3,
                                  population=population, seed=trial)
            for method, metrics in result["metrics"].items():
                rows.append({
                    "device": dev_id, "method": method, "trial": trial,
                    "faithfulness": metrics["faithfulness"],
                    "stability": metrics["stability"],
                    "sparsity": metrics["sparsity"],
                    "composite_score": metrics["score"],
                })
        print("  trial %d/%d done" % (trial, n_trials), flush=True)
    return rows


def write_long_csv(rows):
    path = RESULTS / "xai_trials.csv"
    ordered = sorted(rows, key=lambda r: (r["device"], r["trial"], r["method"]))
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["device", "method", "trial", "faithfulness",
                                          "stability", "sparsity", "composite_score"])
        w.writeheader()
        w.writerows(ordered)
    return path


def write_per_device_method_csvs(rows):
    devices = sorted({r["device"] for r in rows})
    methods = sorted({r["method"] for r in rows})
    paths = []
    for dev in devices:
        for method in methods:
            sub = sorted((r for r in rows if r["device"] == dev and r["method"] == method),
                        key=lambda r: r["trial"])
            path = RESULTS / ("xai_trials_%s_%s.csv" % (dev, method.replace(" ", "_").replace("-", "_")))
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["trial", "faithfulness", "stability", "sparsity", "composite_score"])
                for r in sub:
                    w.writerow([r["trial"], r["faithfulness"], r["stability"],
                               r["sparsity"], r["composite_score"]])
            paths.append(path)
    return paths


def _ci95(vals):
    if len(vals) < 2:
        return 0.0
    return round(1.96 * st.pstdev(vals) / (len(vals) ** 0.5), 4)


def write_summary_csv(rows):
    path = RESULTS / "xai_trials_summary.csv"
    devices = sorted({r["device"] for r in rows})
    methods = sorted({r["method"] for r in rows})
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        header = ["device", "method", "n_trials"]
        for col in ("faithfulness", "stability", "sparsity", "composite_score"):
            header += ["%s_mean" % col, "%s_std" % col, "%s_ci95" % col]
        w.writerow(header)
        for dev in devices:
            for method in methods:
                sub = [r for r in rows if r["device"] == dev and r["method"] == method]
                row = [dev, method, len(sub)]
                for key in ("faithfulness", "stability", "sparsity", "composite_score"):
                    vals = [r[key] for r in sub]
                    row += [round(st.mean(vals), 4), round(st.pstdev(vals), 4), _ci95(vals)]
                w.writerow(row)
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=N_TRIALS_DEFAULT)
    args = ap.parse_args()

    print("Running %d repeated trials x 5 devices x 5 XAI methods "
          "(fresh RNG re-measurement each trial)..." % args.trials)
    rows = run_trials(args.trials)

    long_path = write_long_csv(rows)
    per_paths = write_per_device_method_csvs(rows)
    summary_path = write_summary_csv(rows)

    print("\nwrote %s (%d rows)" % (long_path, len(rows)))
    print("wrote %d per-device/method CSVs: results/xai_trials_<device>_<method>.csv" % len(per_paths))
    print("wrote %s (mean / std / 95%% CI per device x method)" % summary_path)


if __name__ == "__main__":
    main()
