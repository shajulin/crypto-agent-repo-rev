import os
import csv
import json
import random
import datetime
from pathlib import Path

from common.timing import timed
from common import rng_tests, cryptolib

MODULE = "Testbed"

                                                                            
DATA_DIR = Path(__file__).resolve().parents[1] / "data"

N_DEVICES = int(os.environ.get("CRYPTO_TESTBED_N", "1000"))
SECURITY_FLOOR_BITS = 112
RNG_CLASSES = {"strong": "os_urandom", "weak": "weak_lcg"}

OBSERVABLE = ["weak_rng", "no_root_of_trust", "not_updatable", "expired_cert",
              "deprecated_hash", "below_par_curve", "outdated_tls"]
UNOBSERVABLE = ["side_channel", "backdoored_keygen"]                             


                                                                                
def _compliant(rng, i):
    return {
        "id": "gen%04d" % i, "rng_class": "strong", "hash": "SHA-256",
        "curve": "P-256", "tls": "1.3", "cipher_bits": 256,
        "cert_valid_days": rng.choice([365, 180, 120, 90]),
        "secure_boot": True, "secure_element": True, "updatable": True,
        "side_channel": False, "backdoored_keygen": False,
    }


def _inject(cfg, weakness, rng):
    if weakness == "weak_rng":
        cfg["rng_class"] = "weak"
    elif weakness == "no_root_of_trust":
        cfg["secure_boot"] = False; cfg["secure_element"] = False
    elif weakness == "not_updatable":
        cfg["updatable"] = False
    elif weakness == "expired_cert":
        cfg["cert_valid_days"] = rng.choice([-15, -90])
    elif weakness == "deprecated_hash":
        cfg["hash"] = "SHA-1"
    elif weakness == "below_par_curve":
        cfg["curve"] = "P-224"
    elif weakness == "outdated_tls":
        cfg["tls"] = rng.choice(["1.0", "1.1"])
    elif weakness == "side_channel":
        cfg["side_channel"] = True
    elif weakness == "backdoored_keygen":
        cfg["backdoored_keygen"] = True


def _random_device(rng, i):
    cfg = _compliant(rng, i)
    if rng.random() < 0.5:                                   
        for w in rng.sample(OBSERVABLE + UNOBSERVABLE, rng.randint(1, 3)):
            _inject(cfg, w, rng)
    else:                                                         
        if rng.random() < 0.25:                                                  
            cfg["cert_valid_days"] = rng.randint(1, 29)
    return cfg


def _ground_truth(cfg):
    v = []
    if cfg["rng_class"] == "weak": v.append("weak_rng")
    if cfg["hash"] == "SHA-1": v.append("deprecated_hash")
    if cfg["curve"] == "P-224": v.append("below_par_curve")
    if cfg["tls"] in ("1.0", "1.1"): v.append("outdated_tls")
    if cfg["cipher_bits"] < 128: v.append("weak_cipher")
    if cfg["cert_valid_days"] < 0: v.append("expired_cert")
    if not cfg["updatable"]: v.append("not_updatable")
    if not cfg["secure_boot"] and not cfg["secure_element"]: v.append("no_root_of_trust")
    if cfg["side_channel"]: v.append("side_channel")
    if cfg["backdoored_keygen"]: v.append("backdoored_keygen")
    return (len(v) > 0), v


                                                                             
def _observe(cfg):
    gen = RNG_CLASSES[cfg["rng_class"]]
    rng_weak = rng_tests.assess_generator(gen, nbytes=16384)["quality"] == "weak"
    cert = cryptolib.build_and_validate_cert("t-" + cfg["id"], cfg["cert_valid_days"])
    sb = cryptolib.measure_security_bits(cfg["cipher_bits"], cfg["curve"], cfg["hash"])
    days = cfg["cert_valid_days"]
    near_expiry_risk = round(0.25 * (30 - days) / 30, 3) if 0 <= days < 30 else 0.0
    obs = {
        "weak_rng": rng_weak,
        "no_root_of_trust": not cfg["secure_boot"] and not cfg["secure_element"],
        "not_updatable": not cfg["updatable"],
        "expired_cert": cert["expired"],
        "deprecated_hash": sb["hash_bits"] < SECURITY_FLOOR_BITS,
        "below_par_curve": sb["ecc_bits"] < 128,
        "weak_cipher": sb["symmetric_bits"] < 128,
        "outdated_tls": cfg["tls"] in ("1.0", "1.1"),
    }
    return obs, near_expiry_risk, sb


                                                                                  
                                                                                          
                                                                                  
                                                                                     
                                                                   
_WEIGHTS = {"weak_rng": 0.30, "no_root_of_trust": 0.15, "not_updatable": 0.12,
            "expired_cert": 0.25, "deprecated_hash": 0.12, "below_par_curve": 0.10,
            "weak_cipher": 0.20, "outdated_tls": 0.10}
NAIVE_THRESHOLD = 0.25                                          


def _risk_score(obs, near_expiry_risk):
    s = sum(_WEIGHTS[k] for k, on in obs.items() if on)
    return min(s + near_expiry_risk, 1.0)                                          


                                                           
def _confusion(y_true, y_pred):
    tp = sum(1 for t, p in zip(y_true, y_pred) if t and p)
    tn = sum(1 for t, p in zip(y_true, y_pred) if not t and not p)
    fp = sum(1 for t, p in zip(y_true, y_pred) if not t and p)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t and not p)
    n = len(y_true) or 1
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {"TP": tp, "TN": tn, "FP": fp, "FN": fn,
            "accuracy": round((tp + tn) / n, 4), "precision": round(prec, 4),
            "recall": round(rec, 4), "f1": round(f1, 4)}


def _roc_auc(scores, labels):
    pos = [s for s, l in zip(scores, labels) if l]
    neg = [s for s, l in zip(scores, labels) if not l]
    if not pos or not neg:
        return 0.0
    wins = sum((s > t) + 0.5 * (s == t) for s in pos for t in neg)
    return round(wins / (len(pos) * len(neg)), 4)


def _pr_auc(scores, labels):
    order = sorted(range(len(scores)), key=lambda i: -scores[i])
    tp = fp = 0
    total_pos = sum(labels) or 1
    prev_rec = 0.0; ap = 0.0
    for i in order:
        if labels[i]:
            tp += 1
        else:
            fp += 1
        rec = tp / total_pos
        prec = tp / (tp + fp)
        ap += prec * (rec - prev_rec)
        prev_rec = rec
    return round(ap, 4)


def _tune_threshold(scores, labels):
    best_t, best_f1 = 0.5, -1.0
    for t in sorted(set(scores)):
        pred = [s >= t for s in scores]
        f1 = _confusion(labels, pred)["f1"]
        if f1 > best_f1:
            best_f1, best_t = f1, t
    return best_t


def _persist_population(devices, labels, violations, obs_list, scores, sbs, seed):
    DATA_DIR.mkdir(exist_ok=True)
    records = []
    for i, d in enumerate(devices):
        obs, near = obs_list[i]
        records.append({
            "id": d["id"], "seed": seed,
            "ground_truth": "weak" if labels[i] else "strong",
            "violations": violations[i],
            "observable_present": any(obs.values()),
            "near_expiry_risk": near,
            "risk_score": round(scores[i], 3),
            "security_bits": sbs[i]["overall_min_bits"],
            "rng_class": d["rng_class"], "hash": d["hash"], "curve": d["curve"],
            "tls": d["tls"], "cert_valid_days": d["cert_valid_days"],
            "secure_boot": d["secure_boot"], "secure_element": d["secure_element"],
            "side_channel": d["side_channel"], "backdoored_keygen": d["backdoored_keygen"],
        })
    (DATA_DIR / "testbed_population.json").write_text(
        json.dumps(records, indent=2), encoding="utf-8")
    with open(DATA_DIR / "testbed_population.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(records[0].keys()))
        w.writeheader()
        for r in records:
            r = dict(r); r["violations"] = ";".join(r["violations"])
            w.writerow(r)
    (DATA_DIR / "manifest.json").write_text(json.dumps({
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "n_devices": len(devices), "seed": seed,
        "weak": sum(labels), "strong": len(labels) - sum(labels),
        "note": "Simulated testbed population, regenerated (overwritten) each run.",
    }, indent=2), encoding="utf-8")


                                                       
def run(n=N_DEVICES, seed=7, persist=False):
    rng = random.Random(seed)
    with timed(MODULE):
        with timed(MODULE, "generate_population"):
            devices = [_random_device(rng, i) for i in range(n)]
            gts = [_ground_truth(d) for d in devices]
            labels = [g[0] for g in gts]
            violations = [g[1] for g in gts]

        with timed(MODULE, "framework_observe"):
            obs_list, scores, sbs = [], [], []
            for d in devices:
                obs, near, sb = _observe(d)
                obs_list.append((obs, near)); sbs.append(sb)
                scores.append(_risk_score(obs, near))

        if persist:
            _persist_population(devices, labels, violations, obs_list, scores, sbs, seed)

        with timed(MODULE, "evaluate"):
            idx = list(range(n)); rng.shuffle(idx)
            cut = n // 2
            tr, te = idx[:cut], idx[cut:]
            tuned = _tune_threshold([scores[i] for i in tr], [labels[i] for i in tr])

            te_lab = [labels[i] for i in te]
            te_scores = [scores[i] for i in te]
                                                                                  
                                                                               
            naive_pred = [s >= NAIVE_THRESHOLD for s in te_scores]
            tuned_pred = [s >= tuned for s in te_scores]

            base = _confusion(te_lab, naive_pred)
            improved = _confusion(te_lab, tuned_pred)
            roc = _roc_auc(te_scores, te_lab)
            pr = _pr_auc(te_scores, te_lab)

                                                                       
            fn_unobs_only = 0
            per_obs = {w: {"n": 0, "detected": 0} for w in OBSERVABLE}
            fp_near_expiry_naive, fp_near_expiry_tuned = 0, 0
            for k, i in enumerate(te):
                observable_present = any(obs_list[i][0].values())
                if labels[i] and not tuned_pred[k] and not observable_present:
                    fn_unobs_only += 1                                                     
                if labels[i]:
                    for w in violations[i]:
                        if w in per_obs:
                            per_obs[w]["n"] += 1
                            if tuned_pred[k]:
                                per_obs[w]["detected"] += 1
                if not labels[i] and obs_list[i][1]:                                      
                    if naive_pred[k]:
                        fp_near_expiry_naive += 1
                    if tuned_pred[k]:
                        fp_near_expiry_tuned += 1
            for w, d in per_obs.items():
                d["recall"] = round(d["detected"] / d["n"], 3) if d["n"] else None

    bits = [s["overall_min_bits"] for s in sbs]
    weak_ct = sum(labels)
    return {
        "n_devices": n, "weak_devices": weak_ct, "strong_devices": n - weak_ct,
        "n_train": len(tr), "n_test": len(te),
        "naive_threshold": NAIVE_THRESHOLD, "tuned_threshold": round(tuned, 3),
        "roc_auc": roc, "pr_auc": pr,
        "baseline": base, "calibrated": improved,
        "accuracy_gain": round(improved["accuracy"] - base["accuracy"], 4),
        "f1_gain": round(improved["f1"] - base["f1"], 4),
        "baseline_fp_from_near_expiry": fp_near_expiry_naive,
        "improved_fp_from_near_expiry": fp_near_expiry_tuned,
        "improved_fn_unobservable_only": fn_unobs_only,
        "per_observable_recall": per_obs,
        "coverage_ceiling_note": (
            "recall is capped below 1.0 by UNOBSERVABLE weaknesses "
            "(side-channel / backdoored key-gen) that config+RNG tests cannot see"),
        "measured_axes": ["RNG statistical tests", "security-bits (real keygen+hash)",
                          "X.509 expiry"],
        "security_bits_summary": {
            "min": min(bits), "max": max(bits),
            "mean": round(sum(bits) / len(bits), 1),
            "devices_below_128bit": sum(1 for b in bits if b < 128)},
    }


def _mean_std(xs):
    m = sum(xs) / len(xs)
    var = sum((x - m) ** 2 for x in xs) / len(xs)
    return round(m, 4), round(var ** 0.5, 4)


def run_repeated(n=N_DEVICES, seeds=(7, 13, 21)):
                                                                    
    runs = [run(n, seed=s, persist=(k == 0)) for k, s in enumerate(seeds)]
    keys = {"roc_auc": [r["roc_auc"] for r in runs],
            "pr_auc": [r["pr_auc"] for r in runs],
            "naive_accuracy": [r["baseline"]["accuracy"] for r in runs],
            "naive_precision": [r["baseline"]["precision"] for r in runs],
            "naive_recall": [r["baseline"]["recall"] for r in runs],
            "naive_f1": [r["baseline"]["f1"] for r in runs],
            "tuned_accuracy": [r["calibrated"]["accuracy"] for r in runs],
            "tuned_precision": [r["calibrated"]["precision"] for r in runs],
            "tuned_recall": [r["calibrated"]["recall"] for r in runs],
            "tuned_f1": [r["calibrated"]["f1"] for r in runs]}
    summary = {k: {"mean": _mean_std(v)[0], "std": _mean_std(v)[1]} for k, v in keys.items()}
    detail = runs[0]
    detail["seeds"] = list(seeds)
    detail["summary_over_seeds"] = summary
    return detail
