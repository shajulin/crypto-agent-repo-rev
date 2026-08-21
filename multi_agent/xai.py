import itertools
import math
import numpy as np

from config_inspector.devices import get_device

                                                                        
                                                                         
                                                                 
FEATURES = ["rng_weakness", "no_root_of_trust", "not_updatable", "cert_expired",
            "hash_deprecated", "curve_below_par", "tls_outdated"]

                                                          
_W = np.array([0.28, 0.15, 0.15, 0.17, 0.10, 0.08, 0.07])

                                                                                 
_INTERACTIONS = [
    (0, 1, 0.15),                                                           
    (2, 3, 0.12),                                                       
    (1, 2, 0.10),                                                          
]
RISK_THRESHOLD = 0.4
ACTIVE_THR = 0.5                                                      

FEATURE_TO_KG_NODE = {
    "rng_weakness": "Cipher Suite", "no_root_of_trust": "Firmware",
    "not_updatable": "Firmware", "cert_expired": "TLS Version",
    "hash_deprecated": "Cipher Suite", "curve_below_par": "Key Length",
    "tls_outdated": "TLS Version",
}

WEAKNESS_MSG = {
    "rng_weakness": "weak RNG -> predictable keys/nonces",
    "no_root_of_trust": "no secure boot/element -> no root of trust",
    "not_updatable": "no firmware update path -> unpatchable",
    "cert_expired": "expired certificate -> impersonation/MITM",
    "hash_deprecated": "deprecated SHA-1 -> signature forgery",
    "curve_below_par": "P-224 curve -> <128-bit security",
    "tls_outdated": "TLS <1.3 -> downgrade attacks",
}


def risk_model(x):
    x = np.asarray(x, dtype=float)
    r = float(np.dot(_W, x))
    for i, j, w in _INTERACTIONS:
        r += w * x[i] * x[j]
    return min(r, 1.0)


                                                                                 
def feature_vector(m1, m2col, m3, dev_id):
    dev = get_device(dev_id)
                                                                
    q = {"strong": 0.0, "good": 0.4, "weak": 0.9}[m1["random_number_generator"]["quality"]]
    has_rot = dev["secure_boot"] or dev["secure_element"]
    x = {
        "rng_weakness": q,
        "no_root_of_trust": 0.0 if has_rot else 1.0,
        "not_updatable": 0.0 if m1["os_fingerprinting"]["updatable"] else 1.0,
        "cert_expired": 1.0 if dev["cert_valid_days"] < 0 else 0.0,
        "hash_deprecated": 1.0 if dev["hash"] == "SHA-1" else 0.0,
        "curve_below_par": 1.0 if dev["curve"] == "P-224" else 0.0,
        "tls_outdated": 0.0 if dev["tls"] == "1.3" else 1.0,
    }
    return np.array([x[f] for f in FEATURES])


def root_cause(feature_values, best_attribution):
    active = [f for f in FEATURES if feature_values[f] >= ACTIVE_THR]
    if not active:
        return None
    f = max(active, key=lambda k: abs(best_attribution[k]))
    return {"feature": f, "node": FEATURE_TO_KG_NODE[f], "message": WEAKNESS_MSG[f]}


def active_nodes(feature_values):
    return sorted({FEATURE_TO_KG_NODE[f] for f in FEATURES
                   if feature_values[f] >= ACTIVE_THR})


                                                                                
def _shap(x):
    n = len(x)
    phi = np.zeros(n)
    idx = list(range(n))
    for i in idx:
        others = [j for j in idx if j != i]
        for r in range(len(others) + 1):
            wc = (math.factorial(r) * math.factorial(n - r - 1) / math.factorial(n))
            for S in itertools.combinations(others, r):
                S = list(S)
                xs = np.zeros(n); xs[S] = x[S]
                xsi = xs.copy(); xsi[i] = x[i]
                phi[i] += wc * (risk_model(xsi) - risk_model(xs))
    return phi


def _lime(x, n_samples=600, seed=0):
    rng = np.random.default_rng(seed)
    masks = rng.integers(0, 2, size=(n_samples, len(x)))
    Z = masks * x
    y = np.array([risk_model(z) for z in Z])
    dist = np.sum(1 - masks, axis=1)
    w = np.exp(-(dist ** 2) / 2.0)
    Xd = masks - masks.mean(0)
    yd = y - np.average(y, weights=w)
    W = np.diag(w)
    coef, *_ = np.linalg.lstsq(Xd.T @ W @ Xd + 1e-6 * np.eye(len(x)),
                               Xd.T @ W @ yd, rcond=None)
    return coef * x


def _grad_cfa(x, eps=1e-3):
    grad = np.zeros(len(x))
    for i in range(len(x)):
        xp = x.copy(); xp[i] += eps
        xm = x.copy(); xm[i] -= eps
        grad[i] = (risk_model(xp) - risk_model(xm)) / (2 * eps)
    return grad * x


def _fair_xai(x, population):
    base = _shap(x)
    pop_attr = np.array([_shap(p) for p in population]) if len(population) else base[None]
    consistency = 1.0 / (1.0 + pop_attr.var(axis=0))
    adj = base * consistency
    s = np.sum(np.abs(base)) or 1.0
    return adj / (np.sum(np.abs(adj)) or 1.0) * s


def _latent_cf_attribution(x):
    x = x.copy()
    attr = np.zeros(len(x))
    for i in np.argsort(-x):
        before = risk_model(x)
        x[i] = 0.0
        attr[i] = before - risk_model(x)
    return attr


def minimal_fix(x):
    xw = x.copy()
    fixes = []
    for i in np.argsort(-x):
        if risk_model(xw) < RISK_THRESHOLD:
            break
        if x[i] > 0:
            xw[i] = 0.0
            fixes.append(FEATURES[i])
    return {"fix_features": fixes, "residual_risk": round(risk_model(xw), 3)}


METHODS = {
    "SHAP": lambda x, pop, seed: _shap(x),
    "LIME": lambda x, pop, seed: _lime(x, seed=seed),
    "Grad-CFA": lambda x, pop, seed: _grad_cfa(x),
    "FairXAI": lambda x, pop, seed: _fair_xai(x, pop),
    "Latent-CF": lambda x, pop, seed: _latent_cf_attribution(x),
}


                                                                             
def _ground_truth_deletion(x):
    base = risk_model(x)
    return np.array([base - risk_model(np.where(np.arange(len(x)) == i, 0.0, x))
                     for i in range(len(x))])


def _pearson(a, b):
    if np.std(a) < 1e-12 or np.std(b) < 1e-12:
        return 0.0
    return float(np.corrcoef(a, b)[0, 1])


def _faithfulness(attr, truth):
    return round(max(0.0, _pearson(attr, truth)), 3)


def _sparsity(attr):
    a = np.abs(attr)
    if a.sum() == 0:
        return 0.0
    p = a / a.sum()
    ent = -np.sum(p[p > 0] * np.log(p[p > 0])) / np.log(len(a))
    return round(1 - ent, 3)


def _stability(fn, x, pop, seed, trials=8, noise=0.02):
    base = fn(x, pop, seed)
    rng = np.random.default_rng(seed + 10_000)                                      
    diffs = [np.mean(np.abs(fn(np.clip(x + rng.normal(0, noise, len(x)), 0, 1), pop, seed) - base))
             for _ in range(trials)]
    return round(float(1.0 / (1.0 + np.mean(diffs))), 3)


                                                                     
_SCORE_W = {"faithfulness": 0.7, "stability": 0.2, "sparsity": 0.1}


def compare(x, population, seed=0):
    truth = _ground_truth_deletion(x)
    methods, metrics = {}, {}
    for name, fn in METHODS.items():
        attr = fn(x, population, seed)
        faith = _faithfulness(attr, truth)
        spars = _sparsity(attr)
        stab = _stability(fn, x, population, seed)
        score = round(_SCORE_W["faithfulness"] * faith
                      + _SCORE_W["stability"] * stab
                      + _SCORE_W["sparsity"] * spars, 3)
        methods[name] = {f: round(float(v), 4) for f, v in zip(FEATURES, attr)}
        metrics[name] = {"faithfulness": faith, "stability": stab,
                         "sparsity": spars, "score": score}
    best = max(metrics, key=lambda m: metrics[m]["score"])
    best_attr = methods[best]
    fvals = {f: round(float(v), 3) for f, v in zip(FEATURES, x)}
                                                                                
                                                      
    rc = root_cause(fvals, best_attr)
    return {
        "feature_values": fvals,
        "ground_truth_deletion": {f: round(float(v), 4) for f, v in zip(FEATURES, truth)},
        "methods": methods, "metrics": metrics,
        "best_method": best, "best_attribution": best_attr,
        "dominant_feature": rc["feature"] if rc else None,
        "dominant_kg_node": rc["node"] if rc else None,
        "root_cause": rc,
        "active_nodes": active_nodes(fvals),
        "minimal_fix": minimal_fix(x),
        "explained_risk": round(risk_model(x), 3),
    }


def explain(dev_id, m1, m2col, m3, population=None, seed=0):
    x = feature_vector(m1, m2col, m3, dev_id)
    return compare(x, population if population is not None else [], seed=seed)
