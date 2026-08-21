import os
import re
import time
import json
from pathlib import Path
from urllib import request, error


def _load_dotenv():
    here = Path(__file__).resolve()
    for candidate in (here.parents[1] / ".env", here.parents[2] / ".env"):
        if not candidate.exists():
            continue
        for line in candidate.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if k and v and not os.environ.get(k):
                os.environ[k] = v


_load_dotenv()


def _post_json(url, payload, timeout=600):
    body = json.dumps(payload).encode("utf-8")
    req = request.Request(url, data=body,
                          headers={"Content-Type": "application/json"}, method="POST")
    with request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _try_ollama(system, user):
    model = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")
    base = os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    try:
        data = _post_json(base.rstrip("/") + "/api/chat", {
            "model": model, "stream": False,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
                                                                            
            "options": {"temperature": 0, "seed": 42, "top_p": 1},
        })
        txt = data.get("message", {}).get("content", "")
        return (txt, "ollama") if txt else (None, "ollama-error:EmptyResponse")
    except error.URLError as e:
        return None, "ollama-error:%s" % type(e).__name__
    except Exception as e:                                          
        return None, "ollama-error:%s" % type(e).__name__


def _fallback(system, user):
    ev = {}
    m = re.search(r"EVIDENCE_JSON:\s*(\{.*\})\s*$", user, re.S)
    if m:
        try:
            ev = json.loads(m.group(1))
        except Exception:                                          
            ev = {}
    risk = ev.get("aggregate_risk", 0.0)
    level = ("critical" if risk >= 0.6 else "high" if risk >= 0.35
             else "medium" if risk >= 0.2 else "low")
    cfg = ev.get("config", {}); meas = ev.get("measurements", {})
    causes = []
    if meas.get("rng_quality") == "weak":
        causes.append("weak RNG (predictable keys/nonces)")
    if meas.get("cert_status") == "EXPIRED":
        causes.append("expired certificate")
    if cfg.get("hash") == "SHA-1":
        causes.append("deprecated SHA-1")
    if cfg.get("curve") == "P-224":
        causes.append("below-par P-224 curve")
    if not cfg.get("secure_boot") and not cfg.get("secure_element"):
        causes.append("no root of trust")
    if cfg.get("tls") != "1.3":
        causes.append("outdated TLS")
    recs = []
    if meas.get("rng_quality") == "weak":
        recs.append("Replace PRNG with a hardware TRNG / secure element")
    if meas.get("cert_status") == "EXPIRED":
        recs.append("Renew the X.509 certificate and rotate keys")
    if cfg.get("hash") == "SHA-1":
        recs.append("Migrate off SHA-1 to SHA-256+")
    recs = recs or ["Maintain current posture; monitor cert lifetime"]
    report = {"device": ev.get("device", "?"), "risk_level": level,
              "root_cause": causes[0] if causes else "none",
              "recommendations": recs,
              "compliance": "NON-COMPLIANT" if causes else "COMPLIANT",
              "reasoning": "Derived from measured evidence: risk=%.2f, causes=%s."
                           % (risk, causes or ["none"])}
    return json.dumps(report), "fallback"


def complete(system, user, want_json=True):
    start = time.perf_counter()
    text, provider = _try_ollama(system, user)
    if text is None:
        text, provider = _fallback(system, user)
    return text, {"provider": provider,
                  "latency_ms": round((time.perf_counter() - start) * 1000, 1)}


def parse_json(text):
    m = re.search(r"\{.*\}", str(text), re.S)
    if not m:
        return {}
    try:
        return json.loads(m.group(0))
    except Exception:                                              
        return {}
