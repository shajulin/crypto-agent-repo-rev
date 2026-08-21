import os
                                                                        
os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")

import re
import sys
import json
import time
import contextlib
from pathlib import Path

_REAL_STDOUT = sys.stdout


def _log(msg):
    print(msg, file=_REAL_STDOUT, flush=True)


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

FW = Path("/app/data/frameworks")
IN = FW / "evidence_input.json"
OUT = FW / "crewai_result.json"
LEVELS = ("critical", "high", "medium", "low")


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
    causes, recs = [], []
    if meas.get("rng_quality") == "weak":
        causes.append("weak RNG"); recs.append("Replace PRNG with a hardware TRNG")
    if meas.get("cert_status") == "EXPIRED":
        causes.append("expired cert"); recs.append("Renew the X.509 certificate")
    if cfg.get("hash") == "SHA-1":
        causes.append("SHA-1"); recs.append("Migrate off SHA-1 to SHA-256+")
    if cfg.get("tls") != "1.3":
        causes.append("outdated TLS"); recs.append("Require TLS 1.3")
    return {"device": dev_id, "risk_level": level,
            "root_cause": causes[0] if causes else "none",
            "recommendations": recs or ["Maintain posture; monitor cert lifetime"],
            "compliance": "NON-COMPLIANT" if causes else "COMPLIANT",
            "reasoning": "Derived from evidence (rng/%s cert/%s hash/%s tls/%s)."
                         % (meas.get("rng_quality"), meas.get("cert_status"),
                            cfg.get("hash"), cfg.get("tls"))}


def main():
                                                                                  
                                                                         
    for _ in range(600):                                                
        if IN.exists():
            break
        _log("[crewai] waiting for evidence_input.json ...")
        time.sleep(3)
    if not IN.exists():
        _log("[crewai] evidence_input.json never arrived -> exiting")
        return
    evidence = json.loads(IN.read_text(encoding="utf-8"))["evidence"]

                                                                                
                                                                                  
                                                                                   
    akka_done = FW / "akka_mem.json"
    for _ in range(1200):                                                                         
        if akka_done.exists():
            _log("[crewai] Akka finished -> running CrewAI uncontended")
            break
        _log("[crewai] waiting for Akka to finish first ...")
        time.sleep(3)

                                                                              
                                                                        
    import threading
    try:
        import psutil
    except ImportError:
        psutil = None
    _peak = [0]
    _stop = threading.Event()

    def _sample():
        p = psutil.Process()
        while not _stop.is_set():
            try:
                rss = p.memory_info().rss
                for c in p.children(recursive=True):
                    try:
                        rss += c.memory_info().rss
                    except Exception:                                  
                        pass
                _peak[0] = max(_peak[0], rss)
            except Exception:                                          
                pass
            _stop.wait(0.5)
    if psutil is not None:
        threading.Thread(target=_sample, daemon=True).start()

    with _quiet():
        from crewai import Agent, Task, Crew, Process, LLM
                                                                         
                                                                               
                                                                                  
                                                                                   
                                                                             
                                                                                     
        llm = LLM(model="ollama/" + os.environ.get("OLLAMA_MODEL", "llama3.2:3b"),
                  base_url=os.environ.get("OLLAMA_BASE_URL", "http://ollama:11434"),
                  temperature=0, seed=42)

    from crewai import Agent, Task, Crew, Process                                             

                                                                              
                                                                        
    _TEMPLATE = (
        '{"device":"<id>","risk_level":"critical|high|medium|low",'
        '"root_cause":"<short phrase>","recommendations":["<fix>","<fix>"],'
        '"compliance":"COMPLIANT|NON-COMPLIANT",'
        '"reasoning":"<2 sentences citing the concrete weaknesses: rng, cert, '
        'hash, curve, tls, secure boot, firmware>"}')

    reports = {}
    valid_llm = 0
    total_latency_ms = 0.0
    for dev_id, ev in evidence.items():
        t_dev = time.time()
        try:
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
                          agent=analyst,
                          expected_output="a short bullet list naming each weakness")
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
            rep = _parse_json(out)
        except Exception as e:                                     
            _log("[crewai] %s crew error: %s" % (dev_id, type(e).__name__))
            rep = {}
        if not _valid(rep):
            rep = _derive(dev_id, ev); src = "derived"
            rep["raw_risk_level"] = None                                                  
        else:
            rep.setdefault("device", dev_id)
            rep.setdefault("reasoning", "")
                                                                                     
            rep["raw_risk_level"] = str(rep.get("risk_level", "")).lower()
            src = "llm"; valid_llm += 1
        total_latency_ms += (time.time() - t_dev) * 1000
        reports[dev_id] = rep
        _log("[crewai] %s -> %s (%s)" % (dev_id, rep["risk_level"], src))

    n = len(evidence) or 1
    _stop.set()
    peak_mb = round(_peak[0] / 1e6, 1) if _peak[0] else None
    FW.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"reports": reports,
                               "meta": {"framework": "crewai", "mode": "crewai-real",
                                        "raw_valid_rate": round(valid_llm / n, 3),
                                        "total_latency_ms": round(total_latency_ms, 1),
                                        "peak_memory_mb": peak_mb,
                                        "total_tool_calls": 0,
                                        "features": {"llm": True, "tools": False,
                                                     "autonomy": False, "memory": True,
                                                     "multi_agent": True, "jvm_free": True}}},
                              indent=2, default=str), encoding="utf-8")
    _log("[crewai] wrote %s (raw_valid_rate=%.2f)" % (OUT, valid_llm / n))


if __name__ == "__main__":
    main()
