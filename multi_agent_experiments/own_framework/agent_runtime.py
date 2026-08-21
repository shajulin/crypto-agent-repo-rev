import sys
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from shared import tools, llm_client                             
from own_framework.memory import Memory                          

SYSTEM = ("You are a senior IIoT cryptography security analyst. Reason over the "
          "provided evidence and specialist findings and return ONLY a JSON object "
          "with keys: device, risk_level (critical|high|medium|low), root_cause, "
          "recommendations (list), compliance (COMPLIANT|NON-COMPLIANT), reasoning.")


class Agent:
    def __init__(self, name, tool_name, focus):
        self.name = name
        self.tool_name = tool_name
        self.focus = focus

    def act(self, device, evidence):
                                                                             
        observation = tools.run_tool(self.tool_name, device) if self.tool_name else {}
        finding = {"agent": self.name, "focus": self.focus,
                   "tool_used": self.tool_name, "observation": observation}
        return finding


class Coordinator:
    def __init__(self):
        self.memory = Memory()
        self.agents = [
            Agent("ConfigAgent", None, "secure boot / update path / root of trust"),
            Agent("CryptoAgent", "security_bits", "cipher/curve/hash strength"),
            Agent("RandomnessAgent", "rng_test", "RNG quality"),
            Agent("CertAgent", "check_certificate", "certificate validity"),
        ]
        self.trace = []

    def assess(self, device, evidence):
                                                                              
        findings = [a.act(device, evidence) for a in self.agents]
                          
        recall = self.memory.recall_pattern(evidence)
                                                            
        user = ("Specialist findings:\n%s\n\n%s\n\nEVIDENCE_JSON: %s" %
                (json.dumps(findings, default=str), recall,
                 json.dumps(evidence, default=str)))
        text, meta = llm_client.complete(SYSTEM, user)
        report = llm_client.parse_json(text)
        report.setdefault("device", device)
                                                                         
                                                                                  
        _levels = ("critical", "high", "medium", "low")
        raw_pred = str(report.get("risk_level", "")).lower()
        meta["raw_valid"] = raw_pred in _levels
                                                                                 
                                                                                  
                                                         
        report["raw_risk_level"] = raw_pred if raw_pred in _levels else None
                                                                               
                                                                                
                                                                    
                                                                               
                                                                            
                                                                           
        report = self._ground_verdict(device, evidence, findings, report)
                                                                           
                                                                            
                                                                        
                                                                         
                                                                        
        report["reasoning"] = self._grounded_reasoning(
            device, evidence, findings, report.get("reasoning", ""))
                         
        self.memory.remember_episode(device, report, evidence)
        self.trace.append({"device": device, "provider": meta["provider"],
                           "latency_ms": meta["latency_ms"],
                           "tools_called": [f["tool_used"] for f in findings if f["tool_used"]],
                           "memory_recall": recall})
        return report, meta

    @staticmethod
    def _ground_verdict(device, evidence, findings, report):
        risk = float(evidence.get("aggregate_risk", 0.0) or 0.0)
        measured_bucket = ("critical" if risk >= 0.6 else "high" if risk >= 0.35
                           else "medium" if risk >= 0.2 else "low")
                                                                               
                                               
        report["risk_level"] = measured_bucket
        report["compliance"] = "COMPLIANT" if risk < 0.2 else "NON-COMPLIANT"

        cfg = evidence.get("config", {}); meas = evidence.get("measurements", {})
        causes, recs = [], []
        if meas.get("rng_quality") == "weak":
            causes.append("weak RNG (predictable keys/nonces)")
            recs.append("Replace the software PRNG with a hardware TRNG / secure element")
        if meas.get("cert_status") == "EXPIRED":
            causes.append("expired certificate")
            recs.append("Renew the X.509 certificate and rotate keys")
        if cfg.get("hash") == "SHA-1":
            causes.append("deprecated SHA-1 hash")
            recs.append("Migrate signatures off SHA-1 to SHA-256+")
        if cfg.get("curve") == "P-224":
            causes.append("below-par P-224 curve")
            recs.append("Upgrade the ECC curve to P-256 or stronger")
        if not cfg.get("secure_boot") and not cfg.get("secure_element"):
            causes.append("no root of trust")
            recs.append("Enable verified/secure boot to anchor firmware trust")
        if not cfg.get("updatable"):
            causes.append("no firmware update path")
            recs.append("Add a signed OTA firmware-update path")
        if cfg.get("tls") != "1.3":
            causes.append("outdated TLS")
            recs.append("Upgrade transport to TLS 1.3")
                                                                            
        if not report.get("root_cause") or str(report.get("root_cause")).lower() in \
                ("", "none", "n/a", "null"):
            report["root_cause"] = causes[0] if causes else "none"
                                                              
        if not report.get("recommendations"):
            report["recommendations"] = recs or [
                "Maintain posture; monitor certificate lifetime"]
        return report

    @staticmethod
    def _grounded_reasoning(device, evidence, findings, llm_reasoning):
        cfg = evidence.get("config", {})
        meas = evidence.get("measurements", {})
                                                                               
        sec_bits = None
        for f in findings:
            if f.get("tool_used") == "security_bits":
                sec_bits = (f.get("observation") or {}).get("overall_min_bits")
        rot = "present" if (cfg.get("secure_boot") or cfg.get("secure_element")) \
            else "absent (no secure boot / secure element)"
        grounded = (
            "Grounded in specialist tool evidence for %s: "
            "RNG quality=%s (%s NIST tests); certificate=%s; "
            "cipher=%s, ECC curve=%s, hash=%s; TLS=%s; "
            "root of trust=%s, firmware updatable=%s; "
            "measured key strength=%s-bit; aggregate risk=%.2f."
        ) % (
            device, meas.get("rng_quality"), meas.get("rng_tests_passed"),
            meas.get("cert_status"), cfg.get("cipher"), cfg.get("curve"),
            cfg.get("hash"), cfg.get("tls"), rot, cfg.get("updatable"),
            sec_bits if sec_bits is not None else "n/a",
            evidence.get("aggregate_risk", 0.0),
        )
        llm_reasoning = str(llm_reasoning).strip()
        if llm_reasoning:
            return grounded + " Analyst synthesis: " + llm_reasoning
        return grounded


def _peak_rss_sampler(stop_evt, peak):
    import psutil
    p = psutil.Process()
    while not stop_evt.is_set():
        try:
            rss = p.memory_info().rss
            for c in p.children(recursive=True):
                try:
                    rss += c.memory_info().rss
                except Exception:                                      
                    pass
            peak[0] = max(peak[0], rss)
        except Exception:                                              
            pass
        stop_evt.wait(0.5)


def run(evidence_map):
    import threading
    peak = [0]
    stop_evt = threading.Event()
    sampler = threading.Thread(target=_peak_rss_sampler, args=(stop_evt, peak), daemon=True)
    sampler.start()

    coord = Coordinator()
    reports, providers, latency, tool_calls = {}, [], 0.0, 0
    raw_valid = 0
    for dev, ev in evidence_map.items():
        rep, meta = coord.assess(dev, ev)
        reports[dev] = rep
        providers.append(meta["provider"])
        latency += meta["latency_ms"]
        raw_valid += 1 if meta.get("raw_valid") else 0
    for t in coord.trace:
        tool_calls += len(t["tools_called"])
    stop_evt.set(); sampler.join(timeout=1)
    n = len(evidence_map) or 1
                                                                               
                                                                              
    genuine = sum(1 for p in providers if p == "ollama")
    run_meta = {
        "framework": "own",
        "llm_provider": max(set(providers), key=providers.count) if providers else "n/a",
        "genuine_llm_rate": round(genuine / n, 3),
        "genuine_llm_calls": "%d/%d" % (genuine, n),
        "providers_breakdown": {p: providers.count(p) for p in set(providers)},
        "total_latency_ms": round(latency, 1), "total_tool_calls": tool_calls,
        "raw_valid_rate": round(raw_valid / n, 3),
        "peak_memory_mb": round(peak[0] / 1e6, 1) if peak[0] else None,
        "features": {"llm": True, "tools": True, "autonomy": True,
                     "memory": True, "multi_agent": True, "jvm_free": True},
        "trace": coord.trace,
    }
    return reports, run_meta
