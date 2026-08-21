import os
import sys
import json
import time
from pathlib import Path

import psutil
import requests

sys.path.insert(0, "/app")
sys.path.insert(0, "/app/multi_agent_experiments")

from crypto_inspector import inspector as m2                  
from threat_risk import assessment as m3                      
from knowledge_graph import kg as m4                          
from multi_agent import agents as m5                          
from config_inspector.devices import get_device               

ROLE = os.environ.get("AGENT_ROLE", "config")
FRAMEWORK = os.environ.get("FRAMEWORK", "own")
AGG = os.environ.get("AGGREGATOR_URL", "http://aggregator:8000")
OUT = Path("/app/data/agents") / FRAMEWORK
OUT.mkdir(parents=True, exist_ok=True)


def log(msg):
    print("[%s/%s] %s" % (FRAMEWORK, ROLE, msg), flush=True)


def fetch_r1():
    for _ in range(60):
        try:
            h = requests.get(AGG + "/health", timeout=5).json()
            if h.get("ready"):
                break
        except Exception:                                          
            pass
        log("waiting for aggregator to be ready ...")
        time.sleep(3)
    data = requests.get(AGG + "/devices", timeout=10).json()
    r1 = {}
    for dev_id, blob in data.items():
        p = blob["profile"]
        r1[dev_id] = {
            "random_number_generator": p["random_number_generator"],
            "os_fingerprinting": p["os_fingerprinting"],
            "cpu_capability_detection": p["cpu_capability"],
            "memory_analysis": p["memory_analysis"],
        }
    return r1


def wait_for(*names, timeout=900):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if all((OUT / n).exists() for n in names):
            return {n.split(".")[0]: json.loads((OUT / n).read_text(encoding="utf-8"))
                    for n in names}
        time.sleep(2)
    raise TimeoutError("missing prerequisites: %s" % (names,))


def write(name, payload, compute_ms):
    payload["_meta"] = {"agent": ROLE, "framework": FRAMEWORK,
                        "compute_ms": round(compute_ms, 2),
                        "memory_rss_mb": round(psutil.Process().memory_info().rss / 1e6, 1),
                        "timestamp": time.time()}
    (OUT / name).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    log("wrote %s (compute=%.1fms)" % (name, compute_ms))


                                                                              
def run_config(r1):
    t0 = time.perf_counter()
    findings = {}
    for dev_id, m1 in r1.items():
        dev = get_device(dev_id)
        cpu = m1["cpu_capability_detection"]; rng = m1["random_number_generator"]
        osf = m1["os_fingerprinting"]; mem = m1["memory_analysis"]
        issues = []
        if not dev["secure_boot"]:
            issues.append("no secure boot")
        if not osf["updatable"]:
            issues.append("no firmware update path")
        if not dev["secure_boot"] and not dev["secure_element"]:
            issues.append("no root of trust")
        findings[dev_id] = {
            "collected": {
                "hardware": cpu["declared_cpu"],
                "cpu": {"class": cpu["class"], "aes_MBps": cpu["measured_aes_MBps"]},
                "memory": {"ram_kb": mem["ram_kb"], "verdict": mem["verdict"]},
                "os": {"os": osf["declared_os"], "tls": osf["tls"]},
                "rng": {"generator": rng["generator"], "quality": rng["quality"]},
            },
            "issues": issues or ["nominal"],
        }
    write("config.json", {"findings": findings}, (time.perf_counter() - t0) * 1000)


def run_crypto(r1):
    t0 = time.perf_counter()
    r2 = m2.inspect(r1)
    write("crypto.json", r2, (time.perf_counter() - t0) * 1000)


def run_threat(r1):
    from common import attacks                                    
    import random as _random
    pre = wait_for("crypto.json")
    t0 = time.perf_counter()
    r3 = m3.assess(r1, pre["crypto"])
                                                                                
                                                                          
                                                        
    all_ids = list(r1.keys())
    k = min(int(os.environ.get("ATTACK_TARGETS", "7")), len(all_ids))
    rng = _random.Random(int(os.environ.get("ATTACK_SEED", "42")))
    targeted = sorted(rng.sample(all_ids, k),
                      key=lambda d: (int("".join(c for c in d if c.isdigit()) or 0), d))
    scan_targets = {"aggregator": [8000], "mqtt": [1883]}
    r3["attack_results"] = attacks.run_attacks(targeted, scan_targets)
    r3["attack_results"]["targeted_devices"] = targeted
    r3["attack_results"]["all_devices"] = all_ids
                                                                       
    import csv as _csv
    rows = attacks.to_rows(r3["attack_results"])
    with open(OUT / "attack_details.csv", "w", newline="", encoding="utf-8") as f:
        w = _csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    try:
        conns = len(psutil.net_connections())
    except Exception:                                              
        conns = -1
    r3["runtime_posture"] = {
        "process_count": len(psutil.pids()),
        "network_connections": conns,
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory_percent": psutil.virtual_memory().percent,
    }
    total_succ = sum(len(v["succeeded"])
                     for v in r3["attack_results"]["per_device"].values())
    log("attacks launched on %d/%d devices (%s): %d succeeded; open ports=%s" %
        (len(targeted), len(all_ids), ",".join(targeted), total_succ,
         r3["attack_results"]["network_recon"]))
    write("threat.json", r3, (time.perf_counter() - t0) * 1000)


def _wait_ollama(timeout=420):
    base = os.environ.get("OLLAMA_BASE_URL")
    model = os.environ.get("OLLAMA_MODEL")
    if not base or not model:
        return False
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            tags = requests.get(base.rstrip("/") + "/api/tags", timeout=5).json()
            names = [m.get("name", "") for m in tags.get("models", [])]
            if any(model.split(":")[0] in n for n in names):
                log("ollama ready: %s" % names)
                return True
        except Exception:                                          
            pass
        log("waiting for ollama model %s to be pulled ..." % model)
        time.sleep(6)
    log("ollama not ready in time -> using offline fallback")
    return False


def _warmup_ollama():
    base = os.environ.get("OLLAMA_BASE_URL")
    model = os.environ.get("OLLAMA_MODEL")
    if not base or not model:
        return
    try:
        requests.post(base.rstrip("/") + "/api/generate",
                      json={"model": model, "prompt": "ok", "stream": False,
                            "options": {"num_predict": 1}}, timeout=180)
        log("ollama model %s warmed up (loaded into memory)" % model)
    except Exception as e:                                             
        log("ollama warmup failed (%s) -> first call may cold-load" % type(e).__name__)


def run_xai(r1):
    pre = wait_for("crypto.json", "threat.json")
    _wait_ollama()
    t0 = time.perf_counter()
    r5, fw_comparison = m5.reason(r1, pre["crypto"], pre["threat"])
    explanations = _ollama_explain(r5, pre["threat"])
    write("xai.json", {"agents": r5, "framework_comparison": fw_comparison,
                       "llm_explanations": explanations},
          (time.perf_counter() - t0) * 1000)


def run_kg(r1):
    pre = wait_for("crypto.json", "threat.json", "xai.json")
    t0 = time.perf_counter()
    r5 = pre["xai"]["agents"]
    r4 = m4.build(r1, pre["crypto"], pre["threat"], r5)
    write("kg.json", r4, (time.perf_counter() - t0) * 1000)


def _ollama_explain(r5, r3):
    try:
        from shared import llm_client
    except Exception as e:                                         
        log("llm_client unavailable: %s" % e)
        return {}
    out = {}
    for dev_id, f in r5.items():
        xai = f["xai"]
        sysmsg = ("You are an IIoT crypto security analyst. In 2 sentences explain the "
                  "device's main risk and the fix. Be concrete.")
        user = ("Device %s: risk=%.2f, best XAI method=%s, root cause=%s. "
                "EVIDENCE_JSON: {}" % (dev_id, r3["risk"][dev_id],
                                       xai["best_method"], xai.get("dominant_kg_node")))
        text, meta = llm_client.complete(sysmsg, user, want_json=False)
        out[dev_id] = {"provider": meta["provider"], "explanation": text.strip()[:400]}
    log("LLM explanations via %s" % (out.get(next(iter(out)), {}).get("provider")
                                     if out else "n/a"))
    return out


def run_recommend(r1):
    pre = wait_for("config.json", "threat.json", "kg.json", "xai.json")
    t0 = time.perf_counter()
    config, threat, kg = pre["config"], pre["threat"], pre["kg"]
    atk_all = threat.get("attack_results", {}).get("per_device", {})
    out = {}
    for dev_id in sorted(r1):
        recs = []
                                                                      
        for o in atk_all.get(dev_id, {}).get("attacks", []):
            if o.get("success"):
                                                                                 
                                                                               
                sev = "CRITICAL"
                recs.append({"priority": sev, "issue": o["attack"],
                             "recommendation": o.get("remediation", ""),
                             "prevention": o.get("prevention", "")})
                                    
        for issue in config["findings"][dev_id]["issues"]:
            if issue != "nominal":
                recs.append({"priority": "MEDIUM", "issue": issue,
                             "recommendation": "Remediate: %s" % issue,
                             "prevention": "Add a compliance gate for this control."})
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        recs.sort(key=lambda r: order.get(r["priority"], 9))
        out[dev_id] = {"root_cause": kg.get(dev_id, {}).get("root_cause_node"),
                       "risk": threat["risk"][dev_id],
                       "recommendations": recs}
    write("recommendations.json", {"per_device": out}, (time.perf_counter() - t0) * 1000)
    log("recommendations: %s" %
        {d: len(v["recommendations"]) for d, v in out.items()})


def run_report(r1):
    pre = wait_for("config.json", "crypto.json", "threat.json", "xai.json", "kg.json",
                   "recommendations.json")
    t0 = time.perf_counter()
    config, crypto, threat = pre["config"], pre["crypto"], pre["threat"]
    xai, kg = pre["xai"], pre["kg"]
    report = {"devices": {}}
    lines = ["# Final Security Report (distributed agentic pipeline)\n"]
    for dev_id in sorted(r1):
        risk = threat["risk"][dev_id]
        root = kg.get(dev_id, {}).get("root_cause_node") or "none"
        expl = xai["llm_explanations"].get(dev_id, {})
        atk = threat.get("attack_results", {}).get("per_device", {}).get(dev_id, {})
        succeeded = atk.get("succeeded", [])
        dev_report = {
            "risk": risk,
            "risk_level": ("critical" if risk >= 0.6 else "high" if risk >= 0.35
                           else "medium" if risk >= 0.2 else "low"),
            "root_cause": root,
            "config_issues": config["findings"][dev_id]["issues"],
            "attacks_succeeded": succeeded,
            "crypto": {m: crypto["table"][m][dev_id] for m in crypto["methods"]},
            "best_xai_method": xai["agents"][dev_id]["xai"]["best_method"],
            "llm_explanation": expl.get("explanation"),
            "llm_provider": expl.get("provider"),
        }
        report["devices"][dev_id] = dev_report
        lines += [
            "## %s — risk %.2f (%s)" % (dev_id, risk, dev_report["risk_level"]),
            "- root cause: **%s**" % root,
            "- config issues: %s" % ", ".join(dev_report["config_issues"]),
            "- **attacks succeeded: %s**" % (", ".join(succeeded) if succeeded else "none"),
            "- best XAI method: %s" % dev_report["best_xai_method"],
            "- explanation (%s): %s" % (expl.get("provider"), expl.get("explanation")),
        ]
                                                                                    
        atk_details = atk.get("attacks", [])
        remediations = [o for o in atk_details if o.get("success")]
        if remediations:
            lines.append("- **remediation (ensure it won't happen again):**")
            for o in remediations:
                lines.append("    - %s: %s _Prevention:_ %s" %
                             (o["attack"], o.get("remediation", ""), o.get("prevention", "")))
        lines.append("")
    report["network_recon"] = threat.get("attack_results", {}).get("network_recon", {})
    (OUT / "final_report.json").write_text(json.dumps(report, indent=2, default=str),
                                           encoding="utf-8")
    (OUT / "final_report.md").write_text("\n".join(lines), encoding="utf-8")
    write("report_meta.json", {"devices_reported": len(report["devices"])},
          (time.perf_counter() - t0) * 1000)
    log("wrote final_report.json / final_report.md")


def run_compare(r1):
    sys.path.insert(0, "/app/multi_agent_experiments")
    from shared import evidence as evm, task                       
    from own_framework import agent_runtime                         
    from crewai_framework import crew                               
    t0 = time.perf_counter()
                                                                                
                                                                                 
                                                                              
                                                           
    if _wait_ollama():
        _warmup_ollama()
    fw_dir = Path("/app/data/frameworks"); fw_dir.mkdir(parents=True, exist_ok=True)
    ev, ref = evm.build_evidence()
    ref_risk = ref["risk"]

    reports, metas = {}, {}
                                                                                 
                                                                                  
                                                                                
                                                                                   
                                        
    log("running Own uncontended (crewai/akka held until Own finishes) ...")
    ro, mo = agent_runtime.run(ev); reports["own"] = ro; metas["own"] = mo
    log("Own done: provider=%s genuine=%s" % (mo.get("llm_provider"),
                                              mo.get("genuine_llm_calls")))

                                                                                    
                                                                          
    (fw_dir / "evidence_input.json").write_text(
        json.dumps({"evidence": ev, "reference": ref}, indent=2, default=str),
        encoding="utf-8")

                                                                                   
                                                                                  
                                                                                  
                             
                                                                                 
                                                                     
    for fw, fname, waits in [("akka", "akka_result.json", 1200),                      
                             ("crewai", "crewai_result.json", 1200)]:                   
        p = fw_dir / fname
        for _ in range(waits):
            if p.exists():
                break
            time.sleep(3)
        if p.exists():
            data = json.loads(p.read_text(encoding="utf-8"))
            reports[fw] = data.get("reports", data)
            metas[fw] = data.get("meta", {})
                                                                                
                                                                              
                                                                
            if not metas[fw].get("total_latency_ms"):
                am = fw_dir / "akka_mem.json"
                if fw == "akka" and am.exists():
                    try:
                        lat = json.loads(am.read_text("utf-8")).get("latency_ms")
                        if lat:
                            metas[fw]["total_latency_ms"] = float(lat)
                    except (ValueError, OSError):
                        pass
            log("using REAL %s container output" % fw)
        elif fw == "crewai":
            rc, mc = crew.run(ev); reports["crewai"] = rc; metas["crewai"] = mc
            log("crewai container absent -> emulated fallback")
        else:
            log("akka container output absent -> skipped")

                                                                            
                                                                              
                                                                         
                                                                
    _CAP_FLAGS = ["llm", "tools", "autonomy", "memory", "multi_agent", "jvm_free"]

    def _capability(meta, genuine_rate):
                                                                                
                                                                                  
                                                                             
        feats = dict(meta.get("features", {}))
        feats["llm"] = isinstance(genuine_rate, (int, float)) and genuine_rate > 0
        feats["tools"] = (meta.get("total_tool_calls") or 0) > 0
        return round(sum(1 for k in _CAP_FLAGS if feats.get(k)) / len(_CAP_FLAGS), 3)

    def _peak_mem_mb(fw, meta):
        if fw == "akka":
            am = fw_dir / "akka_mem.json"
            if am.exists():
                try:
                    b = json.loads(am.read_text("utf-8")).get("peak_bytes", 0)
                    return round(b / 1e6, 1) if b else None
                except (ValueError, OSError):
                    return None
        return meta.get("peak_memory_mb")

    rows = []
    for fw, reps in reports.items():
        per, means = task.score_all_fair(reps, ref_risk)
        raw_acc, raw_n = task.raw_tier_accuracy(reps, ref_risk)
        meta = metas.get(fw, {})
        quality = round(0.40 * means["oracle_agreement"]
                        + 0.20 * means["schema_validity"]
                        + 0.20 * means["recommendation_quality"]
                        + 0.20 * means["reasoning_coherence"], 3)
        tool = 1.0 if (meta.get("total_tool_calls") or 0) > 0 else 0.0
        raw_valid = meta.get("raw_valid_rate")
                                                                              
                                                                                     
                                                                              
                                                                                 
                                                                                
                                                                               
                                                                               
                                                                                   
                               
        if fw == "akka":
                                                                                
                                                                       
            provider = ("ollama (real, akka actors)"
                        if meta.get("features", {}).get("llm")
                        else "rule-based (LLM unreachable)")
            genuine = raw_valid if raw_valid is not None else "n/a"
        elif fw == "crewai":
            provider = ("ollama (real container)" if meta.get("mode") == "crewai-real"
                        else "emulated fallback")
            genuine = raw_valid if raw_valid is not None else "n/a"
        else:
            provider = meta.get("llm_provider") or "n/a"
                                                                                   
                                                                                      
            genuine = meta.get("genuine_llm_rate")
            if genuine is None:
                genuine = raw_valid if raw_valid is not None else "n/a"
        cap = _capability(meta, genuine)
        peak_mb = _peak_mem_mb(fw, meta)
        rows.append({"framework": fw,
                     "provider": provider,
                     "genuine_llm_rate": genuine,
                     "peak_memory_mb": peak_mb if peak_mb is not None else "n/a",
                     "raw_tier_accuracy": raw_acc if raw_acc is not None else "n/a",
                     "raw_tier_attempts": raw_n,
                     "oracle_agreement": means["oracle_agreement"],
                     "recommendation_quality": means["recommendation_quality"],
                     "reasoning_coherence": means["reasoning_coherence"],
                     "grounded_report_quality": quality,
                     "tool_autonomy": tool, "capability_coverage": cap,
                     "raw_output_validity": raw_valid if raw_valid is not None else "n/a",
                     "latency_ms": meta.get("total_latency_ms", "n/a"),
                     "overall": raw_acc if raw_acc is not None else "n/a"})

    (OUT / "framework_comparison.json").write_text(
        json.dumps({"metric": "fair_quality+engineering", "rows": rows},
                   indent=2, default=str), encoding="utf-8")
    axes = ["provider", "genuine_llm_rate", "raw_tier_accuracy",
            "grounded_report_quality", "oracle_agreement",
            "recommendation_quality", "reasoning_coherence", "tool_autonomy",
            "capability_coverage", "raw_output_validity", "peak_memory_mb",
            "latency_ms", "overall"]
    md = ["# 3-Framework Agent Comparison - fair quality + REAL engineering axes "
          "(live, via Ollama)\n",
          "| framework | " + " | ".join(axes) + " |",
          "|---|" + "---|" * len(axes)]
    for r in rows:
        md.append("| %s | %s |" % (r["framework"],
                                   " | ".join(str(r.get(a, "-")) for a in axes)))
    (OUT / "framework_comparison.md").write_text("\n".join(md), encoding="utf-8")
    _fig_compare(rows, ["oracle_agreement", "recommendation_quality",
                        "reasoning_coherence", "tool_autonomy", "capability_coverage"])
    write("compare_meta.json", {"frameworks": [r["framework"] for r in rows]},
          (time.perf_counter() - t0) * 1000)
    log("compared frameworks (quality+engineering): %s"
        % [(r["framework"], r["overall"]) for r in rows])


def _fig_compare(rows, axes):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
        show = [a for a in axes if a != "overall"]
        x = np.arange(len(show)); w = 0.8 / max(len(rows), 1)
        fig, ax = plt.subplots(figsize=(11, 5))
        for i, r in enumerate(rows):
            ax.bar(x + i * w, [r.get(a, 0) for a in show], w, label=r["framework"])
        ax.set_xticks(x + w * (len(rows) - 1) / 2)
        ax.set_xticklabels(show, rotation=20, ha="right")
        ax.set_ylim(0, 1.05); ax.legend()
        ax.set_title("Framework comparison — fair multi-axis metric")
        fig.tight_layout(); fig.savefig(OUT / "framework_comparison.png", dpi=140)
        plt.close(fig)
    except Exception as e:                                          
        log("figure skipped: %s" % e)


ROLES = {"config": run_config, "crypto": run_crypto, "threat": run_threat,
         "xai": run_xai, "kg": run_kg, "recommend": run_recommend,
         "report": run_report, "compare": run_compare}


def main():
    log("starting (framework=%s)" % FRAMEWORK)
    r1 = fetch_r1()
    log("pulled %d device profiles from aggregator" % len(r1))
    ROLES[ROLE](r1)
    log("done")


if __name__ == "__main__":
    main()
