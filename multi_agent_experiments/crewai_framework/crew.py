import sys
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from shared import llm_client                                    

ROLES = [
    ("Config Analyst", "Assess secure boot, update path, and root of trust."),
    ("Crypto Analyst", "Assess cipher, curve, hash and certificate strength."),
    ("Risk Lead", "Combine the above into a final risk verdict and recommendations."),
]

FINAL_SYSTEM = ("You are the Risk Lead of a security crew. Given the crew's notes and "
                "the evidence, return ONLY JSON: device, risk_level "
                "(critical|high|medium|low), root_cause, recommendations (list), "
                "compliance (COMPLIANT|NON-COMPLIANT), reasoning.")


def _real_crewai_available():
                                                                                 
                                                                                 
                                                                       
    return False


def _run_real_crew(evidence_map):
    from crewai import Agent, Task, Crew, Process
    reports = {}
    for dev, ev in evidence_map.items():
        agents = [Agent(role=r, goal=g, backstory="IIoT security specialist.",
                        verbose=False) for r, g in ROLES]
        tasks = [Task(description="%s\nEvidence: %s" % (g, json.dumps(ev, default=str)),
                      agent=a, expected_output="notes") for a, (r, g) in zip(agents, ROLES)]
        crew = Crew(agents=agents, tasks=tasks, process=Process.sequential, verbose=False)
        out = str(crew.kickoff())
        reports[dev] = llm_client.parse_json(out) or {"device": dev}
        reports[dev].setdefault("device", dev)
    return reports, "crewai-real"


def _run_emulated_crew(evidence_map):
    reports = {}
    for dev, ev in evidence_map.items():
        context = []
        for role, goal in ROLES[:-1]:                                       
            sysmsg = "You are the %s. %s Return one short note." % (role, goal)
            user = "EVIDENCE_JSON: %s" % json.dumps(ev, default=str)
            note, _ = llm_client.complete(sysmsg, user, want_json=False)
            context.append("%s: %s" % (role, note[:200]))
                               
        user = "Crew notes:\n%s\n\nEVIDENCE_JSON: %s" % ("\n".join(context),
                                                         json.dumps(ev, default=str))
        text, _ = llm_client.complete(FINAL_SYSTEM, user)
        rep = llm_client.parse_json(text)
        rep.setdefault("device", dev)
        reports[dev] = rep
    return reports, "crewai-emulated"


def run(evidence_map):
    import time
    start = time.perf_counter()
    if _real_crewai_available():
        reports, mode = _run_real_crew(evidence_map)
    else:
        reports, mode = _run_emulated_crew(evidence_map)
    meta = {
        "framework": "crewai", "mode": mode,
        "total_latency_ms": round((time.perf_counter() - start) * 1000, 1),
        "total_tool_calls": 0,                                                                
        "features": {"llm": True, "tools": False, "autonomy": False,
                     "memory": True, "multi_agent": True, "jvm_free": True},
    }
    return reports, meta
