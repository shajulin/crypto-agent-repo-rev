import sys
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from shared import evidence as ev_mod, task                        
from own_framework import agent_runtime                             


def main():
    print("[own] building shared crypto evidence (Modules 1-3) ...")
    evidence, ref = ev_mod.build_evidence()
    print("[own] running our agentic framework ...")
    reports, meta = agent_runtime.run(evidence)
    per, mean = task.score_all(reports, ref["risk"])

    print("\n=== OUR FRAMEWORK: per-device reports ===")
    for dev, rep in reports.items():
        print("  %-6s risk=%-9s root=%-32s score=%.2f" %
              (dev, rep.get("risk_level"), str(rep.get("root_cause"))[:32], per[dev]["overall"]))
    print("\nLLM provider: %s | total latency: %.1f ms | tool calls: %d | mean task score: %.3f"
          % (meta["llm_provider"], meta["total_latency_ms"], meta["total_tool_calls"], mean))
    print("features:", meta["features"])

    out = {"framework": "own", "reports": reports, "scores": per,
           "mean_score": mean, "meta": {k: v for k, v in meta.items() if k != "trace"}}
    (HERE / "result.json").write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    print("\n[own] wrote", HERE / "result.json")
    return out


if __name__ == "__main__":
    main()
