import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
EPISODIC = HERE / "memory_episodic.jsonl"
SEMANTIC = HERE / "memory_semantic.json"


class Memory:
    def __init__(self):
        self.semantic = self._load_semantic()

    def _load_semantic(self):
        if SEMANTIC.exists():
            try:
                return json.loads(SEMANTIC.read_text(encoding="utf-8"))
            except Exception:                                   
                return {}
        return {}

    def remember_episode(self, device, report, evidence):
        rec = {"device": device, "risk_level": report.get("risk_level"),
               "root_cause": report.get("root_cause"),
               "risk": evidence.get("aggregate_risk")}
        with open(EPISODIC, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
                                                                    
        key = "rng:%s" % evidence.get("measurements", {}).get("rng_quality")
        self.semantic.setdefault(key, []).append(report.get("risk_level"))
        SEMANTIC.write_text(json.dumps(self.semantic, indent=2), encoding="utf-8")

    def recall_pattern(self, evidence):
        key = "rng:%s" % evidence.get("measurements", {}).get("rng_quality")
        seen = self.semantic.get(key, [])
        if seen:
            common = max(set(seen), key=seen.count)
            return "memory: devices with %s previously assessed as '%s' (%d times)" % (
                key, common, len(seen))
        return "memory: no prior pattern for this RNG class"
