import sys
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from shared import evidence as ev_mod                             


def main():
    evidence, ref = ev_mod.build_evidence()
    (HERE / "evidence_input.json").write_text(
        json.dumps({"evidence": evidence, "reference": ref}, indent=2, default=str),
        encoding="utf-8")
    print("[akka] wrote", HERE / "evidence_input.json",
          "(%d devices)" % len(evidence))


if __name__ == "__main__":
    main()
