from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
COMPOSE = _ROOT / ".platform_run.yml"
DATA = _ROOT / "data"
RESULTS = _ROOT / "results"
IMAGE = "iiot-node:latest"
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")

                                                                
_DEVICE_TYPES = ["ESP32", "ESP32-S3", "RaspberryPi", "RaspberryPi", "ESP32"]


                                                                              

def _node(command, environment, depends_on=None):
    svc = {
        "build": {"context": ".", "dockerfile": "distributed/Dockerfile"},
        "image": IMAGE,
        "command": command,
        "environment": environment,
        "volumes": ["./data:/app/data"],
    }
    if depends_on is not None:
        svc["depends_on"] = depends_on
    return svc


def build_compose(n_devices: int, n_attacks: int, seed: int) -> dict:
    agg_url = "http://aggregator:8000"
    ollama_url = "http://ollama:11434"
    services: dict = {}

                                 
    services["mqtt"] = {
        "image": "eclipse-mosquitto:2",
        "volumes": ["./distributed/mqtt/mosquitto.conf:/mosquitto/config/mosquitto.conf:ro"],
        "ports": ["1883:1883"],
    }
    for i in range(1, n_devices + 1):
        services["dev%d" % i] = _node(
            ["python", "distributed/device_agent.py"],
            {"DEVICE_ID": "dev%d" % i,
             "DEVICE_TYPE": _DEVICE_TYPES[(i - 1) % len(_DEVICE_TYPES)],
             "PUBLISH_INTERVAL": "3600"},
            depends_on=["mqtt"],
        )
    services["aggregator"] = _node(
        ["python", "distributed/aggregator.py"],
        {"EXPECTED_DEVICES": str(n_devices)},
        depends_on=["mqtt"],
    )
    services["aggregator"]["ports"] = ["8000:8000"]
    services["monitor"] = _node(
        ["python", "distributed/monitor.py"],
        {"AGGREGATOR_URL": agg_url, "MONITOR_SAMPLES": "10", "MONITOR_INTERVAL": "4"},
        depends_on=["aggregator"],
    )
    services["monitor"]["volumes"] = [
        "./data:/app/data", "/var/run/docker.sock:/var/run/docker.sock"]

                                  
    services["ollama"] = {
        "image": "ollama/ollama:latest",
        "entrypoint": ["/bin/sh", "-c",
                       "ollama serve & sleep 8 && (ollama pull %s || true) && wait"
                       % OLLAMA_MODEL],
        "volumes": ["ollama_models:/root/.ollama"],
        "ports": ["11434:11434"],
    }

    def _agent(role, environment, depends_on):
        env = {"AGENT_ROLE": role, "FRAMEWORK": "own", "AGGREGATOR_URL": agg_url}
        env.update(environment)
        return _node(["python", "distributed/agent.py"], env, depends_on=depends_on)

    ok = "service_completed_successfully"
    services["agent-config"] = _agent("config", {}, ["aggregator"])
    services["agent-crypto"] = _agent("crypto", {}, ["aggregator"])
                                                                                     
    services["agent-threat"] = _agent(
        "threat", {"ATTACK_TARGETS": str(n_attacks), "ATTACK_SEED": str(seed)},
        {"agent-crypto": {"condition": ok}})
    services["agent-xai"] = _agent(
        "xai", {"OLLAMA_BASE_URL": ollama_url, "OLLAMA_MODEL": OLLAMA_MODEL},
        {"agent-threat": {"condition": ok}, "ollama": {"condition": "service_started"}})
    services["agent-kg"] = _agent("kg", {}, {"agent-xai": {"condition": ok}})
    services["agent-recommend"] = _agent(
        "recommend", {}, {"agent-kg": {"condition": ok}})
    services["agent-report"] = _agent(
        "report", {}, {"agent-recommend": {"condition": ok}})
                                                                                  
                                                                                   
    services["agent-compare"] = _agent(
        "compare", {"OLLAMA_BASE_URL": ollama_url, "OLLAMA_MODEL": OLLAMA_MODEL},
        {"agent-report": {"condition": ok}, "ollama": {"condition": "service_started"}})

                                       
    services["crewai"] = {
        "build": {"context": ".", "dockerfile": "distributed/Dockerfile.crewai"},
        "depends_on": ["ollama"],
        "environment": {"OLLAMA_BASE_URL": ollama_url, "OLLAMA_MODEL": OLLAMA_MODEL,
                        "CREWAI_TRACING_ENABLED": "false", "OTEL_SDK_DISABLED": "true"},
        "volumes": ["./data:/app/data"],
    }
    services["akka"] = {
        "image": "sbtscala/scala-sbt:eclipse-temurin-jammy-17.0.10_7_1.9.9_2.13.13",
        "working_dir": "/project",
                                                                                
                                                                             
                                                                           
        "environment": {"JAVA_TOOL_OPTIONS": "-Xmx768m -XX:MaxMetaspaceSize=256m",
                        "SBT_OPTS": "-Xmx512m"},
        "volumes": ["./multi_agent_experiments/akka_framework:/project", "./data:/data",
                                                                                   
                                                                                   
                    "akka_ivy:/root/.ivy2", "akka_sbt:/root/.sbt",
                    "akka_coursier:/root/.cache"],
                                                                                
                                                           
        "command": ["bash", "-c", "tr -d '\\r' < /project/run_with_mem.sh | bash"],
    }

    return {"services": services,
            "volumes": {"ollama_models": None, "akka_ivy": None,
                        "akka_sbt": None, "akka_coursier": None}}


                                                                              

def _dc(*args, check=False, **kw):
    return subprocess.run(["docker", "compose", "-f", str(COMPOSE), *args],
                          cwd=str(_ROOT), text=True, check=check, **kw)


def _preflight_model() -> None:
    print("\n[preflight] ensuring local Ollama model '%s' is available ..." % OLLAMA_MODEL)
    subprocess.run(["docker", "volume", "create", "ollama_models"],
                   capture_output=True, text=True, encoding="utf-8", errors="replace")
    common = ["-v", "ollama_models:/root/.ollama", "ollama/ollama:latest"]
    pull = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "/bin/sh", *common, "-c",
         "ollama serve & sleep 8 && ollama pull %s && ollama list" % OLLAMA_MODEL],
        text=True, encoding="utf-8", errors="replace", capture_output=True)
    out = (pull.stdout or "") + (pull.stderr or "")
    if OLLAMA_MODEL.split(":")[0] in out and pull.returncode == 0:
        print("[preflight] OK — local model '%s' is pulled and ready." % OLLAMA_MODEL)
    else:
        print("[preflight] WARNING — could not confirm the model was pulled:")
        print("\n".join(out.strip().splitlines()[-8:]))
        print("[preflight] the ollama service will retry the pull during the run.")


def _rmtree(path: Path) -> None:
    if not path.exists():
        return
    for child in path.iterdir():
        if child.is_dir():
            _rmtree(child)
            try:
                child.rmdir()
            except OSError:
                pass
        else:
            try:
                child.unlink()
            except OSError:
                pass


def _clean_stale_outputs() -> None:
    print("[clean] removing previous data/ and results/ (clean slate) ...")
    _rmtree(DATA)
    _rmtree(RESULTS)
    stale_yml = _ROOT / ".phase1_run.yml"
    if stale_yml.exists():
        try:
            stale_yml.unlink()
        except OSError:
            pass
    DATA.mkdir(exist_ok=True)
    (RESULTS / "phase1").mkdir(parents=True, exist_ok=True)
    (RESULTS / "phase2").mkdir(parents=True, exist_ok=True)


def _preflight_akka() -> None:
    print("\n[preflight] compiling Akka project (downloads JVM deps once) ...")
    for v in ("akka_ivy", "akka_sbt", "akka_coursier"):
        subprocess.run(["docker", "volume", "create", v], capture_output=True, text=True, encoding="utf-8", errors="replace")
    akka_dir = _ROOT / "multi_agent_experiments" / "akka_framework"
    r = subprocess.run(
        ["docker", "run", "--rm",
         "-v", "%s:/project" % akka_dir, "-w", "/project",
         "-v", "akka_ivy:/root/.ivy2", "-v", "akka_sbt:/root/.sbt",
         "-v", "akka_coursier:/root/.cache",
         "sbtscala/scala-sbt:eclipse-temurin-jammy-17.0.10_7_1.9.9_2.13.13",
         "sbt", "compile"],
        text=True, encoding="utf-8", errors="replace", capture_output=True, timeout=1200)
    if r.returncode == 0:
        print("[preflight] OK — Akka compiled and its deps are cached.")
    else:
        print("[preflight] WARNING — Akka compile did not finish cleanly:")
        print("\n".join(((r.stdout or "") + (r.stderr or "")).strip().splitlines()[-8:]))


def _render_figures() -> None:
    RESULTS.mkdir(exist_ok=True)
    mounts = ["-v", "%s:/app/data" % (DATA), "-v", "%s:/app/results" % (RESULTS)]
    for mod in ("figures.phase1", "figures.phase2"):
        print("\n[figures] rendering %s ..." % mod)
        r = subprocess.run(["docker", "run", "--rm", *mounts, IMAGE, "python", "-m", mod],
                           cwd=str(_ROOT), text=True, encoding="utf-8", errors="replace", capture_output=True)
        sys.stdout.write(r.stdout)
        if r.returncode != 0:
            sys.stdout.write(r.stderr)
            print("[figures] %s exited %d" % (mod, r.returncode))


def _report_comparison() -> None:
    fc = DATA / "agents" / "own" / "framework_comparison.json"
    md = DATA / "agents" / "own" / "framework_comparison.md"
    print("\n" + "=" * 68 + "\nFRAMEWORK COMPARISON (Own vs CrewAI vs Akka)\n" + "=" * 68)
    if md.exists():
        print(md.read_text(encoding="utf-8"))
    elif fc.exists():
        print(json.dumps(json.loads(fc.read_text(encoding="utf-8")), indent=2))
    else:
        print("(no framework_comparison produced — check container logs above)")

                                                                                
                                                                              
                                        
    if not fc.exists():
        return
    print("\n" + "-" * 68 + "\nGENUINENESS CHECK (real LLM vs offline/derived fallback)\n"
          + "-" * 68)
    rows = json.loads(fc.read_text(encoding="utf-8")).get("rows", [])
    for r in rows:
        fw = r.get("framework"); prov = r.get("provider"); g = r.get("genuine_llm_rate")
        lat = r.get("latency_ms")
        if fw == "akka":
            verdict = "OK — rule-based by design (no LLM claimed)"
        elif isinstance(g, (int, float)) and g >= 0.99:
            verdict = "GENUINE — all verdicts from the real local LLM"
        elif isinstance(g, (int, float)) and g > 0.0:
            verdict = "PARTIAL — %.0f%% genuine LLM, rest deterministic fallback" % (g * 100)
        else:
            verdict = "FALLBACK — verdicts came from the offline/derived reasoner, NOT the LLM"
        print("  %-7s provider=%-26s genuine=%-5s latency=%-9s -> %s"
              % (fw, prov, g, lat, verdict))
    print("(Rule of thumb: a real llama3.2:3b verdict takes seconds; a total "
          "latency of milliseconds means the offline fallback ran.)")


def run(n_devices: int, n_attacks: int, seed: int, build: bool = True) -> None:
    COMPOSE.write_text(json.dumps(build_compose(n_devices, n_attacks, seed), indent=2),
                       encoding="utf-8")
    DATA.mkdir(exist_ok=True)
    print("\n[run] wrote %s (%d devices, attacking %d, seed %d)"
          % (COMPOSE.name, n_devices, n_attacks, seed))

    _clean_stale_outputs()
    _preflight_model()
    _preflight_akka()

    fc = DATA / "agents" / "own" / "framework_comparison.json"
    if fc.exists():
        fc.unlink()

    t0 = time.perf_counter()
    if build:
        print("\n[run] docker compose build ... (first build can take several minutes)")
        _dc("build")
    print("[run] docker compose up -d ...")
    _dc("up", "-d")

    print("[run] waiting for the agent chain + framework comparison to finish ...")
    print("[run] NOTE: frameworks now run GENUINE, UNCONTENDED local-LLM inference "
          "(Own, then CrewAI, then Akka) — on CPU this is slow but real; expect "
          "~15-40 min for a small fleet.")
    deadline = time.perf_counter() + 4500                                             
    last = 0.0
    try:
        while time.perf_counter() < deadline:
            if fc.exists():
                print("[run] framework_comparison.json produced — run complete.")
                break
            now = time.perf_counter()
            if now - last > 30:
                print("   ... still running (%.0fs elapsed)" % (now - t0), flush=True)
                last = now
            time.sleep(3)
        else:
            print("[run] TIMEOUT waiting for completion — dumping recent agent logs:")
            _dc("logs", "--tail", "40", "agent-compare", "crewai", "akka")
    finally:
        print("\n[run] docker compose down ...")
        _dc("down")

    _render_figures()
    _report_comparison()
    print("\n[done] figures in results/phase1 + results/phase2; "
          "data in data/ (total %.0fs)." % (time.perf_counter() - t0))


                                                                              

def _ask_int(prompt: str, default: int, lo: int, hi: int) -> int:
    while True:
        raw = input("%s [%d]: " % (prompt, default)).strip()
        if not raw:
            return default
        try:
            v = int(raw)
        except ValueError:
            print("  please enter a whole number."); continue
        if v < lo or v > hi:
            print("  please enter a value between %d and %d." % (lo, hi)); continue
        return v


def main() -> None:
    ap = argparse.ArgumentParser(description="Interactive full-stack crypto-agents launcher.")
    ap.add_argument("--devices", type=int, help="fleet size N (skip the prompt)")
    ap.add_argument("--attacks", type=int, help="devices to attack A<=N (skip the prompt)")
    ap.add_argument("--seed", type=int, help="attack-selection seed (default: random each run)")
    ap.add_argument("--no-build", action="store_true", help="skip docker build (reuse images)")
    args = ap.parse_args()

    print("=" * 68)
    print("crypto-agents — two-phase IIoT cryptographic-posture platform")
    print("=" * 68)

    n_devices = args.devices if args.devices is not None \
        else _ask_int("How many IIoT devices to simulate?", 5, 1, 200)
    default_attacks = min(7, n_devices)
    n_attacks = args.attacks if args.attacks is not None \
        else _ask_int("How many of them to attack (random subset)?",
                      default_attacks, 0, n_devices)

    if n_attacks > n_devices:
        print("[note] you asked to attack %d devices but only %d exist — "
              "clamping to %d (can't attack more devices than there are)."
              % (n_attacks, n_devices, n_devices))
        n_attacks = n_devices

                                                                               
                                                       
    seed = args.seed if args.seed is not None else random.randint(1, 10_000_000)

    print("\nPlan:")
    print("  • simulate %d devices (each a distinct synthesized config)" % n_devices)
    print("  • attack a random %d-device subset (seed=%d)" % (n_attacks, seed))
    print("  • run Phase 1 (MQTT data plane) + Phase 2 (7 agents, Ollama, "
          "CrewAI, Akka) in Docker")
    print("  • render figures for exactly %d devices + framework comparison\n" % n_devices)

    run(n_devices, n_attacks, seed, build=not args.no_build)


if __name__ == "__main__":
    main()
