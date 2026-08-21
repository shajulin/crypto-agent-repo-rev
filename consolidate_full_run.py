import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
OUT = RESULTS / "full_run"
CSV_OUT = OUT / "csv"
IMG_OUT = OUT / "images"
DOCKER_OUT = OUT / "docker"

CSV_FILES = [
    "xai_trials.csv", "xai_trials_summary.csv",
    "llm_eval_trials.csv", "llm_eval_summary.csv",
    "crewai_eval_trials.csv", "crewai_eval_summary.csv",
    "akka_eval_trials.csv", "akka_eval_summary.csv",
    "llm_eval_trials_qwen2_5_14b.csv", "llm_eval_summary_qwen2_5_14b.csv",
    "crewai_eval_trials_qwen2_5_14b.csv", "crewai_eval_summary_qwen2_5_14b.csv",
    "akka_eval_trials_qwen2_5_14b.csv", "akka_eval_summary_qwen2_5_14b.csv",
    "llm_eval_trials_selfconsistency.csv", "llm_eval_summary_selfconsistency.csv",
    "llm_eval_trials_fewshot.csv", "llm_eval_summary_fewshot.csv",
]
IMG_FILES = ["xai_trial_reliability.png", "framework_llm_comparison.png", "model_comparison.png"]
DOCKER_FILES = [
    (ROOT / "data" / "agents" / "own" / "final_report.json", "final_report.json"),
    (ROOT / "data" / "agents" / "own" / "final_report.md", "final_report.md"),
    (ROOT / "data" / "agents" / "own" / "framework_comparison.md", "framework_comparison.md"),
    (ROOT / "data" / "agents" / "own" / "framework_comparison.png", "framework_comparison.png"),
    (ROOT / "data" / "agents" / "own" / "xai.json", "own_xai.json"),
    (ROOT / "data" / "agents" / "own" / "threat.json", "own_threat.json"),
    (ROOT / "data" / "frameworks" / "crewai_result.json", "crewai_result.json"),
    (ROOT / "data" / "frameworks" / "akka_result.json", "akka_result.json"),
]


def _copy_glob(pattern, dest_dir):
    copied = []
    for p in sorted(RESULTS.glob(pattern)):
        shutil.copy2(p, dest_dir / p.name)
        copied.append(p.name)
    return copied


def main():
    missing = []
    for d in (CSV_OUT, IMG_OUT, DOCKER_OUT):
        d.mkdir(parents=True, exist_ok=True)

    copied_csv = []
    for name in CSV_FILES:
        src = RESULTS / name
        if src.exists():
            shutil.copy2(src, CSV_OUT / name)
            copied_csv.append(name)
        else:
            missing.append("results/" + name)
    per_device_method = _copy_glob("xai_trials_dev*_*.csv", CSV_OUT)
    copied_csv += per_device_method

    copied_img = []
    for name in IMG_FILES:
        src = RESULTS / name
        if src.exists():
            shutil.copy2(src, IMG_OUT / name)
            copied_img.append(name)
        else:
            missing.append("results/" + name)

    copied_docker = []
    for src, name in DOCKER_FILES:
        if src.exists():
            shutil.copy2(src, DOCKER_OUT / name)
            copied_docker.append(name)
        else:
            missing.append(str(src.relative_to(ROOT)))

    index = ["# Full run -- consolidated results\n",
            "Everything produced by the repeated-trial rigor pass, in one place.\n",
            "## csv/ (%d files)\n" % len(copied_csv)]
    index += ["- `%s`" % n for n in sorted(copied_csv)]
    index += ["\n## images/ (%d files)\n" % len(copied_img)]
    index += ["- `%s`" % n for n in copied_img]
    index += ["\n## docker/ (%d files, from the live 5-device docker-compose run)\n" % len(copied_docker)]
    index += ["- `%s`" % n for n in copied_docker]
    if missing:
        index += ["\n## MISSING (not copied -- generate these first)\n"]
        index += ["- `%s`" % n for n in missing]
    (OUT / "INDEX.md").write_text("\n".join(index) + "\n", encoding="utf-8")

    print("wrote %s" % (OUT / "INDEX.md"))
    print("csv: %d files, images: %d files, docker: %d files" %
         (len(copied_csv), len(copied_img), len(copied_docker)))
    if missing:
        print("MISSING (%d): %s" % (len(missing), ", ".join(missing)))


if __name__ == "__main__":
    main()
