#!/usr/bin/env bash
set -uo pipefail
ROOT="/c/Users/hp/Desktop/crypto"
cd "$ROOT"
SIZES="${SIZES:-5 10 15 20 25 30 35 40 45 50}"
MODEL="${MODEL:-qwen2.5:7b}"
COMPOSE="distributed/.scale_run.yml"
IMG="iiot-node:latest"
PER_RUN_TIMEOUT="${PER_RUN_TIMEOUT:-10800}"
OUTROOT="results/scale"
mkdir -p "$OUTROOT"
MASTER="$OUTROOT/sweep_log.txt"
say(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$MASTER"; }
dc(){ docker compose -f "$COMPOSE" "$@"; }
say "=== SCALABILITY SWEEP START — model=$MODEL sizes=[$SIZES] ==="
for N in $SIZES; do
  ATK=$(( (6*N + 9) / 10 )); [ "$ATK" -lt 1 ] && ATK=1
  NN=$(printf "%02d" "$N")
  OUT="$OUTROOT/dev${NN}"
  say "----- N=$N devices, attacks=$ATK -> $OUT -----"
  rm -rf "$OUT"; mkdir -p "$OUT"
  bash distributed/gen_compose.sh "$N" "$ATK" "$MODEL" > "$COMPOSE"
  cp "$COMPOSE" "$OUT/compose.yml"
  rm -rf data 2>/dev/null
  mkdir -p data
  t0=$(date +%s)
  say "building+starting stack (N=$N) ..."
  dc up --build -d --remove-orphans >"$OUT/compose_up.log" 2>&1
  if [ $? -ne 0 ]; then say "!! compose up FAILED for N=$N (see compose_up.log)"; fi
  sentinel_own="data/agents/own/final_report.json"
  sentinel_fw="data/agents/own/framework_comparison.json"
  deadline=$(( t0 + PER_RUN_TIMEOUT ))
  ok_own=0; ok_fw=0
  while [ "$(date +%s)" -lt "$deadline" ]; do
    [ -f "$sentinel_own" ] && ok_own=1
    [ -f "$sentinel_fw" ]  && ok_fw=1
    if [ "$ok_own" = 1 ] && [ "$ok_fw" = 1 ]; then break; fi
    sleep 15
  done
  elapsed=$(( $(date +%s) - t0 ))
  say "run N=$N finished: own_report=$ok_own framework_cmp=$ok_fw elapsed=${elapsed}s"
  curl -s http://localhost:8000/health > "$OUT/health.json" 2>/dev/null || true
  dc ps -a --format '{{.Name}}\t{{.State}}\t{{.ExitCode}}' > "$OUT/containers.txt" 2>&1 || true
  dc logs --no-color > "$OUT/all_containers.log" 2>&1 || true
  say "rendering figures (N=$N) ..."
  rm -rf results/phase1 results/phase2 2>/dev/null
  WINPWD="$(pwd -W 2>/dev/null || pwd)"
  MSYS_NO_PATHCONV=1 docker run --rm -v "${WINPWD}:/app" "$IMG" \
      sh -c "python -m figures.phase1 && python -m figures.phase2" \
      > "$OUT/figures.log" 2>&1 || say "!! figure render had errors (see figures.log)"
  mkdir -p "$OUT/data" "$OUT/figures"
  cp -r data/. "$OUT/data/" 2>/dev/null || true
  cp -r results/phase2/. "$OUT/figures/" 2>/dev/null || true
  cp -r results/phase1/. "$OUT/figures/" 2>/dev/null || true
  succ=$(grep -o '"success": true' data/agents/own/threat.json 2>/dev/null | wc -l)
  say "N=$N archived. attacks_succeeded=$succ elapsed=${elapsed}s"
  dc down >"$OUT/compose_down.log" 2>&1 || true
done
say "=== SCALABILITY SWEEP COMPLETE ==="
