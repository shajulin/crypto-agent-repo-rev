#!/usr/bin/env bash
until [ -f /data/frameworks/evidence_input.json ]; do
  echo '[akka] waiting for evidence'; sleep 3
done
PEAKFILE=/tmp/akka_peak_kb
echo 0 > "$PEAKFILE"
(
  peak=0
  while true; do
    cur=$(ps -eo rss= 2>/dev/null | awk '{s+=$1} END{print s+0}')
    if [ "${cur:-0}" -gt "$peak" ]; then peak=$cur; echo "$peak" > "$PEAKFILE"; fi
    sleep 1
  done
) &
tracker=$!
t0=$(date +%s%3N)
sbt 'run /data/frameworks' || true
t1=$(date +%s%3N)
sleep 1
kill "$tracker" 2>/dev/null || true
peak_kb=$(cat "$PEAKFILE" 2>/dev/null || echo 0)
elapsed=$((t1 - t0))
printf '{"peak_bytes": %d, "latency_ms": %d}\n' "$((peak_kb * 1024))" "$elapsed" \
  > /data/frameworks/akka_mem.json
echo "[akka] captured peak RSS $((peak_kb / 1024)) MB + latency ${elapsed} ms"
