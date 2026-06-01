#!/bin/bash
#
# run-scenario.sh — orchestrate the 60-minute real-world measurement window.
#
# Marks the run window (ISO start/stop, for annotating your OTel backend) and
# runs the per-minute sampler for the duration. Bring up the AIO first and start
# the agent loops:
#
#   sudo ./setup-aio.sh                          # AIO (manager+indexer+dashboard) from official artifacts
#   sudo ./setup-agent.sh --manager <aio-ip>     # on each agent host
#   ./agent-load.sh --duration 3600              # on each agent host
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SAMPLER="$SCRIPT_DIR/../metrics/sampler.py"

ENDPOINT="https://localhost:9200"
USER="admin"
PASSWORD="admin"
DURATION=3600
INTERVAL=60
OUT="./runs/scenario-$(date +%Y%m%d-%H%M%S)"
INSECURE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --endpoint) ENDPOINT="$2"; shift 2 ;;
        --user)     USER="$2"; shift 2 ;;
        --password) PASSWORD="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        --out)      OUT="$2"; shift 2 ;;
        --insecure) INSECURE="--insecure"; shift ;;
        *) echo "Usage: $0 [--endpoint URL] [--user U] [--password P] [--duration S] [--interval S] [--out DIR] [--insecure]"; exit 1 ;;
    esac
done

mkdir -p "$OUT"
START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "[INFO] Run window START: $START"

python3 "$SAMPLER" \
    --endpoint "$ENDPOINT" --user "$USER" --password "$PASSWORD" \
    --interval "$INTERVAL" --duration "$DURATION" --out "$OUT" $INSECURE

STOP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "[INFO] Run window STOP: $STOP"

cat > "$OUT/run-metadata.json" <<EOF
{
  "track": "A-real-world",
  "endpoint": "$ENDPOINT",
  "start": "$START",
  "stop": "$STOP",
  "duration_s": $DURATION,
  "interval_s": $INTERVAL
}
EOF
echo "[INFO] Wrote $OUT/run-metadata.json"
