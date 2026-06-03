#!/bin/bash
#
# run-scenario.sh — orchestrate the 60-minute real-world measurement window.
#
# Marks the run window (ISO start/stop) and runs the per-minute sampler for the
# duration, then generates report.md. Bring up the AIO first and start the agent
# loops:
#
#   sudo ./setup-aio.sh --version 5.0.0                       # AIO (manager+indexer+dashboard)
#   sudo ./setup-agent.sh --version 5.0.0 --manager <aio-ip>  # on each agent host
#   ./agent-load.sh --duration 3600                           # on each agent host
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SAMPLER="$SCRIPT_DIR/../metrics/sampler.py"
REPORT="$SCRIPT_DIR/../analyze/report.py"

ENDPOINT="https://localhost:9200"
USER="admin"
PASSWORD="admin"
DURATION=3600
INTERVAL=60
OUT="./runs/scenario-$(date +%Y%m%d-%H%M%S)"
INSECURE=""
LABEL=""        # version tag for the report, e.g. wazuh-5.0.0 or wazuh-4.x
DISK_PATH="/var/lib/wazuh-indexer"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --endpoint)  ENDPOINT="$2"; shift 2 ;;
        --user)      USER="$2"; shift 2 ;;
        --password)  PASSWORD="$2"; shift 2 ;;
        --duration)  DURATION="$2"; shift 2 ;;
        --interval)  INTERVAL="$2"; shift 2 ;;
        --out)       OUT="$2"; shift 2 ;;
        --label)     LABEL="$2"; shift 2 ;;
        --disk-path) DISK_PATH="$2"; shift 2 ;;
        --insecure)  INSECURE="--insecure"; shift ;;
        *) echo "Usage: $0 [--endpoint URL] [--user U] [--password P] [--duration S] [--interval S] [--out DIR] [--label TAG] [--disk-path PATH] [--insecure]"; exit 1 ;;
    esac
done

mkdir -p "$OUT"
[[ -d "$DISK_PATH" ]] || DISK_PATH="/"   # fall back if the indexer data path is unknown
START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "[INFO] Run window START: $START (label: ${LABEL:-none})"

python3 "$SAMPLER" \
    --endpoint "$ENDPOINT" --user "$USER" --password "$PASSWORD" \
    --interval "$INTERVAL" --duration "$DURATION" --out "$OUT" \
    --disk-path "$DISK_PATH" $INSECURE

STOP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "[INFO] Run window STOP: $STOP"

cat > "$OUT/run-metadata.json" <<EOF
{
  "scenario": "real-world",
  "label": "$LABEL",
  "endpoint": "$ENDPOINT",
  "start": "$START",
  "stop": "$STOP",
  "duration_s": $DURATION,
  "interval_s": $INTERVAL
}
EOF
echo "[INFO] Wrote $OUT/run-metadata.json"

# Generate the hardware-utilization report.
python3 "$REPORT" --run "$OUT" ${LABEL:+--label "$LABEL"} || \
    echo "[WARN] Report generation failed; metrics.csv is still available."
