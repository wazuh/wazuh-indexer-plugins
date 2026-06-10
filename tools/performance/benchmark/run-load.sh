#!/bin/bash
#
# run-load.sh — drive the isolated scenario's findings load and sample the indexer.
#
# Pre-creates the security-analytics detector (setup-detector.sh), then indexes the fixed
# system-activity event into the wazuh-events-v5-system-activity data stream at --rate
# events/sec for --duration seconds (event-loader.py), while metrics/sampler.py samples the
# indexer internals + host (node_exporter) in parallel. Finally it verifies that events were
# indexed AND findings were generated — a run that produces zero findings fails loudly.
#
# Runs on the monitor VM against the indexer over the network (--insecure TLS).
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SAMPLER="$SCRIPT_DIR/../metrics/sampler.py"

TARGET="https://localhost:9200"
USER="admin"
PASSWORD="admin"
RATE=1000
DURATION=600      # load + sampler window (s)
INTERVAL=60       # sampler cadence (s)
OUT="./runs/load-$(date +%Y%m%d-%H%M%S)"
NO_HOST=""        # --no-host → sampler skips local psutil (it runs off the indexer host)
NODE_EXPORTER=""  # node_exporter endpoint (host:9100) for the indexer's host metrics
INDEX="wazuh-events-v5-system-activity"
FINDINGS_INDEX="wazuh-findings-v5-*"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)         TARGET="$2"; shift 2 ;;
        --user)           USER="$2"; shift 2 ;;
        --password)       PASSWORD="$2"; shift 2 ;;
        --rate)           RATE="$2"; shift 2 ;;
        --duration)       DURATION="$2"; shift 2 ;;
        --interval)       INTERVAL="$2"; shift 2 ;;
        --out)            OUT="$2"; shift 2 ;;
        --no-host)        NO_HOST="--no-host"; shift ;;
        --node-exporter)  NODE_EXPORTER="$2"; shift 2 ;;
        --index)          INDEX="$2"; shift 2 ;;
        *) echo "Usage: $0 [--target URL] [--user U] [--password P] [--rate N] [--duration S] [--interval S] [--out DIR] [--no-host] [--node-exporter HOST:9100] [--index IDX]"; exit 1 ;;
    esac
done

NE_ARG=()
[[ -n "$NODE_EXPORTER" ]] && NE_ARG=(--node-exporter "$NODE_EXPORTER")
mkdir -p "$OUT"

# 1. Pre-create the detector so indexed events become findings.
bash "$SCRIPT_DIR/setup-detector.sh" --target "$TARGET" --user "$USER" --password "$PASSWORD" \
    --index "$INDEX" --insecure | tee "$OUT/detector-setup.txt"

# 2. Sample cluster internals + host alongside the load (background) for the window.
python3 "$SAMPLER" --endpoint "$TARGET" --user "$USER" --password "$PASSWORD" \
    --interval "$INTERVAL" --duration "$DURATION" --out "$OUT" --insecure $NO_HOST ${NE_ARG[@]+"${NE_ARG[@]}"} &
SAMPLER_PID=$!

# 3. Drive the steady-rate load for the window.
LOAD_RC=0
echo "[INFO] Indexing $INDEX at $RATE events/s for ${DURATION}s ..."
python3 "$SCRIPT_DIR/event-loader.py" --target "$TARGET" --user "$USER" --password "$PASSWORD" \
    --index "$INDEX" --rate "$RATE" --duration "$DURATION" --insecure 2>&1 | tee "$OUT/load-report.txt" \
    || LOAD_RC=$?

wait "$SAMPLER_PID" 2>/dev/null || true

# 4. Give the detector's monitor a moment to run its 1-minute schedule, then sanity-check.
echo "[INFO] Waiting 90s for the detector monitor to evaluate the last events ..."
sleep 90
curl -ks -u "$USER:$PASSWORD" "$TARGET/$INDEX/_refresh" >/dev/null 2>&1 || true

count() { curl -ks -u "$USER:$PASSWORD" "$TARGET/$1/_count" | grep -o '"count":[0-9]*' | head -1 | cut -d: -f2; }
EVENTS=$(count "$INDEX"); [[ "$EVENTS" =~ ^[0-9]+$ ]] || EVENTS=0
FINDINGS=$(count "$FINDINGS_INDEX"); [[ "$FINDINGS" =~ ^[0-9]+$ ]] || FINDINGS=0

echo "[INFO] Events indexed into '$INDEX': $EVENTS | Findings in '$FINDINGS_INDEX': $FINDINGS"
{ echo "events_indexed=$EVENTS"; echo "findings=$FINDINGS"; } >> "$OUT/load-report.txt"
echo "[INFO] Report: $OUT/load-report.txt | metrics: $OUT/metrics.csv"

if [[ "$LOAD_RC" -ne 0 || "$EVENTS" -eq 0 ]]; then
    echo "[ERROR] Load indexed no events (loader exit=$LOAD_RC, events=$EVENTS)." >&2
    echo "        Check the indexer is reachable at $TARGET and the data stream exists." >&2
    exit 1
fi
if [[ "$FINDINGS" -eq 0 ]]; then
    echo "[ERROR] $EVENTS events indexed but ZERO findings generated." >&2
    echo "        The detector did not match. Inspect $OUT/detector-setup.txt and the rule/mapping" >&2
    echo "        (benchmark/detector/). The monitor runs on a 1-min schedule — a longer --duration helps." >&2
    exit 1
fi
echo "[INFO] OK — $EVENTS events → $FINDINGS findings."
