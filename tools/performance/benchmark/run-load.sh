#!/bin/bash
#
# run-load.sh — drive the isolated scenario's findings load and sample the indexer.
#
# Indexes the fixed system-activity event into the wazuh-events-v5-system-activity data
# stream at --rate events/sec for --duration seconds (event-loader.py), while
# metrics/sampler.py samples the indexer internals + host (node_exporter) in parallel.
#
# Findings are produced by the indexer's OWN detection pipeline: the content-manager syncs
# the CTI catalog on start and auto-creates the real detectors (incl. system-activity), whose
# DocumentLevelMonitors match the indexed event. (This build does NOT expose the
# security-analytics REST API to create detectors manually, so we rely on the built-in
# pipeline — see config/perf-tune.yml: catalog_update_on_start + catalog_create_detectors.)
#
# It verifies events were indexed (fatal if zero) and reports the findings count (a warning,
# not fatal, if zero — the perf metrics are still valid and worth keeping).
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

# 0. Auth/connectivity preflight — fail fast instead of burning the whole window on 401s
#    (every sampler poll, detector call and bulk would otherwise fail one by one).
PRE=$(curl -ks -o /dev/null -w '%{http_code}' -u "$USER:$PASSWORD" "$TARGET/_cluster/health" 2>/dev/null || echo 000)
if [[ "$PRE" != "200" ]]; then
    echo "[ERROR] Preflight to $TARGET failed (HTTP $PRE) as user '$USER'. Aborting before the load." >&2
    echo "        401 ⇒ wrong password; 000 ⇒ unreachable/TLS. Verify: curl -k -u $USER:<pw> $TARGET/_cluster/health" >&2
    exit 1
fi

# 1. Diagnostic: how many detectors has the content-manager created so far (from the CTI
#    catalog)? Best-effort read of the SA detectors system index; the load doesn't depend on
#    it (the monitors keep matching new events as detectors come online during the window).
DET_COUNT=$(curl -ks -u "$USER:$PASSWORD" "$TARGET/.opensearch-sap-detectors-config/_count" \
    | grep -o '"count":[0-9]*' | head -1 | cut -d: -f2)
[[ "$DET_COUNT" =~ ^[0-9]+$ ]] || DET_COUNT=0
echo "[INFO] Detectors present (content-manager / CTI catalog): $DET_COUNT"
[[ "$DET_COUNT" -eq 0 ]] && echo "[WARN] No detectors yet — the content-manager may still be syncing the CTI catalog, or it can't reach the CTI API. Findings need a detector watching $INDEX."

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

# 4. Give the detectors' monitors a moment to evaluate the last events (auto-created
#    detectors default to a ~2-minute schedule), then sanity-check.
echo "[INFO] Waiting 150s for the detector monitors to evaluate the last events ..."
sleep 150
curl -ks -u "$USER:$PASSWORD" "$TARGET/$INDEX/_refresh" >/dev/null 2>&1 || true

count() { curl -ks -u "$USER:$PASSWORD" "$TARGET/$1/_count" | grep -o '"count":[0-9]*' | head -1 | cut -d: -f2; }
EVENTS=$(count "$INDEX"); [[ "$EVENTS" =~ ^[0-9]+$ ]] || EVENTS=0
FINDINGS=$(count "$FINDINGS_INDEX"); [[ "$FINDINGS" =~ ^[0-9]+$ ]] || FINDINGS=0

echo "[INFO] Events indexed into '$INDEX': $EVENTS | Findings in '$FINDINGS_INDEX': $FINDINGS"
{ echo "events_indexed=$EVENTS"; echo "findings=$FINDINGS"; echo "detectors=$DET_COUNT"; } >> "$OUT/load-report.txt"
echo "[INFO] Report: $OUT/load-report.txt | metrics: $OUT/metrics.csv"

# Indexing nothing is a real failure (bad target / data stream). Zero findings is only a
# WARNING — the perf metrics are still valid; we keep them rather than abort the run.
if [[ "$LOAD_RC" -ne 0 || "$EVENTS" -eq 0 ]]; then
    echo "[ERROR] Load indexed no events (loader exit=$LOAD_RC, events=$EVENTS)." >&2
    echo "        Check the indexer is reachable at $TARGET and the data stream exists." >&2
    exit 1
fi
if [[ "$FINDINGS" -eq 0 ]]; then
    echo "[WARN] $EVENTS events indexed but ZERO findings generated (detectors=$DET_COUNT)." >&2
    echo "       The built-in detection pipeline produced no finding for the event. Likely causes:" >&2
    echo "         - the content-manager couldn't sync the CTI catalog (indexer needs network to the CTI API)," >&2
    echo "         - catalog_create_detectors/update_on_start are off (see config/perf-tune.yml)," >&2
    echo "         - or no synced detector matches the event. Metrics are still saved." >&2
else
    echo "[INFO] OK — $EVENTS events → $FINDINGS findings (detectors=$DET_COUNT)."
fi
