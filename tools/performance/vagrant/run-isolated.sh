#!/bin/bash
#
# run-isolated.sh — measurement helper for the `isolated` scenario: cold-start +
# steady-rate findings load under continuous monitoring.
#
# Normally invoked by tools/performance/run.sh (which owns vagrant up/destroy).
# Assumes `PERF_SCENARIO=isolated vagrant up` provisioned: an `indexer` VM
# (single-node wazuh-indexer + node_exporter + JMX exporter from boot) and a `monitor`
# VM (Prometheus + Grafana scraping the indexer).
#
# It:
#   1. restarts wazuh-indexer to capture its COLD START (Prometheus is already scraping
#      node_exporter + the JMX exporter, so startup CPU/RAM/disk/JVM land in the series),
#   2. waits for the indexer to go green,
#   3. from the monitor VM: pre-creates the detector, then indexes the fixed
#      system-activity event into wazuh-events-v5-system-activity at --rate events/sec for
#      --duration seconds (generating findings), sampling the indexer in parallel,
#   4. pulls the load + metrics back over SSH and generates report.md + timeline.png.
#
# Everything is over `vagrant ssh` — no reliance on guest→host synced folders.
#
# Run from tools/performance/vagrant/.
#
set -euo pipefail

INDEXER_IP="${PERF_AIO_IP:-192.168.60.20}"
RATE=1000     # events/sec indexed into the data stream
DURATION=""   # load + sampler window (s); empty → run-load.sh default
INTERVAL=""   # sampler cadence (s); empty → run-load.sh default
PASSWORD=""
VERSION=""   # fallback only; the label uses the detected INSTALLED version

while [[ $# -gt 0 ]]; do
    case "$1" in
        --rate)        RATE="$2"; shift 2 ;;
        --duration)    DURATION="$2"; shift 2 ;;
        --interval)    INTERVAL="$2"; shift 2 ;;
        --password)    PASSWORD="$2"; shift 2 ;;
        --version)     VERSION="$2"; shift 2 ;;
        --indexer-ip)  INDEXER_IP="$2"; shift 2 ;;
        *) echo "Usage: $0 [--rate N] [--duration S] [--interval S] [--password P] [--version X.Y.Z] [--indexer-ip IP]"; exit 1 ;;
    esac
done

cd "$(dirname "$0")"
# shellcheck source=lib.sh
source ./lib.sh

perf_rsync
perf_resolve_password indexer   # sets PASSWORD
perf_detect_version indexer     # sets VERSION + LABEL

# 1. Cold start: restart the indexer; Prometheus/node_exporter/JMX exporter are already recording.
RESTART_TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "[INFO] Cold-start marker: $RESTART_TS — restarting wazuh-indexer ..."
if ! vagrant ssh indexer -c "sudo systemctl restart wazuh-indexer"; then
    echo "[ERROR] Could not restart wazuh-indexer on the indexer VM. Service state:" >&2
    vagrant ssh indexer -c "sudo systemctl status wazuh-indexer --no-pager -l | head -n 25; \
        echo '--- last 40 journal lines ---'; \
        sudo journalctl -u wazuh-indexer --no-pager -n 40" >&2 || true
    echo "[HINT] If the unit is missing, the indexer was not installed: the VM was likely" >&2
    echo "       'already provisioned' from a prior run. Destroy and re-run so --version takes effect:" >&2
    echo "         (cd \"\$(dirname \"\$0\")\" && vagrant destroy -f) && ./run.sh --version <X.Y>" >&2
    exit 1
fi

# 2. Wait for the node to come back green (cold start captured in Prometheus). The setup
#    plugin also needs to create the wazuh-events-v5-* / wazuh-findings-v5-* templates and
#    data streams on this first green — the detector setup (step 3) depends on them.
echo "[INFO] Waiting for the indexer to go green ..."
vagrant ssh indexer -c "
    for i in \$(seq 1 60); do
        curl -ks -u admin:'$PASSWORD' https://localhost:9200/_cluster/health 2>/dev/null \
            | grep -q '\"status\":\"green\"\|\"status\":\"yellow\"' && exit 0
        sleep 5
    done
    echo '[WARN] indexer not green/yellow within 5 min — last health check (HTTP 401 ⇒ wrong password):' >&2
    curl -ks -o /dev/null -w '  HTTP %{http_code}\n' -u admin:'$PASSWORD' https://localhost:9200/_cluster/health >&2 || true
"

# 3. Pre-create the detector + drive the findings load FROM the monitor VM (off the indexer
#    host). --node-exporter pulls the indexer's host metrics (CPU/RAM/disk) into the CSV from
#    node_exporter (the sampler runs off the indexer host here and can't read them via psutil).
OUT_GUEST="/root/perf-run"
echo "[INFO] Running the findings load from the monitor VM against $INDEXER_IP (rate=${RATE}/s) ..."
vagrant ssh monitor -c \
    "sudo /opt/perf/benchmark/run-load.sh \
        --target https://$INDEXER_IP:9200 --user admin --password '$PASSWORD' \
        --rate $RATE ${DURATION:+--duration $DURATION} ${INTERVAL:+--interval $INTERVAL} \
        --no-host --node-exporter $INDEXER_IP:9100 --out $OUT_GUEST"

# 4. Pull results (load report + indexer-internal CSV) from the monitor VM.
# Per-version output dir so runs don't overwrite each other (compare across versions).
LOCAL_OUT="../runs/isolated-$VERSION"
echo "[INFO] Fetching results from the monitor VM ..."
perf_pull_results monitor "$OUT_GUEST" "$LOCAL_OUT"

# Pull the events/findings counts the loader recorded into load-report.txt for the metadata.
EVENTS=$(grep -o 'events_indexed=[0-9]*' "$LOCAL_OUT/load-report.txt" 2>/dev/null | head -1 | cut -d= -f2 || true)
FINDINGS=$(grep -o 'findings=[0-9]*' "$LOCAL_OUT/load-report.txt" 2>/dev/null | head -1 | cut -d= -f2 || true)

# Record the run's real version/label so compare.py / plot.py / report.py can use it.
cat > "$LOCAL_OUT/run-metadata.json" <<EOF
{
  "scenario": "isolated",
  "label": "$LABEL",
  "version": "$VERSION",
  "cold_start": "$RESTART_TS",
  "rate": $RATE,
  "events_indexed": ${EVENTS:-0},
  "findings": ${FINDINGS:-0}
}
EOF

# Generate the deliverables on the host: aggregated report.md + a single-run timeline.png
# (so the user just runs ./run.sh and reads the CSV + PNG). Both are best-effort.
python3 ../analyze/report.py --run "$LOCAL_OUT" --label "$LABEL" \
    || echo "[WARN] Host-side report generation failed; metrics.csv is available."
python3 ../analyze/plot.py "$LABEL=$LOCAL_OUT/metrics.csv" --out "$LOCAL_OUT/timeline.png" \
    || echo "[WARN] Host-side timeline plot failed (matplotlib installed?); metrics.csv is available."

# Grafana is reached over the monitor VM's PRIVATE-network IP (the host-routable one,
# same value the Vagrantfile assigns). `hostname -I` on the guest would return the
# VirtualBox NAT IP (10.0.2.15) first, which the host can't reach.
MON_IP="${PERF_MONITOR_IP:-192.168.60.30}"
echo
echo "[INFO] Done ($LABEL). Results: tools/performance/runs/isolated-$VERSION/"
echo "       metrics.csv, report.md, timeline.png — events: ${EVENTS:-?}, findings: ${FINDINGS:-?}"
echo "[INFO] Cold start at $RESTART_TS — view the timelines in Grafana:"
echo "         http://${MON_IP}:3000/d/wazuh-host-overview   (host CPU/RAM/disk)"
echo "         http://${MON_IP}:3000/d/wazuh-jvm-overview    (JVM heap/GC/threads via JMX)"
# Best-effort: open the host dashboard in the host's browser (no-op if unavailable).
DASH_URL="http://${MON_IP}:3000/d/wazuh-host-overview"
(command -v open >/dev/null 2>&1 && open "$DASH_URL") \
    || (command -v xdg-open >/dev/null 2>&1 && xdg-open "$DASH_URL" >/dev/null 2>&1) \
    || true
