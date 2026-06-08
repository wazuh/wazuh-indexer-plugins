#!/bin/bash
#
# run-isolated.sh — measurement helper for the `isolated` scenario: cold-start +
# synthetic load under continuous monitoring.
#
# Normally invoked by tools/performance/run.sh (which owns vagrant up/destroy).
# Assumes `PERF_SCENARIO=isolated vagrant up` provisioned: an `indexer` VM
# (single-node wazuh-indexer + node_exporter from boot) and a `monitor` VM
# (Prometheus + Grafana scraping the indexer, plus OpenSearch Benchmark).
#
# It:
#   1. restarts wazuh-indexer to capture its COLD START (Prometheus is already
#      scraping node_exporter, so startup CPU/RAM/disk land in the timeseries),
#   2. waits for the indexer to go green,
#   3. runs the OSB synthetic workload FROM the monitor VM (off the indexer host),
#   4. pulls the OSB report + indexer-internal CSV back over SSH.
#
# Everything is over `vagrant ssh` — no reliance on guest→host synced folders.
#
# Run from tools/performance/vagrant/.
#
set -euo pipefail

INDEXER_IP="${PERF_AIO_IP:-192.168.60.20}"
DOCS=1000000
DURATION=""   # sampler window (s); empty → run-osb.sh default
INTERVAL=""   # sampler cadence (s); empty → run-osb.sh default
PASSWORD=""
VERSION=""   # fallback only; the label uses the detected INSTALLED version

while [[ $# -gt 0 ]]; do
    case "$1" in
        --docs)        DOCS="$2"; shift 2 ;;
        --duration)    DURATION="$2"; shift 2 ;;
        --interval)    INTERVAL="$2"; shift 2 ;;
        --password)    PASSWORD="$2"; shift 2 ;;
        --version)     VERSION="$2"; shift 2 ;;
        --indexer-ip)  INDEXER_IP="$2"; shift 2 ;;
        *) echo "Usage: $0 [--docs N] [--duration S] [--interval S] [--password P] [--version X.Y.Z] [--indexer-ip IP]"; exit 1 ;;
    esac
done

cd "$(dirname "$0")"
# shellcheck source=lib.sh
source ./lib.sh

perf_rsync
perf_resolve_password indexer   # sets PASSWORD
perf_detect_version indexer     # sets VERSION + LABEL

# Fail fast on a missing HOST dependency. gen-corpora.py (step 2b) runs on the host —
# it needs the wcs/ generator, which isn't in the VMs — and that generator imports
# `requests`. Check now, before the multi-minute cold-start/green wait, so a missing
# dep surfaces as a clear message instead of a deep traceback minutes later.
if [[ ! -f ../benchmark/workloads/wazuh-events/documents.json ]] && ! python3 -c 'import requests' 2>/dev/null; then
    echo "[ERROR] The host is missing the Python 'requests' module, needed to build the OSB" >&2
    echo "        corpus (gen-corpora.py runs on the host via the WCS event generator). Install it:" >&2
    echo "          pip install requests        # or: sudo apt-get install -y python3-requests" >&2
    exit 1
fi

# 1. Cold start: restart the indexer; Prometheus/node_exporter are already recording.
RESTART_TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "[INFO] Cold-start marker: $RESTART_TS — restarting wazuh-indexer ..."
if ! vagrant ssh indexer -c "sudo systemctl restart wazuh-indexer"; then
    echo "[ERROR] Could not restart wazuh-indexer on the indexer VM. Service state:" >&2
    vagrant ssh indexer -c "sudo systemctl status wazuh-indexer --no-pager -l | head -n 25; \
        echo '--- last 40 journal lines ---'; \
        sudo journalctl -u wazuh-indexer --no-pager -n 40" >&2 || true
    echo "[HINT] If the unit is missing, the indexer was not installed: the VM was likely" >&2
    echo "       'already provisioned' from a prior run. Destroy and re-run so --version takes effect:" >&2
    echo "         (cd \"\$(dirname \"\$0\")\" && vagrant destroy -f) && ./run.sh --scenario isolated --version <X.Y>" >&2
    exit 1
fi

# 2. Wait for the node to come back green (cold start captured in Prometheus).
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

# 2b. Ensure the OSB corpus exists. gen-corpora.py needs the repo (WCS generator +
#     events template), which is only present on the HOST — generate here, then
#     rsync it into the monitor VM (the synced folder is host→guest).
if [[ ! -f ../benchmark/workloads/wazuh-events/documents.json ]]; then
    echo "[INFO] Generating OSB corpus on the host ($DOCS docs) ..."
    python3 ../benchmark/gen-corpora.py --docs "$DOCS"
fi
perf_rsync monitor   # sync the freshly built corpus into the monitor VM

# 3. Run the OSB synthetic workload FROM the monitor VM (off the indexer host).
OUT_GUEST="/root/perf-run"
echo "[INFO] Running OpenSearch Benchmark from the monitor VM against $INDEXER_IP ..."
# --node-exporter pulls the indexer's host metrics (CPU/RAM/disk) into the CSV from
# node_exporter (the monitor already reaches it on :9100), since the sampler runs
# off the indexer host here and can't read them via local psutil.
vagrant ssh monitor -c \
    "sudo /opt/perf/benchmark/run-osb.sh \
        --target https://$INDEXER_IP:9200 --user admin --password '$PASSWORD' \
        --docs $DOCS ${DURATION:+--duration $DURATION} ${INTERVAL:+--interval $INTERVAL} \
        --no-host --node-exporter $INDEXER_IP:9100 --out $OUT_GUEST"

# 4. Pull results (OSB report + indexer-internal CSV) from the monitor VM.
# Per-version output dir so runs don't overwrite each other (compare across versions).
LOCAL_OUT="../runs/isolated-$VERSION"
echo "[INFO] Fetching results from the monitor VM ..."
perf_pull_results monitor "$OUT_GUEST" "$LOCAL_OUT"

# Record the run's real version/label so compare.py / plot.py / report.py can use it.
cat > "$LOCAL_OUT/run-metadata.json" <<EOF
{
  "scenario": "isolated",
  "label": "$LABEL",
  "version": "$VERSION",
  "cold_start": "$RESTART_TS"
}
EOF

# Grafana is reached over the monitor VM's PRIVATE-network IP (the host-routable one,
# same value the Vagrantfile assigns). `hostname -I` on the guest would return the
# VirtualBox NAT IP (10.0.2.15) first, which the host can't reach.
MON_IP="${PERF_MONITOR_IP:-192.168.60.30}"
DASH_URL="http://${MON_IP}:3000/d/wazuh-host-overview"
echo
echo "[INFO] Done ($LABEL). OSB report + metrics.csv: tools/performance/runs/isolated-$VERSION/"
echo "[INFO] Cold start at $RESTART_TS — view the host timeline in Grafana: $DASH_URL"
# Best-effort: open the dashboard in the host's browser (no-op if unavailable).
(command -v open >/dev/null 2>&1 && open "$DASH_URL") \
    || (command -v xdg-open >/dev/null 2>&1 && xdg-open "$DASH_URL" >/dev/null 2>&1) \
    || true
