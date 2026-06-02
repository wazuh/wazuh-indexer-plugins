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
set -e

INDEXER_IP="${PERF_AIO_IP:-192.168.60.20}"
DOCS=1000000
PASSWORD=""
VERSION=""   # explicit override; otherwise auto-detected from the indexer VM

while [[ $# -gt 0 ]]; do
    case "$1" in
        --docs)        DOCS="$2"; shift 2 ;;
        --password)    PASSWORD="$2"; shift 2 ;;
        --version)     VERSION="$2"; shift 2 ;;
        --indexer-ip)  INDEXER_IP="$2"; shift 2 ;;
        *) echo "Usage: $0 [--docs N] [--password P] [--version X.Y.Z] [--indexer-ip IP]"; exit 1 ;;
    esac
done

cd "$(dirname "$0")"

# Push the latest scripts into the VMs (vagrant-libvirt only syncs at up/provision).
echo "[INFO] Syncing latest scripts to the VMs ..."
vagrant rsync >/dev/null 2>&1 || true

# Admin password — read from the indexer guest over SSH, else --password.
if [[ -z "$PASSWORD" ]]; then
    PASSWORD="$(vagrant ssh indexer -c 'sudo cat /opt/perf/runs/admin-password.txt 2>/dev/null' 2>/dev/null | tr -d '\r\n')"
fi
if [[ -z "$PASSWORD" ]]; then
    echo "[ERROR] No indexer password found on the indexer VM. Pass --password '<admin pass>'." >&2
    exit 1
fi

# Resolve the Wazuh version for the label from the installed package, unless --version.
if [[ -z "$VERSION" ]]; then
    RAW="$(vagrant ssh indexer -c "dpkg-query -W -f='\${Version}' wazuh-indexer 2>/dev/null || rpm -q --qf '%{VERSION}-%{RELEASE}' wazuh-indexer 2>/dev/null" 2>/dev/null | tr -d '\r\n')"
    VERSION="${RAW##*:}"
    VERSION="${VERSION%%-*}"
fi
if [[ -z "$VERSION" ]]; then
    echo "[ERROR] Could not determine the wazuh-indexer version from the indexer VM. Pass --version X.Y.Z." >&2
    exit 1
fi
LABEL="wazuh-$VERSION"
echo "[INFO] Run label: $LABEL"

# 1. Cold start: restart the indexer; Prometheus/node_exporter are already recording.
RESTART_TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "[INFO] Cold-start marker: $RESTART_TS — restarting wazuh-indexer ..."
vagrant ssh indexer -c "sudo systemctl restart wazuh-indexer"

# 2. Wait for the node to come back green (cold start captured in Prometheus).
echo "[INFO] Waiting for the indexer to go green ..."
vagrant ssh indexer -c "
    for i in \$(seq 1 60); do
        curl -ks -u admin:'$PASSWORD' https://localhost:9200/_cluster/health 2>/dev/null \
            | grep -q '\"status\":\"green\"\|\"status\":\"yellow\"' && exit 0
        sleep 5
    done
    echo '[WARN] indexer did not report green/yellow within 5 min' >&2
"

# 2b. Ensure the OSB corpus exists. gen-corpora.py needs the repo (WCS generator +
#     events template), which is only present on the HOST — generate here, then
#     rsync it into the monitor VM (the synced folder is host→guest).
if [[ ! -f ../benchmark/workloads/wazuh-events/documents.json ]]; then
    echo "[INFO] Generating OSB corpus on the host ($DOCS docs) ..."
    python3 ../benchmark/gen-corpora.py --docs "$DOCS"
fi
echo "[INFO] Syncing corpus to the monitor VM ..."
vagrant rsync monitor >/dev/null 2>&1 || true

# 3. Run the OSB synthetic workload FROM the monitor VM (off the indexer host).
OUT_GUEST="/root/perf-run"
echo "[INFO] Running OpenSearch Benchmark from the monitor VM against $INDEXER_IP ..."
vagrant ssh monitor -c \
    "sudo /opt/perf/benchmark/run-osb.sh \
        --target https://$INDEXER_IP:9200 --user admin --password '$PASSWORD' \
        --docs $DOCS --no-host --out $OUT_GUEST"

# 4. Pull results (OSB report + indexer-internal CSV) from the monitor VM.
LOCAL_OUT="../runs/isolated"
echo "[INFO] Fetching results from the monitor VM ..."
mkdir -p "$LOCAL_OUT"
vagrant ssh monitor -c "sudo tar -czf - -C $OUT_GUEST . | base64 -w0" 2>/dev/null \
    | tr -dc 'A-Za-z0-9+/=' | base64 -d | tar -xzf - -C "$LOCAL_OUT"

# Record the run's real version/label so compare.py / plot.py / report.py can use it.
cat > "$LOCAL_OUT/run-metadata.json" <<EOF
{
  "scenario": "isolated",
  "label": "$LABEL",
  "version": "$VERSION",
  "cold_start": "$RESTART_TS"
}
EOF

MON_IP=$(vagrant ssh monitor -c "hostname -I | awk '{print \$1}'" 2>/dev/null | tr -d '\r\n')
echo
echo "[INFO] Done ($LABEL). OSB report + metrics.csv: tools/performance/runs/isolated/"
echo "[INFO] Cold start at $RESTART_TS — view the full host timeline in Grafana: http://${MON_IP}:3000"
