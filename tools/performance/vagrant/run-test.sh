#!/bin/bash
#
# run-test.sh — drive a full performance run on the Vagrant environment.
#
# Assumes `vagrant up` has provisioned the env (aio + agents). It:
#   1. starts the FIM + Logcollector load loops on every agent VM (background),
#   2. runs the per-minute measurement window on the AIO VM,
#   3. leaves results in tools/performance/runs/ (shared via the synced folder).
#
# Run from tools/performance/vagrant/.
#
set -e

DURATION=3600
INTERVAL=60
RATE=10
PASSWORD=""
# Version tag for the report; defaults from the version the env was provisioned with.
LABEL="wazuh-${PERF_VERSION:-5.0.0}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration) DURATION="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        --rate)     RATE="$2"; shift 2 ;;
        --password) PASSWORD="$2"; shift 2 ;;
        --label)    LABEL="$2"; shift 2 ;;
        *) echo "Usage: $0 [--duration S] [--interval S] [--rate N] [--password P] [--label TAG]"; exit 1 ;;
    esac
done

cd "$(dirname "$0")"

# Resolve the indexer admin password: explicit flag, else the file captured by
# setup-aio.sh during provisioning. Read it FROM the AIO guest over SSH (works
# regardless of synced-folder direction — libvirt often syncs host→guest only),
# falling back to the host-side synced copy.
if [[ -z "$PASSWORD" ]]; then
    PASSWORD="$(vagrant ssh aio -c 'sudo cat /opt/perf/runs/admin-password.txt 2>/dev/null' 2>/dev/null | tr -d '\r\n')"
fi
if [[ -z "$PASSWORD" && -f ../runs/admin-password.txt ]]; then
    PASSWORD="$(cat ../runs/admin-password.txt)"
fi
if [[ -z "$PASSWORD" ]]; then
    echo "[ERROR] No indexer password found in the AIO VM (/opt/perf/runs/admin-password.txt)." >&2
    echo "        Provisioning's best-effort password capture likely failed. Retrieve it with:" >&2
    echo "          vagrant ssh aio -c 'TAR=\$(sudo find / -name wazuh-install-files.tar 2>/dev/null | head -1); sudo tar -xOf \"\$TAR\" wazuh-install-files/wazuh-passwords.txt | grep -A2 -i admin'" >&2
    echo "        then re-run with --password '<indexer admin password>'." >&2
    exit 1
fi

# Discover agent VM names from the Vagrant status (everything except 'aio').
AGENTS=$(vagrant status --machine-readable | awk -F, '$3=="state" && $2!="aio" && $2!="" {print $2}')
echo "[INFO] Agents: $AGENTS"

OUT="/opt/perf/runs/aio-run"

echo "[INFO] Starting load loops (rate=${RATE}/s, duration=${DURATION}s) ..."
PIDS=()
for a in $AGENTS; do
    vagrant ssh "$a" -c \
        "sudo /opt/perf/scenario/agent-load.sh --rate $RATE --duration $DURATION" &
    PIDS+=($!)
done

echo "[INFO] Running measurement window on aio ..."
vagrant ssh aio -c \
    "sudo /opt/perf/scenario/run-scenario.sh \
        --endpoint https://localhost:9200 --user admin --password '$PASSWORD' \
        --duration $DURATION --interval $INTERVAL --insecure --out $OUT \
        ${LABEL:+--label '$LABEL'}"

# Wait for the agent load loops to finish.
for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done

echo "[INFO] Done. Results: tools/performance/runs/aio-run/ (metrics.csv, metrics.ndjson, run-metadata.json)"
