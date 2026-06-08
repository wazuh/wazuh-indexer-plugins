#!/bin/bash
#
# run-real-world.sh — measurement helper for the `real-world` scenario.
#
# Normally invoked by tools/performance/run.sh (which owns vagrant up/destroy).
# Assumes the VMs (aio + agents) are already up. It:
#   1. starts the FIM + Logcollector load loops on every agent VM (background),
#   2. runs the per-minute measurement window on the AIO VM,
#   3. pulls the results back to tools/performance/runs/ over SSH.
#
# Everything is done over `vagrant ssh` — the synced folder is NOT relied on for
# guest→host transfer (vagrant-libvirt syncs host→guest only).
#
# Run from tools/performance/vagrant/.
#
set -euo pipefail

DURATION=3600
INTERVAL=60
RATE=10
PASSWORD=""
VERSION=""   # fallback only; the label uses the detected INSTALLED version

while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration) DURATION="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        --rate)     RATE="$2"; shift 2 ;;
        --password) PASSWORD="$2"; shift 2 ;;
        --version)  VERSION="$2"; shift 2 ;;
        *) echo "Usage: $0 [--duration S] [--interval S] [--rate N] [--password P] [--version X.Y.Z]"; exit 1 ;;
    esac
done

cd "$(dirname "$0")"
# shellcheck source=lib.sh
source ./lib.sh

perf_rsync
perf_resolve_password aio   # sets PASSWORD
perf_detect_version aio     # sets VERSION + LABEL

# Discover agent VM names from the Vagrant status (everything except 'aio').
AGENTS=$(vagrant status --machine-readable | awk -F, '$3=="state" && $2!="aio" && $2!="" {print $2}' || true)
echo "[INFO] Agents: $AGENTS"

# Guest-local output dir (NOT under the synced mount; pulled back over SSH below).
OUT_GUEST="/root/perf-run"
# Per-version output dir so runs don't overwrite each other (compare across versions).
LOCAL_OUT="../runs/real-world-$VERSION"

echo "[INFO] Starting load loops (rate=${RATE}/s, duration=${DURATION}s) ..."
PIDS=()
for a in $AGENTS; do
    vagrant ssh "$a" -c \
        "sudo /opt/perf/scripts/agent-load.sh --rate $RATE --duration $DURATION" &
    PIDS+=($!)
done

echo "[INFO] Running measurement window on aio ..."
vagrant ssh aio -c \
    "sudo /opt/perf/scripts/run-scenario.sh \
        --endpoint https://localhost:9200 --user admin --password '$PASSWORD' \
        --duration $DURATION --interval $INTERVAL --insecure --out $OUT_GUEST \
        --label '$LABEL'"

# Wait for the agent load loops to finish.
for pid in ${PIDS[@]+"${PIDS[@]}"}; do wait "$pid" 2>/dev/null || true; done

# Pull results from the guest over SSH (CR/PTY-safe; see lib.sh).
echo "[INFO] Fetching results from the AIO VM ..."
perf_pull_results aio "$OUT_GUEST" "$LOCAL_OUT"

# Generate the report on the host — authoritative, independent of the VM's synced state.
python3 ../analyze/report.py --run "$LOCAL_OUT" --label "$LABEL" || \
    echo "[WARN] Host-side report generation failed; metrics.csv is available."

echo "[INFO] Done. Results: tools/performance/runs/real-world-$VERSION/ (metrics.csv, metrics.ndjson, run-metadata.json, report.md)"
