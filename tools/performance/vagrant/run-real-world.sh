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
set -e

DURATION=3600
INTERVAL=60
RATE=10
PASSWORD=""
VERSION=""   # explicit override; otherwise auto-detected from the aio VM

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

# Push the latest scripts into the VMs. vagrant-libvirt only syncs host→guest at
# up/provision, so without this the VMs can run stale scripts.
echo "[INFO] Syncing latest scripts to the VMs ..."
vagrant rsync >/dev/null 2>&1 || true

# Resolve the indexer admin password: explicit flag, else the file captured during
# provisioning, read FROM the AIO guest over SSH (libvirt often syncs host→guest only).
if [[ -z "$PASSWORD" ]]; then
    PASSWORD="$(vagrant ssh aio -c 'sudo cat /opt/perf/runs/admin-password.txt 2>/dev/null' 2>/dev/null | tr -d '\r\n')"
fi
if [[ -z "$PASSWORD" && -f ../runs/admin-password.txt ]]; then
    PASSWORD="$(cat ../runs/admin-password.txt)"
fi
if [[ -z "$PASSWORD" ]]; then
    echo "[ERROR] No indexer password found in the AIO VM (/opt/perf/runs/admin-password.txt)." >&2
    echo "        Retrieve it with:" >&2
    echo "          vagrant ssh aio -c 'TAR=\$(sudo find / -name wazuh-install-files.tar 2>/dev/null | head -1); sudo tar -xOf \"\$TAR\" wazuh-install-files/wazuh-passwords.txt | grep -A2 -i admin'" >&2
    echo "        then re-run with --password '<indexer admin password>'." >&2
    exit 1
fi

# Resolve the Wazuh version for the label from the installed package (ground truth),
# unless --version was given. No assumed default.
if [[ -z "$VERSION" ]]; then
    RAW="$(vagrant ssh aio -c "dpkg-query -W -f='\${Version}' wazuh-indexer 2>/dev/null || rpm -q --qf '%{VERSION}-%{RELEASE}' wazuh-indexer 2>/dev/null" 2>/dev/null | tr -d '\r\n')"
    VERSION="${RAW##*:}"   # strip any epoch
    VERSION="${VERSION%%-*}"  # strip Debian/RPM revision → upstream version
fi
if [[ -z "$VERSION" ]]; then
    echo "[ERROR] Could not determine the wazuh-indexer version from the aio VM. Pass --version X.Y.Z." >&2
    exit 1
fi
LABEL="wazuh-$VERSION"
echo "[INFO] Run label: $LABEL"

# Discover agent VM names from the Vagrant status (everything except 'aio').
AGENTS=$(vagrant status --machine-readable | awk -F, '$3=="state" && $2!="aio" && $2!="" {print $2}')
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
for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done

# Pull results from the guest over SSH. base64 -w0 (no wrapping) + stripping any
# non-base64 chars on the host defends against CR/PTY mangling by `vagrant ssh`.
echo "[INFO] Fetching results from the AIO VM ..."
mkdir -p "$LOCAL_OUT"
vagrant ssh aio -c "sudo tar -czf - -C $OUT_GUEST . | base64 -w0" 2>/dev/null \
    | tr -dc 'A-Za-z0-9+/=' | base64 -d | tar -xzf - -C "$LOCAL_OUT"

# Generate the report on the host — authoritative, independent of the VM's synced state.
python3 ../analyze/report.py --run "$LOCAL_OUT" --label "$LABEL" || \
    echo "[WARN] Host-side report generation failed; metrics.csv is available."

echo "[INFO] Done. Results: tools/performance/runs/real-world-$VERSION/ (metrics.csv, metrics.ndjson, run-metadata.json, report.md)"
