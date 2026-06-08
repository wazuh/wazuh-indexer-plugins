#!/bin/bash
#
# run.sh — entry point for a Wazuh Indexer performance test.
#
# Owns the full lifecycle: brings the Vagrant environment up, runs the scenario's
# measurement, then tears the environment down. The user only runs this script.
#
#   ./run.sh --scenario real-world                 # AIO + 2 agents (FIM/Logcollector)
#   ./run.sh --scenario isolated                   # single indexer + monitor + OSB, cold start
#   ./run.sh --scenario real-world --version 4.14  # install + measure 4.x
#   ./run.sh --scenario isolated --keep            # leave the VMs up afterwards
#
# Results land in tools/performance/runs/. Requires Vagrant + a provider (libvirt,
# VirtualBox, …). For libvirt also set the box, e.g.
#   PERF_BOX=cloud-image/ubuntu-24.04 ./run.sh --scenario real-world
#
set -euo pipefail

SCENARIO=""
VERSION=""
PASSWORD=""
KEEP=""
DESTROY=""
# Scenario-specific passthrough (defaults match the runners).
DURATION="" INTERVAL="" RATE=""   # real-world
DOCS=""                           # isolated

usage() {
    cat <<'EOF'
Usage: run.sh --scenario real-world|isolated [options]

Owns the lifecycle: vagrant up → measure → (real-world) destroy. The isolated
scenario LEAVES THE VMs UP on success so Grafana stays reachable; tear them down
with `run.sh --scenario isolated --destroy` (or just start another run). Results
land in tools/performance/runs/<scenario>-<version>/; run ./analyze.sh afterwards.

Global options:
  --scenario real-world|isolated   topology to run (required)
  --version MAJOR.MINOR            Wazuh line to install (e.g. 5.0, 4.14); latest patch of the line
  --password P                     admin password (auto-detected from the VM if omitted)
  --keep                           leave the VMs up afterwards (real-world; isolated already keeps)
  --destroy                        tear down the scenario's VMs and exit (no run)
  -h, --help                       show this help

real-world options:   --duration S   --interval S   --rate N
isolated options:     --docs N

Provider/box overrides via env, e.g. PERF_BOX, PERF_INDEXER_MEM, PERF_BOOT_TIMEOUT.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --scenario) SCENARIO="$2"; shift 2 ;;
        --version)  VERSION="$2"; shift 2 ;;
        --password) PASSWORD="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        --rate)     RATE="$2"; shift 2 ;;
        --docs)     DOCS="$2"; shift 2 ;;
        --keep)     KEEP=1; shift ;;
        --destroy)  DESTROY=1; shift ;;
        -h|--help)  usage; exit 0 ;;
        *) echo "[ERROR] Unknown argument: $1" >&2; usage >&2; exit 1 ;;
    esac
done

case "$SCENARIO" in
    real-world|isolated) ;;
    *) echo "[ERROR] --scenario must be 'real-world' or 'isolated'." >&2; exit 1 ;;
esac

HERE="$(cd "$(dirname "$0")" && pwd)"
VAGRANT_DIR="$HERE/vagrant"

# Provision: the Vagrantfile reads PERF_SCENARIO; PERF_VERSION (if given) picks the
# install version. Run all vagrant commands from the Vagrantfile's directory.
export PERF_SCENARIO="$SCENARIO"
[[ -n "$VERSION" ]] && export PERF_VERSION="$VERSION"

cd "$VAGRANT_DIR"

# Destroy-only: tear down the scenario's VMs and exit (e.g. clean up an isolated run
# whose VMs were left up for Grafana).
if [[ -n "$DESTROY" ]]; then
    echo "[INFO] Destroying the '$SCENARIO' environment ..."
    PERF_SCENARIO="$SCENARIO" vagrant destroy -f
    exit 0
fi

# Start clean. `vagrant up` won't re-provision an already-created VM, and the Vagrantfile
# defines a DIFFERENT machine set per scenario (indexer/monitor vs aio/agents). So a
# leftover environment from a prior run — even the OTHER scenario — would linger and get
# silently reused (stale install/version/config). Tear down both scenarios' VMs first,
# each under its own PERF_SCENARIO: a bare `vagrant destroy` only sees the default
# scenario's machines, so it would miss the others.
for sc in real-world isolated; do
    created=$(PERF_SCENARIO="$sc" vagrant status --machine-readable 2>/dev/null \
        | awk -F, '$3=="state" && $4!="not_created"{n++} END{print n+0}' || true)
    if [[ "$created" -gt 0 ]]; then
        echo "[INFO] Destroying $created leftover '$sc' VM(s) from a previous run ..."
        PERF_SCENARIO="$sc" vagrant destroy -f
    fi
done

echo "[INFO] Bringing up the '$SCENARIO' environment ..."
if ! vagrant up; then
    echo "[ERROR] 'vagrant up' failed. A boot timeout usually means the host is over-committed:" >&2
    echo "        the two VMs need ~18 GB RAM (indexer 16 + monitor/agents). Options:" >&2
    echo "          - free RAM, or lower it: PERF_INDEXER_MEM=8192 ./run.sh --scenario $SCENARIO ..." >&2
    echo "          - allow a longer boot:   PERF_BOOT_TIMEOUT=1200 ./run.sh --scenario $SCENARIO ..." >&2
    echo "          - clear leftovers:       vagrant global-status --prune ; VBoxManage list runningvms" >&2
    echo "        The VMs are left as-is; re-running this script destroys them first." >&2
    exit 1
fi

# Build the scenario-specific measurement args.
RUN_ARGS=()
[[ -n "$VERSION" ]] && RUN_ARGS+=(--version "$VERSION")
[[ -n "$PASSWORD" ]] && RUN_ARGS+=(--password "$PASSWORD")
if [[ "$SCENARIO" == "real-world" ]]; then
    [[ -n "$DURATION" ]] && RUN_ARGS+=(--duration "$DURATION")
    [[ -n "$INTERVAL" ]] && RUN_ARGS+=(--interval "$INTERVAL")
    [[ -n "$RATE" ]] && RUN_ARGS+=(--rate "$RATE")
else
    [[ -n "$DOCS" ]] && RUN_ARGS+=(--docs "$DOCS")
fi

# Measure. Capture success so we only tear down a clean run.
RUN_OK=1
echo "[INFO] Running the '$SCENARIO' measurement ..."
if ! "./run-${SCENARIO}.sh" ${RUN_ARGS[@]+"${RUN_ARGS[@]}"}; then
    RUN_OK=0
    echo "[ERROR] Measurement failed." >&2
fi

# Teardown policy:
#   - run failed       → leave up for debugging (regardless of scenario)
#   - --keep           → leave up
#   - isolated + ok    → leave up so Grafana/Prometheus stay reachable (they live on
#                        the monitor VM; destroying it discards the cold-start timeline)
#   - real-world + ok  → tear down (no persistent monitoring to preserve)
DESTROY_CMD="(cd $VAGRANT_DIR && PERF_SCENARIO=$SCENARIO vagrant destroy -f)   # or: $HERE/run.sh --scenario $SCENARIO --destroy"
if [[ "$RUN_OK" -ne 1 ]]; then
    echo "[WARN] Run failed — leaving the VMs up for debugging. Destroy with: $DESTROY_CMD"
elif [[ -n "$KEEP" ]]; then
    echo "[INFO] --keep set; leaving the VMs up. Destroy later with: $DESTROY_CMD"
elif [[ "$SCENARIO" == "isolated" ]]; then
    echo "[INFO] Leaving the VMs up so Grafana stays reachable:"
    echo "         http://${PERF_MONITOR_IP:-192.168.60.30}:3000/d/wazuh-host-overview"
    echo "[INFO] Destroy when done: $DESTROY_CMD"
else
    echo "[INFO] Tearing down the environment ..."
    vagrant destroy -f
fi

[[ "$RUN_OK" -eq 1 ]] || exit 1
echo "[INFO] Done. Results in tools/performance/runs/."
