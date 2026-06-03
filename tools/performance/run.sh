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
set -e

SCENARIO=""
VERSION=""
PASSWORD=""
KEEP=""
# Scenario-specific passthrough (defaults match the runners).
DURATION="" INTERVAL="" RATE=""   # real-world
DOCS=""                           # isolated

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
        *) echo "Usage: $0 --scenario real-world|isolated [--version X.Y.Z] [--password P] [--keep]"
           echo "                 [--duration S --interval S --rate N]   (real-world)"
           echo "                 [--docs N]                              (isolated)"; exit 1 ;;
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

# Start clean. `vagrant up` won't re-provision an already-created VM, and the Vagrantfile
# defines a DIFFERENT machine set per scenario (indexer/monitor vs aio/agents). So a
# leftover environment from a prior run — even the OTHER scenario — would linger and get
# silently reused (stale install/version/config). Tear down both scenarios' VMs first,
# each under its own PERF_SCENARIO: a bare `vagrant destroy` only sees the default
# scenario's machines, so it would miss the others.
for sc in real-world isolated; do
    created=$(PERF_SCENARIO="$sc" vagrant status --machine-readable 2>/dev/null \
        | awk -F, '$3=="state" && $4!="not_created"{n++} END{print n+0}')
    if [[ "$created" -gt 0 ]]; then
        echo "[INFO] Destroying $created leftover '$sc' VM(s) from a previous run ..."
        PERF_SCENARIO="$sc" vagrant destroy -f
    fi
done

echo "[INFO] Bringing up the '$SCENARIO' environment ..."
vagrant up

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
if ! "./run-${SCENARIO}.sh" "${RUN_ARGS[@]}"; then
    RUN_OK=0
    echo "[ERROR] Measurement failed." >&2
fi

# Teardown — unless --keep, and kept (for debugging) if the run failed.
if [[ -n "$KEEP" ]]; then
    echo "[INFO] --keep set; leaving the VMs up. Destroy later with: (cd $VAGRANT_DIR && PERF_SCENARIO=$SCENARIO vagrant destroy -f)"
elif [[ "$RUN_OK" -eq 1 ]]; then
    echo "[INFO] Tearing down the environment ..."
    vagrant destroy -f
else
    echo "[WARN] Run failed — leaving the VMs up for debugging. Destroy with: (cd $VAGRANT_DIR && PERF_SCENARIO=$SCENARIO vagrant destroy -f)"
fi

[[ "$RUN_OK" -eq 1 ]] || exit 1
echo "[INFO] Done. Results in tools/performance/runs/."
