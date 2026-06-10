#!/bin/bash
#
# run.sh — entry point for a Wazuh Indexer performance test.
#
# Owns the full lifecycle: brings the Vagrant environment up, runs the scenario's
# measurement, then tears the environment down. The user only runs this script.
#
#   ./run.sh                                       # DEFAULT: isolated (single indexer + monitor)
#   ./run.sh --scenario real-world                 # AIO + 2 agents (FIM/Logcollector)
#   ./run.sh --scenario real-world --version 4.14  # install + measure 4.x
#   ./run.sh --scenario isolated --keep            # leave the VMs up afterwards
#
# Results land in tools/performance/runs/. Requires Vagrant + a provider (libvirt,
# VirtualBox, …). For libvirt also set the box, e.g.
#   PERF_BOX=cloud-image/ubuntu-24.04 ./run.sh
#
set -euo pipefail

SCENARIO="isolated"               # default scenario (one-shot indexer + findings load)
VERSION=""
PASSWORD=""
KEEP=""
DESTROY=""
PACKAGE=""
TUNE_CONFIG=""                    # perf-tune YAML override (default: config/perf-tune.yml)
# Scenario-specific passthrough (defaults match the runners).
DURATION="" INTERVAL="" RATE=""   # both scenarios (RATE: events/sec)

usage() {
    cat <<'EOF'
Usage: run.sh [--scenario isolated|real-world] [options]

Owns the lifecycle: vagrant up → measure → (real-world) destroy. The DEFAULT scenario
is `isolated`: it installs a single indexer, captures cold start, then for --duration
seconds indexes a fixed system-activity event into the wazuh-events-v5-system-activity
data stream at --rate events/sec while monitoring — generating FINDINGS. On completion
it writes metrics.csv + report.md + timeline.png and prints the findings count.

The isolated scenario LEAVES THE VMs UP on success so Grafana stays reachable; tear them
down with `run.sh --destroy` (or just start another run). Results land in
tools/performance/runs/<scenario>-<version>/.

Global options:
  --scenario isolated|real-world   topology to run (default: isolated)
  --version MAJOR.MINOR            Wazuh line to install (e.g. 5.0, 4.14); latest patch of the line
  --password P                     admin password (auto-detected from the VM if omitted)
  --keep                           leave the VMs up afterwards (real-world; isolated already keeps)
  --destroy                        tear down the scenario's VMs and exit (no run)
  --package FILE|URL               benchmark a specific indexer build — a local .deb/.rpm OR
                                   an http(s) URL (e.g. a nightly-backup .deb when a build is
                                   broken); bypasses the artifacts YAML. isolated installs it
                                   directly; real-world installs the AIO then overwrites the
                                   indexer. --version still selects the cert flow (match it).
  --tune-config FILE               perf-tune YAML overriding config/perf-tune.yml (heap size +
                                   detection/memory_lock/swap toggles). Heap is always applied;
                                   toggles default per the YAML. See config/perf-tune.yml.
  -h, --help                       show this help

Measurement options (both scenarios):
  --duration S                     load + sampler window in seconds (default: real-world 3600, isolated 600)
  --interval S                     seconds between samples (default 60)
  --rate N                         events/sec. isolated: events indexed into the data stream per second
                                   (default 1000). real-world: per-agent rate per source (FIM +
                                   Logcollector); 2 agents → ~2N docs/s offered to the indexer (default 10).

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
        --tune-config) TUNE_CONFIG="$2"; shift 2 ;;
        --keep)     KEEP=1; shift ;;
        --destroy)  DESTROY=1; shift ;;
        --package)  PACKAGE="$2"; shift 2 ;;
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

# Resolve a LOCAL --package to an absolute path NOW, while still in the invocation
# directory (the `cd "$VAGRANT_DIR"` below would break a cwd-relative path). A URL is
# left as-is — the guest downloads it.
if [[ -n "$PACKAGE" && "$PACKAGE" != http*://* ]]; then
    [[ -f "$PACKAGE" ]] || { echo "[ERROR] --package file not found: $PACKAGE" >&2; exit 1; }
    PACKAGE="$(cd "$(dirname "$PACKAGE")" && pwd)/$(basename "$PACKAGE")"
fi

# Provision: the Vagrantfile reads PERF_SCENARIO; PERF_VERSION (if given) picks the
# install version. Run all vagrant commands from the Vagrantfile's directory.
export PERF_SCENARIO="$SCENARIO"
[[ -n "$VERSION" ]] && export PERF_VERSION="$VERSION"

# --tune-config: stage a custom perf-tune.yml into the synced folder so the guest can read
# it (the guest only sees files under tools/performance, mounted at /opt/perf). Default
# (config/perf-tune.yml) ships in the tree, so PERF_TUNE_CONFIG is only set when overridden.
if [[ -n "$TUNE_CONFIG" ]]; then
    [[ -f "$TUNE_CONFIG" ]] || { echo "[ERROR] --tune-config file not found: $TUNE_CONFIG" >&2; exit 1; }
    mkdir -p "$HERE/.pkg"
    cp -f "$TUNE_CONFIG" "$HERE/.pkg/perf-tune.yml"
    export PERF_TUNE_CONFIG="/opt/perf/.pkg/perf-tune.yml"
    echo "[INFO] Using perf-tune config: $TUNE_CONFIG ($PERF_TUNE_CONFIG)"
fi

cd "$VAGRANT_DIR"

# Destroy-only: tear down the scenario's VMs and exit (e.g. clean up an isolated run
# whose VMs were left up for Grafana).
if [[ -n "$DESTROY" ]]; then
    echo "[INFO] Destroying the '$SCENARIO' environment ..."
    PERF_SCENARIO="$SCENARIO" vagrant destroy -f
    exit 0
fi

# --package: hand the setup script a build to install via PERF_PACKAGE. A local .deb/.rpm
# is staged into the synced folder so the guest can read it; a URL is passed through and
# the guest downloads it (handy when a nightly build is broken — point at a backup URL).
# isolated installs it directly (setup-indexer.sh); real-world installs the AIO then
# overwrites the indexer (setup-aio.sh).
if [[ -n "$PACKAGE" ]]; then
    case "$SCENARIO" in
        isolated|real-world) ;;
        *) echo "[ERROR] --package requires --scenario isolated or real-world." >&2; exit 1 ;;
    esac
    if [[ "$PACKAGE" == http*://* ]]; then
        export PERF_PACKAGE="$PACKAGE"
        echo "[INFO] --package is a URL; the guest will download it: $PACKAGE"
    else
        [[ -f "$PACKAGE" ]] || { echo "[ERROR] --package file not found: $PACKAGE" >&2; exit 1; }
        mkdir -p "$HERE/.pkg"
        cp -f "$PACKAGE" "$HERE/.pkg/"
        export PERF_PACKAGE="/opt/perf/.pkg/$(basename "$PACKAGE")"
        echo "[INFO] Staged $(basename "$PACKAGE") for the guest ($PERF_PACKAGE)"
    fi
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

# Build the measurement args. --duration/--interval/--rate drive the load + sampler window
# in BOTH scenarios (--rate is events/sec for isolated, per-agent rate for real-world).
RUN_ARGS=()
[[ -n "$VERSION" ]] && RUN_ARGS+=(--version "$VERSION")
[[ -n "$PASSWORD" ]] && RUN_ARGS+=(--password "$PASSWORD")
[[ -n "$DURATION" ]] && RUN_ARGS+=(--duration "$DURATION")
[[ -n "$INTERVAL" ]] && RUN_ARGS+=(--interval "$INTERVAL")
[[ -n "$RATE" ]] && RUN_ARGS+=(--rate "$RATE")

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
