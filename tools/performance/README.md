# Wazuh Indexer - Performance Testing

Tooling to measure Wazuh Indexer performance and catch regressions. Two scenarios
share one measurement layer:

| Scenario | Topology | Load source | Purpose |
|----------|----------|-------------|---------|
| **isolated** *(default)* | single indexer + monitor VM | Steady-rate system-activity events → findings | Indexer in isolation, watched from **boot** (node_exporter + JMX → Prometheus/Grafana) incl. cold start, with the detection pipeline producing findings |
| **real-world** | AIO + 2 agents | Agents' FIM + Logcollector loops | Realistic SIEM ingest, hardware requirements |

`isolated` is the default: it installs a single indexer, captures cold start, then for
`--duration` seconds indexes a fixed system-activity event into the
`wazuh-events-v5-system-activity` data stream at `--rate` events/sec while monitoring — a
**pre-created detector** turns each event into a **finding**. Pick **real-world** for
hardware sizing under realistic agent load.

The **measurement layer** ([metrics/sampler.py](metrics/sampler.py)) polls the
indexer's `_nodes/stats` + `_cluster/stats` (and, on the host, CPU/RAM/disk) and
emits per-minute CSV/NDJSON. The `isolated` scenario adds **node_exporter + a JMX
exporter + Prometheus** for continuous, from-boot host **and JVM** metrics so the cold
start is captured.

> **Topology note:** `isolated` installs a **single standalone wazuh-indexer**
> (no manager, no dashboard) to measure the indexer alone, `real-world` uses the
> full AIO.

> **Terms:** AIO = all-in-one (manager + indexer + dashboard), FIM / Logcollector =
> agent modules that produce file/log events, OSB = OpenSearch Benchmark, cold start =
> the indexer's first boot (index-template/ISM/CTI-sync cost).

## Prerequisites

- Vagrant + a provider (VirtualBox / Parallels / libvirt) for Method 1, on a host with ~20 GB free RAM and 12 vCPU
- Python 3.9+
- `requests`
- `psutil`
- `matplotlib`
- Docker (isolated scenario monitor: Prometheus + Grafana)

Install the Python dependencies in a virtual environment:

```bash
cd tools/performance
python3 -m venv .venv
source .venv/bin/activate
pip install requests psutil matplotlib
```

> Method 1 (Vagrant) installs the guest-side dependencies (`psutil`, Docker) inside the VMs automatically, so on the host you only need Python with `requests` and `matplotlib`. For Method 2 (manual), install the requirements on each host yourself.

## Running

There are two methods to execute the performance tests, they use the same scripts and analysis, differing only in how the hosts are created.

| Method | Where | Use it for |
|--------|-------|-----------|
| **One-liner (Vagrant)** | your machine | turnkey local runs - `run.sh` owns up → measure → teardown |
| **Manual** | any hosts, e.g. **AWS EC2** | cloud / CI / dev - run the guest-side scripts directly on the instances |

### Method 1 - One-liner (Vagrant, local)

One entrypoint owns the whole lifecycle:

```bash
cd tools/performance
./run.sh                                       # DEFAULT: isolated — indexer + findings load, from cold start
./run.sh --scenario real-world                 # AIO + 2 agents (torn down on success)
./run.sh --version 4.14                        # install + measure 4.x instead of 5.x
./run.sh --rate 2000 --duration 900            # 2000 events/s for 15 min (longer active-load window)
./run.sh --destroy                             # tear down a kept isolated env when done
./run.sh --package ~/wazuh-indexer_5.0.0_amd64.deb            # benchmark a local build (indexer only)
./run.sh --scenario real-world --package ~/...amd64.deb       # AIO, then overwrite the indexer
./run.sh --tune-config ./my-perf-tune.yml                     # override heap / detection / memlock / swap
```

> **Findings load (isolated):** the run pre-creates a security-analytics detector + Sigma
> rule (offline, via [benchmark/setup-detector.sh](benchmark/setup-detector.sh)), then
> indexes a fixed system-activity event into `wazuh-events-v5-system-activity` at `--rate`
> events/sec for `--duration` seconds ([benchmark/event-loader.py](benchmark/event-loader.py)).
> The detector's monitor runs on a 1-minute schedule, so each event becomes a finding in
> `wazuh-findings-v5-*`. The run **fails loudly if zero findings are generated**. Keep
> `--duration` at least a few minutes so the monitor fires. Detection/enrichment is ON by
> default (see [config/perf-tune.yml](config/perf-tune.yml)); CTI catalog sync stays OFF
> because the detector is pre-created — no network to the CTI API is needed.

> **Custom indexer build:** `--package FILE` benchmarks a specific local `.deb`/`.rpm`
> instead of resolving by version. `run.sh` stages the file into the synced folder so the
> guest can read it. **isolated** installs it directly; **real-world** installs the AIO
> normally, then overwrites only the `wazuh-indexer` package with it — keeping the AIO's
> generated admin password, security index, and certs (the package's own
> `opensearch.yml` is not applied; the AIO's is kept). `--version` still selects the
> certificate flow, so match it to the package (e.g. `--version 4.14 --package
> wazuh-indexer_4.14.x.deb`). The run is labeled with the package's own installed version,
> so a build sharing a stock version string lands in the same `runs/<scenario>-<ver>/` dir.

> **Teardown:** `real-world` is torn down automatically on success. **`isolated`
> leaves the VMs up** so the Grafana/Prometheus cold-start timeline (which lives on
> the monitor VM) stays reachable — explore it, then run `--destroy` (or just start
> another run; leftovers are cleaned up first). `--keep` forces real-world to stay up too.

Results land in `tools/performance/runs/<scenario>-<version>/`, named after the
**actual installed** Wazuh version, so `--version 4.14` lands in
`runs/isolated-4.14.1/` (the resolved patch) and runs of different versions never
overwrite each other and can be compared (see [Output](#output)). Tune load with
`--duration` / `--interval` / `--rate`. Topologies ([vagrant/Vagrantfile](vagrant/Vagrantfile)):

- **isolated**: `indexer` (16 GB/8 vCPU, node_exporter + JMX exporter from boot) + `monitor`
  (2 GB/2 vCPU, Prometheus/Grafana/image-renderer) - 192.168.60.20 / .30. Restarts the indexer to capture
  its cold start, pre-creates the detector and drives the findings load from the monitor, and
  opens Grafana on the auto-provisioned **Host Overview** (`uid wazuh-host-overview`) and
  **JVM Overview** (`uid wazuh-jvm-overview`) dashboards.
- **real-world**: `aio` (16 GB/8 vCPU) + `agent-1`/`agent-2` (2 GB/2 vCPU) - 192.168.60.20–22.

> **Host:** ~20 GB free RAM, 12 vCPU. Box defaults to `bento/ubuntu-24.04`
> (VirtualBox/Parallels/VMware, incl. Apple Silicon). For libvirt use a
> libvirt-capable box: `PERF_BOX=cloud-image/ubuntu-24.04 ./run.sh`.
> All host↔guest transfer is over `vagrant ssh`, the synced folder is only used to
> deliver scripts at `vagrant up` (vagrant-libvirt syncs one way).

### Tuning config

Indexer tuning is declared in [config/perf-tune.yml](config/perf-tune.yml), applied at
provision time by [scripts/perf-tune-indexer.sh](scripts/perf-tune-indexer.sh):

```yaml
heap_size: 4g                          # JVM -Xms/-Xmx — ALWAYS applied (permanent)

enriched_findings_index_enabled: true  # 5.x findings enrichment (needed for findings)
catalog_update_on_start: false         # CTI catalog sync on start  ┐ off — we pre-create
catalog_update_on_schedule: false      # CTI catalog sync on schedule│   the detector offline
catalog_create_detectors: false        # auto detector creation     ┘   (no CTI network)
telemetry_enabled: false               # content-manager telemetry

memory_lock: false                     # on-demand: bootstrap.memory_lock + systemd LimitMEMLOCK
disable_swap: false                    # on-demand: swapoff -a (this boot only)
```

The YAML is the single source of truth — every key is required (no code-side defaults) and
its value is written verbatim into `opensearch.yml` (the 5.x plugin keys are skipped on 4.x).
The heap is a permanent setting; the `memory_lock` / `disable_swap` toggles are off by
default and enabled on demand. Override per-run with `--tune-config FILE`.

### Method 2 - manual (bare hosts, e.g. AWS EC2)

`run.sh` is Vagrant-only. On real hosts you run the guest-side scripts directly,
more control, and what you'd use on EC2 or in CI. Put the tool on each instance
(`git clone` the repo, or `scp -r tools/performance`), and install deps on the
**measuring** host:

```bash
sudo apt-get install -y python3 python3-requests python3-psutil    # Debian/Ubuntu
cd <repo>/tools/performance
```

A single `--version` selects the release, the flow is identical for 4.x and 5.x.
Use the instances' **private IPs** for inter-host traffic.

**real-world** - 1 AIO instance + 2 agent instances:

```bash
# AIO instance - install + capture the admin password:
VERSION=5.0   # or 4.14  (MAJOR.MINOR; latest patch of the line is installed)
sudo ./scripts/setup-aio.sh --version "$VERSION" --password-out ./runs/admin-password.txt
# ...or benchmark a specific indexer build: install the AIO, then overwrite the indexer
# (--version still selects the cert flow; the AIO password/certs are preserved):
#   sudo ./scripts/setup-aio.sh --version "$VERSION" --package ./wazuh-indexer_5.0.0_amd64.deb \
#        --password-out ./runs/admin-password.txt

# each agent instance - enroll against the AIO and start the load loop:
sudo ./scripts/setup-agent.sh --version "$VERSION" --manager <aio-private-ip>
./scripts/agent-load.sh --duration 3600

# AIO instance - run the measurement window (sampler reads localhost + host metrics):
sudo ./scripts/run-scenario.sh --endpoint https://localhost:9200 --user admin \
  --password "$(cat ./runs/admin-password.txt)" --insecure \
  --duration 3600 --interval 60 --label "wazuh-$VERSION" --out ./runs/"$VERSION"
```

Results stay in `./runs/$VERSION` on the AIO instance - `scp` them off.

**isolated** - 1 indexer instance + 1 monitor instance:

```bash
# indexer instance:
sudo ./scripts/setup-indexer.sh --version 5.0 --password-out ./runs/admin-password.txt
# ...or benchmark a specific build (--version still selects the cert flow):
#   sudo ./scripts/setup-indexer.sh --version 5.0 --package ./wazuh-indexer_5.0.0_amd64.deb
sudo ./monitoring/setup-node-exporter.sh                                    # from boot
sudo ./monitoring/setup-jmx-exporter.sh                                     # JVM metrics on :9404

# monitor instance (needs Docker):
sudo ./monitoring/setup-monitor.sh --indexer-host <indexer-private-ip>      # Prometheus :9090, Grafana :3000

# indexer instance - capture cold start, then drive the findings load from the monitor:
sudo systemctl restart wazuh-indexer
# monitor instance:
./benchmark/run-load.sh --target https://<indexer-private-ip>:9200 --user admin --password <pass> \
  --rate 1000 --duration 600 --no-host --node-exporter <indexer-private-ip>:9100
```

`run-load.sh` pre-creates the detector ([benchmark/setup-detector.sh](benchmark/setup-detector.sh)),
indexes the system-activity event at `--rate` events/sec for `--duration` seconds, samples the
indexer, and verifies findings were generated. `--no-host` skips local psutil (the sampler runs
off the indexer host). `--node-exporter` reads the indexer's host metrics (CPU, RAM, disk, load)
from node_exporter into the CSV, so `report.md` / `compare.md` / `timeline.png` include them. The
same series (plus JVM metrics from the JMX exporter) stay in Prometheus/Grafana for the from-boot
cold-start view.

> **AWS notes:** open the security-group ports between instances, 9200 (indexer),
> 1514/1515 (agent→manager, real-world), 9100 (node_exporter→Prometheus, isolated),
> 9404 (JMX exporter→Prometheus, isolated), 9090/3000 (Prometheus/Grafana). Retrieve
> artifacts with `scp -r <host>:.../runs ./`.

## Layout

```
tools/performance/
├── run.sh                          # One-liner entrypoint - up → measure → destroy (default: isolated)
├── analyze.sh                      # one-shot: build <scenario>-compare.md + -timeline.png from runs/
├── config/perf-tune.yml            # indexer tuning: permanent heap + on-demand toggles
├── metrics/sampler.py              # per-minute host + indexer sampler → CSV/NDJSON
├── analyze/report.py               # aggregates a run → labeled hardware-utilization report.md
├── analyze/compare.py              # diffs two+ runs side by side → compare.md (e.g. 4.x vs 5.x)
├── analyze/plot.py                 # timeline charts overlaying runs → timeline.png (spikes)
├── vagrant/
│   ├── Vagrantfile                 # PERF_SCENARIO=isolated (indexer+monitor) | real-world (aio+agents)
│   ├── lib.sh                      # shared helpers (rsync, password/version detect, results pull)
│   ├── run-real-world.sh           # Vagrant measurement helper (invoked by run.sh)
│   └── run-isolated.sh             # Vagrant measurement helper, cold-start + findings load (invoked by run.sh)
├── scripts/                        # guest-side install/measurement scripts (run directly in Method 2)
│   ├── setup-aio.sh                # install AIO (real-world) - official assistant by --version
│   ├── setup-indexer.sh            # install single-node indexer (isolated) by --version
│   ├── setup-agent.sh              # install + enroll an agent, configure FIM/Logcollector paths
│   ├── perf-tune-indexer.sh        # apply config/perf-tune.yml (heap + toggles) to the indexer
│   ├── run-scenario.sh             # measurement window: marks window, runs sampler + report
│   └── agent-load.sh               # runs on each agent: FIM + Logcollector loops
├── monitoring/                     # isolated-scenario continuous monitoring
│   ├── setup-node-exporter.sh      # node_exporter systemd on the indexer host (from boot)
│   ├── setup-jmx-exporter.sh       # JMX Prometheus exporter (javaagent) on the indexer JVM (:9404)
│   ├── jmx-exporter-config.yaml    # JMX exporter MBean rules
│   ├── setup-monitor.sh            # Prometheus + Grafana on the monitor host
│   ├── compose.yml                 # Prometheus + Grafana containers
│   ├── prometheus.yml              # scrape config (node_exporter :9100 + JMX exporter :9404)
│   ├── grafana-datasource.yml      # auto-provision Prometheus as Grafana's datasource
│   └── grafana/                    # auto-provisioned dashboards
│       ├── dashboard-provider.yml  # tells Grafana to load JSON dashboards at start
│       ├── host-overview.json      # Host Overview dashboard (node_exporter PromQL)
│       └── jvm-overview.json       # JVM Overview dashboard (JMX exporter PromQL)
└── benchmark/                      # isolated-scenario findings load
    ├── event-loader.py             # steady-rate loader: TEST_EVENT → wazuh-events-v5-system-activity
    ├── setup-detector.sh           # pre-creates the log type + Sigma rule + detector (offline)
    ├── run-load.sh                 # detector + loader + sampler, then verifies findings
    └── detector/                   # logtype.json, rule.yml, detector.json
```

## Output

Each run writes `runs/<scenario>-<version>/` with per-minute `metrics.csv`
(+ `.ndjson`), `run-metadata.json` (includes `events_indexed` + `findings` for isolated),
a `report.md`, a single-run `timeline.png`, and — for isolated — `grafana-host-overview.png`
and `grafana-jvm-overview.png` rendered from the live Grafana dashboards (via the
[grafana-image-renderer](https://grafana.com/grafana/plugins/grafana-image-renderer) sidecar
in [monitoring/compose.yml](monitoring/compose.yml)):

```
# Performance report - wazuh-5.0.0
- Samples: 60 (all included)
| Metric              | Avg   | Peak  |
| Host CPU (%)        | 1.5   | 2.3   |
| Host RAM used (GB)  | 9.4   | 9.5   |
| Ingest rate (docs/s)| 121.8 | 133.5 |
```

So the default flow is: run `./run.sh`, wait for completion, then check
`runs/isolated-<version>/metrics.csv` + `timeline.png` (and the findings count printed at
the end). Timing: provisioning ~10–15 min, then the load + sampler window (`--duration`,
default 60 min for real-world, 10 min for isolated).

## Comparing versions (4.x vs 5.x)

Each run is labeled with its real installed version. To compare, run the same
scenario twice (`--version 4.14`, then `--version 5.0`, e.g. on separate CI/AWS
VMs), they land in `runs/real-world-4.14.1/` and `runs/real-world-5.0.0/` (the
resolved patches). Then
generate the comparison + timeline in one shot from `tools/performance/`:

```bash
./analyze.sh                       # every scenario found in runs/
./analyze.sh --scenario real-world # restrict to one scenario
```

It groups runs by scenario (never mixing real-world with isolated) and writes
`<scenario>-compare.md` (side-by-side avg/peak diff, needs ≥2 versions) and
`<scenario>-timeline.png` (overlaid minutes-since-start lines showing *when* spikes
happen - cold start, GC, ingest dips). Each run also keeps its own `report.md`,
all of these include **every sample**, pass `--warmup N` to drop the first N.
Under the hood `analyze.sh` calls the two tools, which you can also run directly:

```bash
python3 analyze/compare.py \
  wazuh-4.14.1=./runs/real-world-4.14.1/metrics.csv \
  wazuh-5.0.0=./runs/real-world-5.0.0/metrics.csv          # → compare.md
python3 analyze/plot.py \
  wazuh-4.14.1=./runs/real-world-4.14.1/metrics.csv \
  wazuh-5.0.0=./runs/real-world-5.0.0/metrics.csv --out timeline.png   # needs matplotlib
```

> For the delta to mean "version cost", the two runs must be **comparable**:
> same driven load (`--rate`), fresh/equal starting data, and a documented JVM
> heap size, otherwise the diff also reflects workload and config differences.

## Metrics captured (per minute)

**Host (the sizing deliverable):** total CPU %, load, RAM used (GB + %), swap,
disk used, disk read/write rate. In **real-world** these come from local psutil and
include a per-process CPU + RAM split across `wazuh-indexer` / `wazuh-manager` /
`wazuh-dashboard`. In **isolated** they come from the indexer's node_exporter (no
per-process split, but the indexer is effectively the whole host there).
**Indexer:** ingest + query rate, **per-operation index/query latency** (ms/op),
indexing pressure, write/search thread-pool queue depth + **rejections/s** (attributed
to the window, not since boot), JVM heap %, GC count/time, segments, merge/refresh/flush,
store size, doc count. See [metrics/sampler.py](metrics/sampler.py) for the exact fields,
the labeled `report.md` surfaces avg + peak for each.

## Troubleshooting

**Leftover VMs.** The `isolated` scenario leaves its VMs up on success, and a failed or
interrupted run leaves them up too. A bare `vagrant destroy` only sees the default
scenario's machines, so destroy with the scenario set explicitly (run from
`tools/performance/vagrant/`):

```bash
PERF_SCENARIO=isolated   vagrant destroy -f   # isolated VMs (indexer + monitor)
PERF_SCENARIO=real-world vagrant destroy -f   # real-world VMs (aio + agents)
```

Or use the entrypoint, which wraps the same command:

```bash
./run.sh --scenario isolated --destroy
```

Starting a new run also clears leftovers from both scenarios first. For VMs orphaned
outside Vagrant's state, inspect them with `vagrant global-status --prune` (and the
provider's own list, e.g. `VBoxManage list runningvms`).
