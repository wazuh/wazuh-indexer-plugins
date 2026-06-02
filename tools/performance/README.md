# Wazuh Indexer — Performance Testing

Tooling to measure Wazuh Indexer performance and catch regressions. Two scenarios
share one measurement layer:

| Scenario | Topology | Load source | Purpose |
|----------|----------|-------------|---------|
| **real-world** | AIO + 2 agents | Agents' FIM + Logcollector loops | Realistic SIEM ingest; hardware requirements |
| **isolated** | single indexer + monitor VM | OpenSearch Benchmark | Indexer in isolation, watched from **boot** (node_exporter → Prometheus/Grafana) incl. cold start |

The **measurement layer** ([metrics/sampler.py](metrics/sampler.py)) polls the
indexer's `_nodes/stats` + `_cluster/stats` (and, on the host, CPU/RAM/disk) and
emits per-minute CSV/NDJSON. The `isolated` scenario adds **node_exporter +
Prometheus** for continuous, from-boot host metrics so the cold start is captured.

> **Topology note:** `isolated` installs a **single standalone wazuh-indexer**
> (no manager, no dashboard) to measure the indexer alone; `real-world` uses the
> full AIO.

## Quick start

One entrypoint owns the whole lifecycle — `vagrant up` → measure → `vagrant destroy`:

```bash
cd tools/performance
./run.sh --scenario real-world                 # AIO + 2 agents
./run.sh --scenario isolated                   # single indexer + monitor + OSB, from cold start
./run.sh --scenario real-world --version 4.14  # install + measure 4.x instead of 5.x
./run.sh --scenario isolated --keep            # leave the VMs up afterwards (debug)
```

Results land in `tools/performance/runs/` (`metrics.csv`, `report.md`, …), labeled
with the **actual installed** Wazuh version (auto-detected from the VM; override
with `--version`). Requires Vagrant + a provider; for libvirt also set a box, e.g.
`PERF_BOX=cloud-image/ubuntu-24.04 ./run.sh --scenario real-world`.

## Layout

```
tools/performance/
├── run.sh                          # ENTRYPOINT — up → measure → destroy (--scenario real-world|isolated)
├── metrics/sampler.py              # per-minute host + indexer sampler → CSV/NDJSON
├── analyze/report.py               # aggregates a run → labeled hardware-utilization report.md
├── analyze/compare.py              # diffs two+ runs side by side → compare.md (e.g. 4.x vs 5.x)
├── analyze/plot.py                 # timeline charts overlaying runs → timeline.png (spikes)
├── vagrant/
│   ├── Vagrantfile                 # PERF_SCENARIO=real-world (aio+agents) | isolated (indexer+monitor)
│   ├── run-real-world.sh           # measurement helper (assumes VMs up); invoked by run.sh
│   └── run-isolated.sh             # measurement helper (cold-start + OSB); invoked by run.sh
├── scripts/                        # guest-side install/measurement scripts (synced to /opt/perf/scripts)
│   ├── setup-aio.sh                # install AIO (real-world) — official assistant by --version
│   ├── setup-indexer.sh            # install single-node indexer (isolated) by --version
│   ├── setup-agent.sh              # install + enroll an agent, configure FIM/Logcollector paths
│   ├── run-scenario.sh             # measurement window: marks window, runs sampler + report
│   └── agent-load.sh               # runs on each agent: FIM + Logcollector loops
├── monitoring/                     # isolated-scenario continuous monitoring
│   ├── setup-node-exporter.sh      # node_exporter systemd on the indexer host (from boot)
│   ├── setup-monitor.sh            # Prometheus + Grafana on the monitor host
│   ├── compose.yml                 # Prometheus + Grafana containers
│   └── prometheus.yml              # scrape config (node_exporter on the indexer)
└── benchmark/                      # OSB synthetic workload (used by the isolated scenario)
    ├── gen-corpora.py              # builds OSB index.json + corpus from the real template + WCS generator
    ├── run-osb.sh                  # runs opensearch-benchmark with the custom workload
    └── workloads/wazuh-events/workload.json
```

## real-world scenario

`./run.sh --scenario real-world` brings up an AIO + 2 agents, drives FIM +
Logcollector load, runs the per-minute measurement window, pulls results to
`runs/aio-run/`, and tears the VMs down. Hosts ([vagrant/Vagrantfile](vagrant/Vagrantfile)):

| VM | Role | Size | IP |
|----|------|------|----|
| `aio` | manager + indexer + dashboard | 16 GB / 8 vCPU | 192.168.60.20 |
| `agent-1` | Wazuh agent (FIM + Logcollector) | 2 GB / 2 vCPU | 192.168.60.21 |
| `agent-2` | Wazuh agent (FIM + Logcollector) | 2 GB / 2 vCPU | 192.168.60.22 |

Tune the load with `--duration` / `--interval` / `--rate`. The admin password is
read from the AIO VM automatically. Everything goes over `vagrant ssh` — the synced
folder is used only to deliver scripts host→guest at `vagrant up`; **guest→host
transfer is not relied on** (vagrant-libvirt syncs one way only).

## isolated scenario

`./run.sh --scenario isolated` brings up a single indexer VM (with node_exporter
from boot) + a monitor VM (Prometheus + Grafana + OpenSearch Benchmark). It
**restarts the indexer to capture its cold start** (Prometheus is already
recording), drives the OSB synthetic workload **from the monitor VM** (off the
indexer host), pulls results to `runs/isolated/`, and points you at Grafana for
the full host timeline. `--docs` sets the corpus size.

> **Host requirements:** ~20 GB free RAM, 12 vCPU. Box defaults to
> `bento/ubuntu-24.04` (VirtualBox/Parallels/VMware, incl. Apple Silicon); VM
> sizing applies to every provider. For libvirt, use a libvirt-capable box:
> `PERF_BOX=cloud-image/ubuntu-24.04 ./run.sh --scenario isolated --provider...`.
> VMs use the `192.168.60.x` subnet (avoids VirtualBox's `192.168.56.x` host-only
> range, which blocks libvirt network creation).

## Manual hosts (without Vagrant)

The guest-side scripts run on any bare host (e.g. AWS VMs). A single `--version`
selects the Wazuh release; the flow is identical for 4.x and 5.x.

**real-world** — on the AIO host, then each agent host:

```bash
VERSION=5.0.0    # or 4.14
sudo ./scripts/setup-aio.sh --version $VERSION --password-out ./runs/admin-password.txt
sudo ./scripts/setup-agent.sh --version $VERSION --manager <aio-ip>   # each agent
./scripts/agent-load.sh --duration 3600                               # each agent
sudo ./scripts/run-scenario.sh --endpoint https://localhost:9200 --user admin \
  --password "$(cat ./runs/admin-password.txt)" --insecure \
  --duration 3600 --interval 60 --label wazuh-$VERSION --out ./runs/$VERSION
```

**isolated** — single indexer + a separate monitor host:

```bash
sudo ./scripts/setup-indexer.sh --version 5.0.0 --password-out ./runs/admin-password.txt
sudo ./monitoring/setup-node-exporter.sh                              # indexer host (from boot)
sudo ./monitoring/setup-monitor.sh --indexer-host <indexer-ip>        # monitor host: Prometheus :9090, Grafana :3000
sudo systemctl restart wazuh-indexer                                  # capture cold start
./benchmark/run-osb.sh --target https://<indexer-ip>:9200 --user admin --password <pass> --no-host
```

`--no-host` tells the sampler to skip psutil (host metrics come from node_exporter).

## Comparing versions (4.x vs 5.x)

Each run is labeled with the real installed version. To compare, run the same
scenario twice (`--version 4.14`, then `--version 5.0.0`, e.g. on separate CI/AWS
VMs) and diff the artifacts.

`run-scenario.sh` runs the sampler then `analyze/report.py`, producing `report.md`
(avg/peak of host CPU, RAM, disk, ingest rate, per-process split — **all samples
included**; pass `--warmup N` to drop the first N). Diff two runs:

```bash
python3 analyze/compare.py wazuh-4.x=./runs/4x/metrics.csv wazuh-5.0.0=./runs/5x/metrics.csv
```

See *when* spikes happen (cold start, GC, ingest dips) with `analyze/plot.py`,
which overlays the runs on a minutes-since-start timeline (needs `matplotlib`):

```bash
python3 analyze/plot.py wazuh-4.x=./runs/4x/metrics.csv wazuh-5.0.0=./runs/5x/metrics.csv --out timeline.png
```

> For the delta to mean "version cost", the two runs must be **comparable**:
> same driven load (`--rate`), fresh/equal starting data, and a documented JVM
> heap size — otherwise the diff also reflects workload and config differences.

## Metrics captured (per minute)

**Host (the sizing deliverable):** total CPU %, load, RAM used (GB + %), swap,
disk used, disk read/write rate; per-process CPU + RAM split across
`wazuh-indexer` / `wazuh-manager` / `wazuh-dashboard`.
**Indexer:** ingest rate + latency, indexing pressure, write/search thread-pool
queue + rejections, JVM heap %, GC count/time, segments, merge/refresh/flush,
store size, doc count. See [metrics/sampler.py](metrics/sampler.py) for the exact fields.

## Requirements

- Python 3.9+ with `requests` (already used by the repo's event generators).
- `psutil` on the host for host/process metrics (`pip install psutil` or
  `apt install python3-psutil`; the Vagrant env installs it automatically).
- `matplotlib` for timeline charts (`analyze/plot.py`): `pip install matplotlib`.
- `opensearch-benchmark` for the isolated scenario (`pip install opensearch-benchmark`;
  the monitor VM installs it automatically).
- Docker on the monitor host for Prometheus + Grafana (`setup-monitor.sh`).
