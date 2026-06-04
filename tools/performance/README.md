# Wazuh Indexer - Performance Testing

Tooling to measure Wazuh Indexer performance and catch regressions. Two scenarios
share one measurement layer:

| Scenario | Topology | Load source | Purpose |
|----------|----------|-------------|---------|
| **real-world** | AIO + 2 agents | Agents' FIM + Logcollector loops | Realistic SIEM ingest, hardware requirements |
| **isolated** | single indexer + monitor VM | OpenSearch Benchmark | Indexer in isolation, watched from **boot** (node_exporter → Prometheus/Grafana) incl. cold start |

Pick **real-world** for hardware sizing under realistic agent load, and **isolated** for
indexer peak throughput and cold-start cost.

The **measurement layer** ([metrics/sampler.py](metrics/sampler.py)) polls the
indexer's `_nodes/stats` + `_cluster/stats` (and, on the host, CPU/RAM/disk) and
emits per-minute CSV/NDJSON. The `isolated` scenario adds **node_exporter +
Prometheus** for continuous, from-boot host metrics so the cold start is captured.

> **Topology note:** `isolated` installs a **single standalone wazuh-indexer**
> (no manager, no dashboard) to measure the indexer alone, `real-world` uses the
> full AIO.

> **Terms:** AIO = all-in-one (manager + indexer + dashboard), FIM / Logcollector =
> agent modules that produce file/log events, OSB = OpenSearch Benchmark, cold start =
> the indexer's first boot (index-template/ISM/CTI-sync cost).

## Prerequisites

- **Method 1 (Vagrant):** Vagrant + a provider (VirtualBox / Parallels / libvirt),
  on a host with ~20 GB free RAM and 12 vCPU. The `isolated` scenario builds its corpus
  on the host (it uses the `wcs/` generator), and `analyze.sh` plots on the host, so the
  host also needs `pip install requests matplotlib`.
- **Method 2 (manual):** the [Requirements](#requirements) deps installed per host,
  plus internet access to the Wazuh package repos.

## Running

There are two methods to execute the performance tests, they use the same scripts and analysis, differing only in how the hosts are created.

| Method | Where | Use it for |
|--------|-------|-----------|
| **One-liner (Vagrant)** | your machine | turnkey local runs - `run.sh` owns up → measure → destroy |
| **Manual** | any hosts, e.g. **AWS EC2** | cloud / CI / dev - run the guest-side scripts directly on the instances |

### Method 1 - One-liner (Vagrant, local)

One entrypoint owns the whole lifecycle:

```bash
cd tools/performance
./run.sh --scenario real-world                 # AIO + 2 agents
./run.sh --scenario isolated                   # single indexer + monitor + OSB, from cold start
./run.sh --scenario real-world --version 4.14  # install + measure 4.x instead of 5.x
./run.sh --scenario isolated --keep            # leave the VMs up afterwards (debug)
```

Results land in `tools/performance/runs/<scenario>-<version>/`, named after the
**actual installed** Wazuh version, so `--version 4.14` lands in
`runs/real-world-4.14.1/` (the resolved patch) and runs of different versions never
overwrite each other and can be compared (see [Output](#output)). Tune load with
`--duration` / `--interval` /
`--rate` (real-world) or `--docs` (isolated). Topologies ([vagrant/Vagrantfile](vagrant/Vagrantfile)):

- **real-world**: `aio` (16 GB/8 vCPU) + `agent-1`/`agent-2` (2 GB/2 vCPU) - 192.168.60.20–22.
- **isolated**: `indexer` (16 GB/8 vCPU, node_exporter from boot) + `monitor`
  (2 GB/2 vCPU, Prometheus/Grafana/OSB) - 192.168.60.20 / .30, restarts the indexer
  to capture its cold start, drives OSB from the monitor, and opens Grafana on the
  auto-provisioned **Host Overview** dashboard (`uid wazuh-host-overview`) for the timeline.

> **Host:** ~20 GB free RAM, 12 vCPU. Box defaults to `bento/ubuntu-24.04`
> (VirtualBox/Parallels/VMware, incl. Apple Silicon). For libvirt use a
> libvirt-capable box: `PERF_BOX=cloud-image/ubuntu-24.04 ./run.sh --scenario real-world`.
> All host↔guest transfer is over `vagrant ssh`, the synced folder is only used to
> deliver scripts at `vagrant up` (vagrant-libvirt syncs one way).

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
sudo ./monitoring/setup-node-exporter.sh                                    # from boot

# monitor instance (needs Docker + opensearch-benchmark, the corpus generator needs the full repo):
sudo ./monitoring/setup-monitor.sh --indexer-host <indexer-private-ip>      # Prometheus :9090, Grafana :3000
python3 benchmark/gen-corpora.py --docs 1000000

# indexer instance - capture cold start, then drive load from the monitor:
sudo systemctl restart wazuh-indexer
# monitor instance:
./benchmark/run-osb.sh --target https://<indexer-private-ip>:9200 --user admin --password <pass> --no-host
```

`--no-host` skips psutil (host metrics come from node_exporter → Prometheus/Grafana).

> **AWS notes:** open the security-group ports between instances, 9200 (indexer),
> 1514/1515 (agent→manager, real-world), 9100 (node_exporter→Prometheus, isolated),
> 9090/3000 (Prometheus/Grafana). Retrieve artifacts with `scp -r <host>:.../runs ./`.

## Layout

```
tools/performance/
├── run.sh                          # One-liner entrypoint - up → measure → destroy
├── analyze.sh                      # one-shot: build <scenario>-compare.md + -timeline.png from runs/
├── metrics/sampler.py              # per-minute host + indexer sampler → CSV/NDJSON
├── analyze/report.py               # aggregates a run → labeled hardware-utilization report.md
├── analyze/compare.py              # diffs two+ runs side by side → compare.md (e.g. 4.x vs 5.x)
├── analyze/plot.py                 # timeline charts overlaying runs → timeline.png (spikes)
├── vagrant/
│   ├── Vagrantfile                 # PERF_SCENARIO=real-world (aio+agents) | isolated (indexer+monitor)
│   ├── lib.sh                      # shared helpers (rsync, password/version detect, results pull)
│   ├── run-real-world.sh           # Vagrant measurement helper (invoked by run.sh)
│   └── run-isolated.sh             # Vagrant measurement helper, cold-start + OSB (invoked by run.sh)
├── scripts/                        # guest-side install/measurement scripts (run directly in Method 2)
│   ├── setup-aio.sh                # install AIO (real-world) - official assistant by --version
│   ├── setup-indexer.sh            # install single-node indexer (isolated) by --version
│   ├── setup-agent.sh              # install + enroll an agent, configure FIM/Logcollector paths
│   ├── run-scenario.sh             # measurement window: marks window, runs sampler + report
│   └── agent-load.sh               # runs on each agent: FIM + Logcollector loops
├── monitoring/                     # isolated-scenario continuous monitoring
│   ├── setup-node-exporter.sh      # node_exporter systemd on the indexer host (from boot)
│   ├── setup-monitor.sh            # Prometheus + Grafana on the monitor host
│   ├── compose.yml                 # Prometheus + Grafana containers
│   ├── prometheus.yml              # scrape config (node_exporter on the indexer)
│   ├── grafana-datasource.yml      # auto-provision Prometheus as Grafana's datasource
│   └── grafana/                    # auto-provisioned dashboard
│       ├── dashboard-provider.yml  # tells Grafana to load JSON dashboards at start
│       └── host-overview.json      # Host Overview dashboard (node_exporter PromQL)
└── benchmark/                      # OSB synthetic workload (used by the isolated scenario)
    ├── gen-corpora.py              # builds OSB index.json + corpus from the real template + WCS generator
    ├── run-osb.sh                  # runs opensearch-benchmark with the custom workload
    └── workloads/wazuh-events/workload.json
```

## Output

Each run writes `runs/<scenario>-<version>/` with per-minute `metrics.csv`
(+ `.ndjson`), `run-metadata.json`, and a `report.md` like:

```
# Performance report - wazuh-5.0.0
- Samples: 60 (all included)
| Metric              | Avg   | Peak  |
| Host CPU (%)        | 1.5   | 2.3   |
| Host RAM used (GB)  | 9.4   | 9.5   |
| Ingest rate (docs/s)| 121.8 | 133.5 |
```

Timing: provisioning ~10–15 min, then the measurement window (`--duration`, default
60 min for real-world, OSB ~10–15 min for isolated).

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
disk used, disk read/write rate, per-process CPU + RAM split across
`wazuh-indexer` / `wazuh-manager` / `wazuh-dashboard`.
**Indexer:** ingest + query rate, **per-operation index/query latency** (ms/op),
indexing pressure, write/search thread-pool queue depth + **rejections/s** (attributed
to the window, not since boot), JVM heap %, GC count/time, segments, merge/refresh/flush,
store size, doc count. See [metrics/sampler.py](metrics/sampler.py) for the exact fields,
the labeled `report.md` surfaces avg + peak for each.

## Requirements

- Python 3.9+ with `requests` (already used by the repo's event generators).
- `psutil` on the host for host/process metrics (`pip install psutil` or
  `apt install python3-psutil`, the Vagrant env installs it automatically).
- `matplotlib` for timeline charts (`analyze/plot.py`): `pip install matplotlib`.
- `opensearch-benchmark` for the isolated scenario (`pip install opensearch-benchmark`,
  the monitor VM installs it automatically).
- Docker on the monitor host for Prometheus + Grafana (`setup-monitor.sh`).
