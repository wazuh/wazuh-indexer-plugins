# Wazuh Indexer — Performance Testing

Tooling to measure Wazuh Indexer performance and catch regressions. Two complementary tracks share one measurement layer:

| Track | Topology | Load source | Purpose |
|-------|----------|-------------|---------|
| **A — Real-world** | AIO + 2 agents | Agents' FIM + Logcollector loops | Realistic SIEM ingest; hardware requirements |
| **B — Synthetic** | indexer-only | OpenSearch Benchmark | Deterministic, repeatable version/config comparison |
| **C — Cold-start + synthetic** | indexer-only + monitor VM | OpenSearch Benchmark | Full lifecycle incl. **startup**, watched continuously (node_exporter → Prometheus/Grafana) |

The **measurement layer** ([metrics/sampler.py](metrics/sampler.py)) polls the
indexer's `_nodes/stats` + `_cluster/stats` (and, on the host, CPU/RAM/disk) and
emits per-minute CSV/NDJSON. Track C adds **node_exporter + Prometheus** for
continuous, from-boot host metrics so the indexer's cold start is captured.

> **Topology note:** Tracks B and C install a **single standalone wazuh-indexer**
> (no manager, no dashboard) to measure the indexer in isolation; Track A uses the
> full AIO.

## Primary scenario

- **Topology:** AIO (manager + indexer + dashboard) + 2 agents (beta2), FIM + Logcollector loops.
- **Sizing:** 16 GB RAM, 8 CPU cores.
- **Duration:** 60 minutes — **Sampling:** every 1 minute (60 samples).

## Layout

```
tools/performance/
├── metrics/sampler.py              # per-minute host + indexer sampler → CSV/NDJSON
├── analyze/report.py               # aggregates a run → labeled hardware-utilization report.md
├── vagrant/
│   ├── Vagrantfile                 # PERF_TRACK=A (aio+agents) | BC (indexer+monitor)
│   ├── run-test.sh                 # Track A orchestrator: load loops + measurement window
│   └── run-track-c.sh              # Track C orchestrator: cold-start restart + OSB load
├── scenario/
│   ├── setup-aio.sh                # install AIO (Track A) — official assistant by --version
│   ├── setup-indexer.sh            # install single-node indexer (Tracks B/C) by --version
│   ├── setup-agent.sh              # install + enroll an agent, configure FIM/Logcollector paths
│   ├── run-scenario.sh             # 60-min orchestrator: marks window, runs sampler + report
│   └── agent-load.sh               # runs on each agent: FIM + Logcollector loops
├── monitoring/                     # Track C continuous monitoring
│   ├── setup-node-exporter.sh      # node_exporter systemd on the indexer host (from boot)
│   ├── setup-monitor.sh            # Prometheus + Grafana on the monitor host
│   ├── compose.yml                 # Prometheus + Grafana containers
│   └── prometheus.yml              # scrape config (node_exporter on the indexer)
└── benchmark/
    ├── gen-corpora.py              # builds OSB index.json + corpus from the real template + WCS generator
    ├── run-osb.sh                  # runs opensearch-benchmark with the custom workload
    └── workloads/wazuh-events/workload.json
```

## Track A — real-world run (self-contained Vagrant env)

The whole scenario is defined as VMs and provisioned end-to-end from the official
nightly artifacts — no manual install steps. Hosts ([vagrant/Vagrantfile](vagrant/Vagrantfile)):

| VM | Role | Size | IP |
|----|------|------|----|
| `aio` | manager + indexer + dashboard | 16 GB / 8 vCPU | 192.168.60.20 |
| `agent-1` | Wazuh agent (FIM + Logcollector) | 2 GB / 2 vCPU | 192.168.60.21 |
| `agent-2` | Wazuh agent (FIM + Logcollector) | 2 GB / 2 vCPU | 192.168.60.22 |

```bash
cd vagrant
vagrant up                          # 5.x by default; PERF_VERSION=4.14 vagrant up for 4.x
./run-test.sh --duration 3600 --interval 60 --rate 10
# → results pulled to tools/performance/runs/aio-run/
```

`run-test.sh` starts the FIM + Logcollector loops on both agents, runs the
per-minute measurement window on the AIO, and pulls the results back over SSH.
The indexer admin password is read from the AIO VM automatically (or pass
`--password`). Everything goes over `vagrant ssh` — the synced folder is used
only to deliver the scripts host→guest at `vagrant up`; **guest→host transfer is
not relied on** (vagrant-libvirt syncs one way only).

> **Host requirements:** ~20 GB free RAM, 12 vCPU. Box defaults to
> `bento/ubuntu-24.04` (VirtualBox/Parallels/VMware, incl. Apple Silicon); VM
> sizing is applied to every provider. Pick a provider with `vagrant up --provider=X`.
> For libvirt, use a libvirt-capable box:
> `PERF_BOX=cloud-image/ubuntu-24.04 vagrant up --provider=libvirt`.
> VMs default to the `192.168.60.x` subnet (avoids VirtualBox's `192.168.56.x`
> host-only range, which otherwise blocks libvirt network creation); override
> with `PERF_AIO_IP` / `PERF_AGENT_IPS`.
> A lighter alternative for Track B only (indexer in isolation) is Docker Compose;
> the full agent→manager→indexer path needs VMs.

### Manual hosts (without Vagrant)

The same scripts run on any bare host (e.g. AWS VMs). A single `--version` selects
the Wazuh release — the flow is identical for 4.x and 5.x:

```bash
VERSION=5.0.0    # or 4.14

# On the AIO host — installs manager + indexer + dashboard via the official assistant:
sudo ./scenario/setup-aio.sh --version $VERSION --password-out ./runs/admin-password.txt

# On each agent host — installs/enrolls the agent and configures FIM + Logcollector:
sudo ./scenario/setup-agent.sh --version $VERSION --manager <aio-ip>
./scenario/agent-load.sh --duration 3600          # start the load loop

# On the AIO host — run the measurement window (sampler reads host + indexer metrics):
sudo ./scenario/run-scenario.sh \
  --endpoint https://localhost:9200 --user admin \
  --password "$(cat ./runs/admin-password.txt)" --insecure \
  --duration 3600 --interval 60 --label wazuh-$VERSION --out ./runs/$VERSION
```

Produces `runs/$VERSION/metrics.csv`, `metrics.ndjson`, `run-metadata.json`, and
`report.md`.

## Tracks B & C — indexer-only synthetic benchmark

Both install a **single standalone indexer** (no manager/dashboard):

```bash
sudo ./scenario/setup-indexer.sh --version 5.0.0 --password-out ./runs/admin-password.txt
```

### Track B — synthetic benchmark

```bash
python3 benchmark/gen-corpora.py --docs 1000000          # corpus from real template + WCS generator
./benchmark/run-osb.sh --target https://<indexer-ip>:9200 --user admin --password <pass>
```

`run-osb.sh` also runs `metrics/sampler.py` alongside OSB's own report. Re-run on
a candidate build and `opensearch-benchmark compare` the two executions.

### Track C — cold-start + continuous monitoring

Adds always-on host monitoring so the indexer's **startup** is captured. On the
indexer host, node_exporter runs from boot; a separate **monitor host** runs
Prometheus + Grafana scraping it:

```bash
# indexer host:
sudo ./monitoring/setup-node-exporter.sh
# monitor host:
sudo ./monitoring/setup-monitor.sh --indexer-host <indexer-ip>     # Prometheus :9090, Grafana :3000

# then capture cold start + load (restart the indexer while Prometheus is recording):
sudo systemctl restart wazuh-indexer        # on the indexer host
./benchmark/run-osb.sh --target https://<indexer-ip>:9200 --user admin --password <pass> --no-host
```

`--no-host` tells the sampler to skip psutil (host metrics come from node_exporter).
Everything is automated in the Vagrant env:

```bash
cd vagrant
PERF_TRACK=BC vagrant up        # indexer VM + monitor VM
./run-track-c.sh                # restart indexer (cold start) → OSB load → pull results; Grafana for the timeline
```

## Comparing versions (4.x vs 5.x)

Each invocation measures **one** running AIO and is tagged with `--label`. To
compare, run the **same flow twice** — once with `--version 4.14`, once with
`--version 5.0.0` (e.g. on separate CI/AWS VMs, in parallel) — and diff the two
`report.md` artifacts. The tool does not orchestrate both; only the `--version`
value changes between runs.

`run-scenario.sh` runs the sampler then `analyze/report.py`, producing `report.md`
(steady-state avg/peak of host CPU, RAM, disk, ingest rate, per-process split) —
the hardware-requirements deliverable. Re-run `report.py --run <dir>` standalone
to re-aggregate (e.g. with a different `--warmup`).

## Metrics captured (per minute)

**Host (the sizing deliverable):** total CPU %, load, RAM used (GB + %), swap,
disk used, disk read/write rate; per-process CPU + RAM split across
`wazuh-indexer` / `wazuh-manager` / `wazuh-dashboard`.
**Indexer:** ingest rate + latency, indexing pressure, write/search thread-pool
queue + rejections, JVM heap %, GC count/time, segments, merge/refresh/flush,
store size, doc count. See [metrics/sampler.py](metrics/sampler.py) for the exact fields.

## Requirements

- Python 3.9+ with `requests` (already used by the repo's event generators).
- `psutil` on the host for host/process metrics in Tracks A/B (`pip install psutil`
  or `apt install python3-psutil`; the Vagrant env installs it automatically).
- Tracks B/C: `opensearch-benchmark` (`pip install opensearch-benchmark`).
- Track C: `node_exporter` on the indexer host (installed by `setup-node-exporter.sh`)
  and Docker on the monitor host for Prometheus + Grafana (`setup-monitor.sh`).
