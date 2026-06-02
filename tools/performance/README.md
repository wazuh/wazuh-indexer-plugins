# Wazuh Indexer — Performance Testing

Tooling to measure Wazuh Indexer performance and catch regressions. Two complementary tracks share one measurement layer:

| Track | Load source | Purpose |
|-------|-------------|---------|
| **A — Real-world (primary)** | 2 Wazuh agents running FIM + Logcollector loops against an AIO deployment | Behavior under realistic SIEM ingest; hardware requirements |
| **B — Synthetic (baseline)** | OpenSearch Benchmark with a custom Wazuh workload | Deterministic, repeatable numbers for version/config comparison |

The **measurement layer** ([metrics/sampler.py](metrics/sampler.py)) runs on the
AIO host, polls the indexer's `_nodes/stats` + `_cluster/stats` and the host's
own CPU/RAM/disk once per minute, and emits per-minute CSV/NDJSON.

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
│   ├── Vagrantfile                 # self-contained env: 1 AIO VM + 2 agent VMs (Ubuntu 24.04)
│   └── run-test.sh                 # host-side orchestrator: load loops + measurement window
├── scenario/
│   ├── setup-aio.sh                # install AIO from official artifacts (curl + installation assistant)
│   ├── setup-agent.sh              # install + enroll an agent, configure FIM/Logcollector paths
│   ├── run-scenario.sh             # 60-min orchestrator: marks window, runs sampler
│   └── agent-load.sh               # runs on each agent: FIM + Logcollector loops
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
# → results in tools/performance/runs/aio-run/ (synced from the AIO VM)
```

`run-test.sh` starts the FIM + Logcollector loops on both agents and runs the
per-minute measurement window on the AIO. The indexer admin password is captured
during provisioning to `runs/admin-password.txt` (or pass `--password`).

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

## Track B — synthetic benchmark

```bash
# 1. Generate index body + corpus from the real events template + WCS generator
python3 benchmark/gen-corpora.py --docs 1000000

# 2. Run the benchmark against an isolated indexer
./benchmark/run-osb.sh --target https://<indexer-ip>:9200 --user admin --password <pass>
```

`run-osb.sh` also runs `metrics/sampler.py` for the duration of the test, so the
same per-minute series is captured alongside OSB's own report. Re-run on a
candidate build and `opensearch-benchmark compare` the two test executions.

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
- `psutil` on the AIO host for host/process metrics (`pip install psutil` or
  `apt install python3-psutil`; the Vagrant AIO installs it automatically).
- Track B: `opensearch-benchmark` installed (`pip install opensearch-benchmark`).
