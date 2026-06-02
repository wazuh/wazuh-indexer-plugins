# Wazuh Indexer — Performance Testing

Tooling to measure Wazuh Indexer performance and catch regressions. Two complementary tracks share a single OpenTelemetry-based
measurement layer:

| Track | Load source | Purpose |
|-------|-------------|---------|
| **A — Real-world (primary)** | 2 Wazuh agents (beta2) running FIM + Logcollector loops against an AIO deployment | Behavior under realistic SIEM ingest |
| **B — Synthetic (baseline)** | OpenSearch Benchmark with a custom Wazuh workload | Deterministic, repeatable numbers for version/config comparison |

The **measurement layer** ([metrics/sampler.py](metrics/sampler.py)) polls the
indexer's `_nodes/stats` + `_cluster/stats` once per minute and emits per-minute
CSV/NDJSON **and** (optionally) OpenTelemetry OTLP metrics.

## Primary scenario

- **Topology:** AIO (manager + indexer + dashboard) + 2 agents (beta2), FIM + Logcollector loops.
- **Sizing:** 16 GB RAM, 8 CPU cores.
- **Duration:** 60 minutes — **Sampling:** every 1 minute (60 samples).

## Layout

```
tools/performance/
├── metrics/sampler.py              # per-minute stats sampler → CSV/NDJSON (+ optional OTLP)
├── otel/otel-collector-config.yml  # reference Collector config (OTLP in → your backend)
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
| `aio` | manager + indexer + dashboard | 16 GB / 8 vCPU | 192.168.56.20 |
| `agent-1` | Wazuh agent (FIM + Logcollector) | 2 GB / 2 vCPU | 192.168.56.21 |
| `agent-2` | Wazuh agent (FIM + Logcollector) | 2 GB / 2 vCPU | 192.168.56.22 |

```bash
cd vagrant
vagrant up                          # provisions AIO + 2 agents from the staging artifacts
./run-test.sh --duration 3600 --interval 60 --rate 10
# → results in tools/performance/runs/aio-run/ (synced from the AIO VM)
```

`run-test.sh` starts the FIM + Logcollector loops on both agents and runs the
per-minute measurement window on the AIO. The indexer admin password is captured
during provisioning to `runs/admin-password.txt` (or pass `--password`).

> **Host requirements:** ~20 GB free RAM, 12 vCPU. Provider defaults to `libvirt`
> (matches `tools/test-cluster`); box defaults to Ubuntu 24.04. Override for other
> hosts, e.g. Apple Silicon: `PERF_PROVIDER=parallels PERF_BOX=bento/ubuntu-24.04 vagrant up`.
> A lighter alternative for Track B only (indexer in isolation) is Docker Compose;
> the full agent→manager→indexer path needs VMs.

### Manual hosts (without Vagrant)

The same scripts run on any bare host. On the AIO host:

```bash
sudo ./scenario/setup-aio.sh        # downloads artifacts + assistant via curl, installs AIO
# override source: --artifacts-url https://packages-staging.xdrsiem.wazuh.info/.../artifact_urls_5.0.0-latest.yaml
```

On each agent host (downloads the agent package, enrolls, configures FIM/Logcollector):

```bash
sudo ./scenario/setup-agent.sh --manager <aio-ip>
./scenario/agent-load.sh --duration 3600          # start the load loop
```

Then run the measurement window from any host that can reach the indexer:

```bash
./scenario/run-scenario.sh \
  --endpoint https://<aio-ip>:9200 --user admin --password <pass> \
     --duration 3600 --interval 60 --insecure --out ./runs/aio-baseline
   ```

   Produces `runs/aio-baseline/metrics.csv`, `metrics.ndjson`, and
   `run-metadata.json` (ISO start/stop — use it to annotate your dashboards).

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

## Metrics captured (per minute)

Ingest (rate, latency, indexing pressure, write thread-pool queue + rejections),
JVM (heap %, GC count/time), search (query rate, latency, search pool rejections),
segments/merge (count, merge/refresh/flush time), host (CPU, load, disk, I/O).
See [metrics/sampler.py](metrics/sampler.py) for the exact field list.

## Requirements

- Python 3.9+ with `requests` (already used by the repo's event generators).
- Optional OTLP export: `pip install opentelemetry-sdk opentelemetry-exporter-otlp`.
- Track B: `opensearch-benchmark` installed (`pip install opensearch-benchmark`).
