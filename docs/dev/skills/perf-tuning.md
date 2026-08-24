# Performance tuning

The `perf-tuning` skill reduces or validates Wazuh Indexer 5.0's memory, CPU, and GC footprint by tuning existing OpenSearch and plugin settings, or by changing index/shard topology. It covers content-manager, security-analytics, alerting, and setup settings, plus OpenSearch core settings such as thread pools, circuit breakers, and indexing buffers.

## Mental model

The skill separates every memory-relevant setting into one of three mechanisms: blast radius (peak memory held during a fan-out), retained state (steady-state resident bytes independent of any single burst), and structural shard count (Lucene index/shard objects resident regardless of load). Attributing an observed effect to the wrong mechanism is the most common way to draw a wrong conclusion from a load test.

## Known traps

The skill documents confirmed dead ends and counterintuitive findings from prior investigation rounds — for example, a shard-consolidation attempt that *increased* memory rather than reducing it, because Security Analytics scopes detectors purely by which index they read, and why zeroing the correlation cache TTLs can trade heap for CPU/search-thread-pool load on a small VM instead of saving memory. See `SKILL.md` for the full list — re-deriving these costs real load-test time.

## Related artifacts

- `SKILL.md` — methodology, known traps, and the Docker-versus-VM division of labor for running a test.
- `SETTINGS_CATALOG.md` — every candidate setting across content-manager, security-analytics, alerting, and setup, cross-checked against the actual registered `Setting<?>` objects in source, with confirmed defaults, ranges, dynamic/static status, and recommended test values.

## Usage

Invoke when asked to investigate, reduce, or test Wazuh Indexer memory usage, heap pressure, circuit breaker trips, or shard/index count, or to tune throughput-versus-memory tradeoffs. The skill relies on an internal load-test harness and VM that aren't part of this repository — see `SKILL.md`'s "Related artifacts" section for access.
