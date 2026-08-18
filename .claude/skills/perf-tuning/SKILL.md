---
name: perf-tuning
description: Reduce or validate Wazuh Indexer 5.0's memory/CPU/GC footprint by tuning existing OpenSearch/plugin settings, or by changing index/shard topology. Covers the settings catalog (content-manager, security-analytics, alerting, setup, OpenSearch core), the Docker load-test harness and the real vagrant VM, one-variable-at-a-time attribution methodology, and known traps (detector fan-out, the SAP dedicated-query-index dead end, unbounded queues). Use when asked to investigate, reduce, or test Wazuh Indexer memory usage, heap pressure, circuit breaker trips, or shard/index count, or to tune throughput-vs-memory tradeoffs.
---

# Wazuh Indexer 5.0 performance tuning

This skill captures everything learned from two rounds of memory investigation:
a shard-consolidation PoC that backfired, and the settings-tuning follow-up it
triggered. Read this before touching any setting or index topology — several
"obvious" fixes here are confirmed dead ends, and re-discovering that costs
hours of load-test time.

## Related artifacts

- **Settings catalog**: `.claude/skills/perf-tuning/SETTINGS_CATALOG.md` —
  every candidate setting across content-manager, security-analytics,
  alerting, and setup, with confirmed defaults, ranges, dynamic/static status,
  and recommended test values. Cross-checked against actual registered
  `Setting<?>` objects in source, not just docs — trust this over
  `docs/ref/modules/*/configuration.md` if the two ever disagree until the
  docs are updated.
- **Team issue**: an internal issue titled "Indexer performance settings
  tuning" is the authoritative scope/requirements doc for the current
  settings-tuning round (not checked into this repo — ask the team for the
  current copy). This skill operationalizes that issue; don't diverge from
  its constraints (see "Guardrails" below).
- **Load-test harness**: the internal `indexer_metrics` tool (not part of
  this repo — ask the team for access) — `run-heap-analysis.sh` is the
  primary script for every attribution test in this skill. See "Running a
  test" below.
- **Real VM**: an internal Vagrant box representative of a small production
  deployment (not part of this repo — ask the team for access). Real specs:
  2 vCPU / 3.8GB RAM / ~978MB JVM heap (auto-sized to 25% of RAM) —
  **roughly half the heap of every Docker test**. Any percentage-of-heap
  setting behaves materially differently here than in Docker; see "Docker
  vs. VM" below.

## Mental model: three mechanisms, don't conflate them

Every memory-relevant setting or architectural choice bounds exactly one of
these. Attributing an observed effect to the wrong mechanism is the single
most common way to draw a wrong conclusion from a test run.

1. **Blast-radius / peak-memory-during-fanout** — how much memory is held
   *concurrently* while detectors evaluate a batch of events (percolate-query
   caps, enrichment max-in-flight, correlation max-in-flight/backpressure).
2. **Retained state** — steady-state resident bytes independent of any single
   burst (caches, history retention, sync frequency).
3. **Structural shard count** — number of Lucene index/shard objects resident
   regardless of load (index/stream topology, per-log-type index creation).

A setting from one bucket will not explain a delta that's actually coming
from another. If a change to a blast-radius setting doesn't move the needle,
check retained-state and structural explanations before concluding "no
effect."

## Known traps — read before proposing a fix

These cost real investigation time to discover. Don't re-derive them.

- **Merging index topology can *increase* memory, not reduce it.** The
  shard-consolidation PoC (merging 8 per-category `wazuh-events-v5`/
  `wazuh-findings-v5` streams into 2 unified ones) cut index/shard count
  exactly as designed (-14 indices) but increased avg heap +18.5%, CPU avg
  +142% relative, GC activity avg +274% relative — because OpenSearch
  Security Analytics scopes detectors purely by **which index they read**,
  with **no query-level category filter**. Once all categories share one
  index, every detector evaluates every event instead of just the one that
  used to see real traffic. Any future index-merge proposal must account for
  this before being trusted — check whether detectors/monitors are scoped by
  index name anywhere in the merge's blast radius, not just whether shard
  count drops.
- **`enable_detectors_with_dedicated_query_indices` looks like the fix for
  per-log-type shard proliferation. It usually isn't.** Confirmed via direct
  tracing of `TransportIndexDetectorAction.java` (in
  `wazuh-indexer-security-analytics`): this setting only reduces index count
  when *multiple* detectors share one log type. If the deployment has one
  detector per log type (check via `_cat/indices/.opensearch-sap-*` — count
  should equal log-type count), toggling this setting produces the same
  index count either way, just a different name. It also never touches the
  `*-alerts` index (set unconditionally), and isn't retroactive for existing
  detectors — flipping it live changes nothing until a detector is
  deleted+recreated. Verify the 1:1 assumption on the actual deployment
  before trusting this analysis; it could change if a future log-type model
  allows multiple detectors per type.
- **Content-manager's bulk/concurrency settings are NOT dynamic** — despite
  being informally described as "semaphore-controlled," `max_items_per_bulk`,
  `max_bulk_bytes`, `max_concurrent_bulks`, `client.timeout` are `NodeScope`
  only in code, no `Dynamic` property, no `addSettingsUpdateConsumer` wiring.
  They can only be changed by baking a new value into the node's static
  config (`opensearch.yml`/`opensearch.prod.yml`) and restarting — a live
  `PUT _cluster/settings` will not work and will silently have no effect on
  the running semaphore size.
- **The enrichment findings queue is unbounded.** `WazuhEnrichedFindingService`'s
  `findingsQueue` is a plain `ConcurrentLinkedQueue` with no size cap.
  Lowering `enriched_findings_max_in_flight` narrows concurrent *processing*
  width, but does not bound total backlog bytes — if inflow outpaces the
  now-slower drain rate, the queue itself becomes the new memory sink instead
  of the in-flight chains. Always watch queue depth (or proxy it via
  findings-indexed-vs-consumed lag), not just heap, when tuning this setting.
- **Lowering correlation cache TTLs is usually the wrong move.**
  `correlation.detector_cache_ttl` / `metadata_cache_ttl` cache small
  ID→object lookups (monitor-id→detector, logtype/rule lists), not full
  documents. Zeroing them mainly adds a `size: 10000` search query per
  finding — trading a small heap saving for real CPU/search-thread-pool load,
  which is usually the *scarcer* resource on a small VM (2 vCPU). Prefer
  raising these TTLs over lowering them unless a specific measurement shows
  otherwise.
- **`events_backpressure` must stay enabled.** Silent finding-shedding via
  `correlation.max_pending_findings` only happens when
  `events_backpressure.enabled` is `false`. This mechanism is deliberate,
  already-shipped prior work (team issue references GitHub #1683) — assert
  it's `true` at the start of every test run as a guardrail against settings
  drift, don't tune it away while chasing memory.
- **The Docker harness's `_cat/indices` capture is blind to hidden/system
  indices.** `tools/heap-monitor.sh`'s `capture_index_stats()` calls
  `_cat/indices` with no `expand_wildcards`, so `.opensearch-sap-*` and any
  other dot-prefixed index is invisible in every report the harness
  produces. If a fix targets shard/index count for one of these families,
  patch the capture call (`&expand_wildcards=all`) first, or the harness
  will report success/failure blind to the thing you're actually testing.
- **The heap-monitor's elapsed clock starts when the container becomes
  healthy, not when the load generator actually starts.** `--push`
  (rebuilds+restarts the indexer service) and `--validate` (runs the real
  CTI-sync pipeline that creates detectors) both happen *after* the initial
  healthcheck but *before* the tester container starts. Early
  `index_stats`/histogram snapshots can land mid-setup or even mid-restart
  (indexer briefly unreachable), reading as "0 documents" when real data
  exists once setup finishes. If you're using `run-heap-analysis.sh` and see
  suspiciously empty early snapshots, this is why — check `capture_index_stats`
  in `tools/heap-monitor.sh` for a retry-on-empty-response guard and confirm
  the monitor's start is gated on the load generator actually running, not
  just on the container being healthy.
- **ISM policy thresholds and index template settings (shard count, replica
  count, `refresh_interval`) for setup-plugin-owned streams are hardcoded in
  bundled JSON resources, not registered `Setting<?>` objects, and are
  actively reasserted on every cluster-manager election.**
  `IndexStateManagement.indexPolicy()` upserts the ISM policy document on
  every election; `StreamIndex.createTemplate()` overwrites the index
  template on every boot. A manual edit via the ISM/template API will be
  silently reverted — there is no live-settings path here, only a code
  change to the bundled resources under `plugins/setup/src/main/resources/`.

## Docker vs. the real VM — division of labor

Don't default to "test everything on Docker" or "test everything on the VM."
Each is right for different things.

| Use Docker for | Use the VM for |
|---|---|
| The main one-variable-at-a-time attribution sweep — controlled, disposable, fast-iterating | Percentage-of-heap settings (e.g. `percolate_query_docs_size_memory_percentage_limit`) — 10% is ≈205MB on Docker's 2GB heap vs. ≈98MB on the VM's 978MB heap; Docker cannot predict VM behavior for these |
| JFR allocation recordings, class histograms, full heap dumps | Settings persistence after a real service restart (`_cluster/settings?include_defaults=true` diffed before/after) |
| Anything needing many repeated, cheap, from-scratch runs | Multi-hour slow-leak detection (Docker's ~20 min runs structurally cannot catch this — poll `_nodes/stats/jvm,breaker` every few minutes over hours) |
| | Startup/config error checks after a settings change (`grep -iE "error|exception|warn"` in the cluster log around a restart) |
| | Confirmatory (not exhaustive) spot-checks of a Docker finding against real-world scale/constraints before calling it final |

**Never run two Docker containers concurrently on the same host** for this
work — resource contention between them reintroduces exactly the kind of
unattributable confound this methodology exists to avoid, one level down.

## Running a test

```bash
cd <path-to-indexer_metrics>
./run-heap-analysis.sh --package <deb> --push --validate --keep-up \
  --duration <seconds> --title <descriptive-title>
```

- `--push` rebuilds and installs the plugins; `--validate` runs the real
  content-manager CTI-sync pipeline (this is what creates the ~21 real
  detectors — don't skip it if the test needs realistic detector fan-out).
- `--keep-up` leaves the container running afterward for `docker exec`
  inspection — use this when you need to apply a live `_cluster/settings`
  change and re-run without re-paying the push+validate cost.
- Match `--jvm-mem`/`--container-cpus`/`--container-mem` to the real VM's
  specs (978m / 2 / 3800m) when the goal is a VM-representative baseline,
  not the tool's own defaults (2g / 4 / 4g) — every prior comparison used the
  more generous defaults, which understates real-world pressure.
- Output lands in `output/<title>_<timestamp>/`, including `heap_analysis.md`
  (the unified report: heap timeline, per-plugin index store size, class
  histogram, JFR allocation call trees) and `metrics.csv`/`chart.png`.

For one-variable-at-a-time attribution: bake the setting under test into
`docker/opensearch.yml` before each run (uniform for both dynamic and static
settings, so results are comparable within Docker) — reserve exercising the
live `PUT _cluster/settings` API path specifically for proving a setting is
genuinely live-tunable, which matters most on the VM.

## Methodology for a settings round

1. **Two default-baseline runs back to back first**, to establish the noise
   floor. Any candidate delta smaller than ~2x that spread is inconclusive,
   not "no effect."
2. **One unit (normally one setting) changed per run relative to the fixed
   baseline.** Group two settings into one run only when there's a citable,
   code-level reason isolating them separately would be uninformative (e.g.
   two settings gate the same flush decision via a `min()` of both) — never
   for convenience.
3. **Triage by mechanism**: test blast-radius settings first (most directly
   tied to detector-fanout-shaped regressions), then retained-state, then
   structural/dead-end confirmations.
4. **Success criteria** (anchor to the actual regression this round follows
   up on unless the team specifies otherwise): avg heap reduced ≥5% vs.
   baseline; peak heap not increased more than +2%; GC activity **not
   increased at all**; effective throughput degradation ≤15%; no
   correctness regression (see below); no OOM/crash — always overrides
   everything else.
5. **Instrument for correctness, not just memory.** A setting that narrows a
   buffer without reducing the work arriving at it converts "held in memory"
   into "processed in smaller, more frequent operations" — pair every memory
   metric with an operation-frequency/cost proxy (CPU-seconds per event,
   thread-pool stats, JFR call-tree frame counts). Diff findings-index doc
   counts against source-event counts at run end to catch silent shedding.
   Track `_nodes/stats/breaker` on every run, not just heap-used-MB — a run
   that "wins" on heap but pushes a circuit breaker closer to its trip point
   is not an unqualified success.

## Guardrails (from the team issue — do not violate)

- This is a **configuration/measurement exercise**. Only propose a code
  change if testing reveals a setting that's missing, unbounded, or should
  be exposed but isn't — file that as a **separate follow-up issue**, don't
  bundle it into a settings-tuning deliverable.
- Any changed default must stay within the **already-documented valid
  range** for a dynamic setting. If a range itself needs widening, say so
  explicitly rather than silently exceeding it.
- **Stability floor is absolute**: any configuration that OOMs or crashes
  under sustained heavy load (not just a short burst) is unsafe and excluded
  outright, regardless of throughput gains.
- Prioritize memory/stability over throughput whenever they trade off.
- Persist adopted defaults either in code or in
  `wazuh-indexer/distribution/src/config/opensearch.prod.yml` (the default
  config shipped in new packages) — a live `PUT _cluster/settings` call is
  for testing only and does not survive a fresh install.
