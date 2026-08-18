# Wazuh Indexer 5.0 memory/throughput settings catalog

Ground truth as of 2026-08-06. Every entry below was verified against the
actual registered `Setting<?>` object in source (not just documentation) —
file:line references are given so this can be re-verified if the code moves.
Cross-checked against `docs/ref/modules/*/configuration.md`; disagreements
are called out explicitly.

Legend: **Dynamic** = live-tunable via `PUT _cluster/settings`, no restart.
**Static** = `NodeScope` only, requires a value in `opensearch.yml`/
`opensearch.prod.yml` at boot; a live API call has no effect.

---

## content-manager (`wazuh-indexer-plugins/plugins/content-manager`)

Settings file: `plugins/content-manager/src/main/java/com/wazuh/contentmanager/settings/PluginSettings.java`.
Registered in `ContentManagerPlugin.java:889-912` (`getSettings()`).

**All bulk/concurrency settings here are Static, despite being informally
described as "semaphore-controlled" — the semaphore size is fixed once at
JVM startup.**

| Setting | Default | Range | Dynamic? | Recommended |
|---|---|---|---|---|
| `plugins.content_manager.max_items_per_bulk` | 999 | 10–999 | Static | 200 |
| `plugins.content_manager.max_bulk_bytes` | 5,242,880 (5MB) | 1MB–100MB | Static | 2MB |
| `plugins.content_manager.max_concurrent_bulks` | 5 | 1–5 | Static | 2 |
| `plugins.content_manager.client.timeout` | 10s | 10–50s | Static | unchanged |
| `plugins.content_manager.catalog.sync_interval` | 60min | 10–1440min | Static | 240min |
| `plugins.content_manager.catalog.update_on_start` | true | — | Static | unchanged |
| `plugins.content_manager.catalog.update_on_schedule` | true | — | Static | unchanged |
| `plugins.content_manager.catalog.create_detectors` | true | — | Static | unchanged (setting `false` stops *new* detector creation from CTI sync, but does not remove existing detectors — useful lever if fan-out ever needs to be capped at the source) |
| `plugins.content_manager.pit_keepalive` | 120s | 60–600s | Static | 60s (floor) |
| `plugins.content_manager.max_integrations` | 100 | ≥0 | **Dynamic** | unchanged |
| `plugins.content_manager.max_decoders` | 200 | ≥0 | **Dynamic** | unchanged |
| `plugins.content_manager.max_rules` | 200 | ≥0 | **Dynamic** | unchanged |
| `plugins.content_manager.max_kvdbs` | 100 | ≥0 | **Dynamic** | unchanged |
| `plugins.content_manager.max_filters` | 100 | ≥0 | **Dynamic** | unchanged |
| `plugins.content_manager.wazuh_uid` | `""` | — | **Dynamic** | not memory-relevant; **undocumented anywhere in `docs/ref`** — flag as a doc gap if updating docs |

**Detector schedule interval** — there is no registered `Setting<?>` for
this. `DetectorFactory.createDetector()` (security-analytics repo) takes
`interval` as a parameter; the value is sourced per-integration from the CTI
catalog document's `detector.interval` field
(`SecurityAnalyticsServiceImpl.java:277-317` in content-manager), with a
hardcoded fallback default of 2 minutes and hardcoded bounds [1, 10080]
minutes as Java literals — not overridable via `opensearch.yml` or the
Cluster Settings API. Changing the fallback/bounds requires a code change.

---

## security-analytics (`wazuh-indexer-security-analytics`)

Settings file: `src/main/java/org/opensearch/securityanalytics/settings/SecurityAnalyticsSettings.java`.
Registered in `SecurityAnalyticsPlugin.java:437-475` (`getSettings()`). 37 of
38 settings here are Dynamic — this is by far the most live-tunable plugin.

### Enrichment pipeline (`WazuhEnrichedFindingService.java`)

| Setting | Default | Range | Dynamic? | Recommended |
|---|---|---|---|---|
| `plugins.security_analytics.enriched_findings_bulk_size` | 100 | 10–1000 | Dynamic | 25 (pair with flush_interval below) |
| `plugins.security_analytics.enriched_findings_max_in_flight` | 5 | 1–10 | Dynamic | 2 — **caveat: the queue feeding these chains is unbounded, see SKILL.md "Known traps"** |
| `plugins.security_analytics.enriched_findings_flush_interval` | 5s | 1–60s | Dynamic | 2s (pair with bulk_size above) |
| `plugins.security_analytics.enriched_findings_enrich_batch_size` | 100 | 1–1000 | Dynamic | 25 |
| `plugins.security_analytics.enriched_findings_rule_cache_max_size` | 10000 | ≥0 | **Static** (only `NodeScope`, no update consumer) | 1000 — LRU of *full rule documents* incl. compliance/MITRE maps, the largest per-entry cost in this catalog |
| `plugins.security_analytics.enriched_findings_index_enabled` | true | — | Dynamic | unchanged (kill switch for the whole enrichment pipeline if ever needed) |

### Correlation backlog / backpressure (`TransportCorrelateFindingAction.java`)

| Setting | Default | Range | Dynamic? | Recommended |
|---|---|---|---|---|
| `plugins.security_analytics.correlation.max_in_flight_findings` | 50 | 1–1000 | Dynamic | 10 (5× the VM's 2 vCPU count) |
| `plugins.security_analytics.correlation.max_pending_findings` | 10000 | 1–1,000,000 | Dynamic | 2000 |
| `plugins.security_analytics.correlation.events_backpressure.enabled` | true | — | Dynamic | **must stay true** — see SKILL.md guardrails |
| `plugins.security_analytics.correlation.events_backpressure.high_watermark_percent` | 100 | 1–100 | Dynamic | 80 (keep ≥30pt gap over low watermark) |
| `plugins.security_analytics.correlation.events_backpressure.low_watermark_percent` | 60 | 0–99 | Dynamic | 40 |
| `plugins.security_analytics.correlation.detector_cache_ttl` | 5m | ≥0s | Dynamic | **raise to 10-15m**, do not lower — see SKILL.md "Known traps" |
| `plugins.security_analytics.correlation.metadata_cache_ttl` | 5m | ≥0s | Dynamic | **raise to 10-15m**, do not lower |
| `plugins.security_analytics.correlation_time_window` | 5m | ≥0s | Dynamic | unchanged (not primarily a memory setting) |

### Other

| Setting | Default | Range | Dynamic? | Recommended |
|---|---|---|---|---|
| `plugins.security_analytics.enable_detectors_with_dedicated_query_indices` | true | — | Dynamic | false — **zero-cost, confirmed dead end for the current 45-shard SAP finding, see SKILL.md "Known traps"; set anyway as a guardrail against future multi-detector-per-logtype proliferation** |
| `plugins.security_analytics.max_detectors` | 10 | ≥0 | Dynamic | unchanged — CTI/content-manager-created detectors are exempt from this cap, so it doesn't bound the fan-out problem |
| `plugins.security_analytics.max_rules_per_detector` | 50 | ≥0 | Dynamic | unchanged |
| `plugins.security_analytics.max_case_management_bulk_size` | 10 | 0–100 | Dynamic | unchanged |
| `plugins.alerting.alert_findings_indexing_batch_size` (base Alerting plugin, distinct pipeline) | 1000 | — | Dynamic | 500 |
| History-index rollover/retention (`alert_history_*`, `finding_history_*`, `correlation_history_*`) | `_max_docs`=1000, `_rollover_period`=12h, `_max_age`=30d, `_retention_period`=60d | — | Dynamic | shorten retention if history-index growth becomes a factor; not the primary lever for the current regression |

**Doc note**: `docs/ref/modules/security-analytics/index.md` has an internal
self-contradiction — states `max_rules_per_detector` default is 50 in one
place, then refers to "the 100-rule-per-detector limit" for the same setting
later in the same file. Trust the registered default (50) over either prose
mention until the doc is fixed.

---

## wazuh-indexer-alerting (`alerting/src/main/kotlin/org/opensearch/alerting/settings/AlertingSettings.kt`)

Confirmed by direct source read — **all settings below are `Dynamic` +
`NodeScope`**. These govern the doc-level-monitor/percolate-query mechanism
that Security Analytics detectors actually run on — this is the most direct
lever on the detector-fan-out blast radius.

| Setting | Default | Range | Recommended |
|---|---|---|---|
| `plugins.alerting.monitor.percolate_query_max_num_docs_in_memory` | 50000 | min 1000 | 5000 |
| `plugins.alerting.monitor.percolate_query_docs_size_memory_percentage_limit` | 10 | 0–100 | 4 (≈39MB on the VM's 978MB heap, vs. ≈98MB at default — meaningful margin against an 80%+-loaded parent breaker) |
| `plugins.alerting.monitor.doc_level_monitor_shard_fetch_size` | 10000 | 1–10000 | 2000 |
| `plugins.alerting.monitor.doc_level_monitor_fan_out_nodes` | 1000 | — | unchanged (low relevance on a single-node deployment) |
| `plugins.alerting.monitor.doc_level_monitor_fanout_max_duration` | 3m | — | 1m |
| `plugins.alerting.monitor.doc_level_monitor_execution_max_duration` | 4m | — | 2m |

**Possible min()-gated pair, unverified**: `percolate_query_max_num_docs_in_memory`
(count cap) and `percolate_query_docs_size_memory_percentage_limit` (byte-%
cap) may both gate the same in-memory percolate buffer, whichever triggers
first. Confirm in `TransportDocLevelMonitorFanOutAction.kt`/
`DocumentLevelMonitorRunner.kt` before treating a single-variable test of
either as fully isolated — if verified as a pair, treat like the
`enriched_findings_bulk_size`/`_flush_interval` pair (test together, not
separately).

---

## setup plugin (`wazuh-indexer-plugins/plugins/setup`)

Settings file: `plugins/setup/src/main/java/com/wazuh/setup/settings/PluginSettings.java`.
Exactly 3 registered settings, confirmed 1:1 against `SetupPlugin.java:254-257`
(`getSettings()`) — **no memory-relevant live-tunable setting exists in this
plugin at all.**

| Setting | Default | Dynamic? | Memory-relevant? |
|---|---|---|---|
| `plugins.setup.timeout` | 30s | Static | No |
| `plugins.setup.backoff` | 15s | Static | No |
| `plugins.setup.settings_update.enabled` | true | Static | No (endpoint access-control toggle) |

**Everything else memory-relevant in this plugin is hardcoded, not a
`Setting<?>`, and requires a code change — see SKILL.md "Known traps":**
`number_of_shards`/`number_of_replicas` (both `1`/`0` in every bundled
template JSON), ISM rollover thresholds (`min_doc_count: 200000000`,
`min_primary_shard_size: 20gb`, per-stream `min_index_age`: events=1h,
findings=90d, raw=10m, active-responses=3d, metrics=30d), and
`index.refresh_interval: 2s` on events/findings/raw streams (undocumented in
both `docs/ref` and `docs/dev`).

A separate, non-`Setting<?>` mechanism exists: `plugins.setup.settings` — a
document (not an OpenSearch `Setting`) in the `.wazuh-settings` index,
exposing `engine.index_raw_events` (default `false`) via
`PUT /_plugins/_setup/settings`. Memory-relevant (toggles raw-event
ingestion into `wazuh-events-raw-v5`) but architecturally outside the
Cluster-Settings-API catalog.

---

## OpenSearch core (not Wazuh-specific)

Confirmed live on the real VM (see SKILL.md's "Related artifacts" for
access) as of 2026-08-06:

| Setting | Live value on VM | Notes |
|---|---|---|
| `indices.breaker.total.limit` | 80% (upstream default 95%) | Set in `opensearch.yml` on the VM already; `use_real_memory: true` |
| `indexing_pressure.memory.limit` | 10% | Set in `opensearch.yml` already |
| `search_backpressure.mode` | enforced | Set in `opensearch.yml` already; node-duress thresholds (`cpu_threshold=0.9`, `heap_threshold=0.7`) are still defaults, unverified whether tuning them helps |
| `indices.memory.index_buffer_size` | 10% (~98MB), default | **Static, `NodeScope`-only** — confirmed in `IndexingMemoryController.java`. Untuned; halving to 5% is a genuine, previously-unexplored lever |
| Thread pools (`thread_pool.write/search/bulk.*`) | no overrides, defaults apply | **Not yet given the same verification depth as the settings above** — named explicitly in the team issue, still needs a dedicated pass before testing |
| Circuit breakers other than `total` (`fielddata.limit`, `request.limit`, `network.breaker.inflight_requests.limit`) | only `total.limit` confirmed live so far | Same — needs its own verification pass |
| Shard indexing backpressure | not yet checked | Distinct mechanism from Security Analytics' `events_backpressure` — do not conflate the two |
| Cluster-manager task throttling | not yet checked | Named in the team issue |

The team issue links the OpenSearch documentation-website pages for
cluster-manager task throttling, shard indexing settings/backpressure, and
search backpressure as the source for valid ranges and starting points for
this section — use those, don't invent settings that don't exist in the
installed OpenSearch 3.6.0 distribution.

---

## Confirmed dead end (do not re-test without new evidence)

`plugins.security_analytics.enable_detectors_with_dedicated_query_indices`
was hypothesized as the fix for a live-VM finding of 45 of 92 total shards
(49%) belonging to per-log-type `.opensearch-sap-<logtype>-detectors-queries-
optimized-*` / `.opensearch-sap-<logtype>-alerts` index pairs (21 log
types). Traced directly in `TransportIndexDetectorAction.java`:

- Only consulted in `createDetector()` and `onGetResponse()` (detector
  update); the update path has an explicit early-out that preserves an
  existing "optimized" index verbatim regardless of the setting's current
  value.
- Only ever changes the *query* index name/count. The `*-alerts` index is
  set unconditionally in both branches, never touched by this setting.
- The real deployment has exactly one detector per log type today — in a
  strict 1:1 world, the "shared" mode produces the same index count as the
  "dedicated" mode, just without a UUID suffix.

**Verdict**: toggling this setting will not reduce the 45-shard count on
this deployment's topology. The actual fix requires a content-manager/
security-analytics code change (e.g. only create detector indices for log
types actually ingested) — file as a separate follow-up issue per the team
issue's own scoping constraint, don't keep re-testing this setting expecting
a different result.
