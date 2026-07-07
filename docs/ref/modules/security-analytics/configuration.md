<!-- // ANCHOR: settings-table -->
## Security Analytics settings

The Security Analytics plugin is configured through settings in `opensearch.yml`. All node-scope settings use the `plugins.security_analytics` prefix. Almost every setting is dynamic and can be changed at runtime via the Cluster Settings API.

| Setting                                                                       | Data type | Default value | Description                                                                                                                            |
| ----------------------------------------------------------------------------- | --------- | ------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `plugins.security_analytics.alert_finding_enabled`                            | Boolean   | `true`        | Enable rollover and retention management for the finding history indices                                                               |
| `plugins.security_analytics.alert_finding_max_docs`                           | Long      | `1000`        | **Deprecated.** Maximum document count for a finding history index before rollover. Minimum `0`                                        |
| `plugins.security_analytics.alert_finding_rollover_period`                    | Time      | `12h`         | How often the finding history rollover job runs                                                                                        |
| `plugins.security_analytics.alert_history_enabled`                            | Boolean   | `true`        | Enable rollover and retention management for the alert history indices                                                                 |
| `plugins.security_analytics.alert_history_max_age`                            | Time      | `30d`         | Maximum age of an alert history index before rollover                                                                                  |
| `plugins.security_analytics.alert_history_max_docs`                           | Long      | `1000`        | Maximum document count for an alert history index before rollover. Minimum `0`                                                         |
| `plugins.security_analytics.alert_history_retention_period`                   | Time      | `60d`         | Retention period after which alert history indices are deleted                                                                         |
| `plugins.security_analytics.alert_history_rollover_period`                    | Time      | `12h`         | How often the alert history rollover job runs                                                                                          |
| `plugins.security_analytics.auto_correlations_enabled`                        | Boolean   | `false`       | Automatically generate correlation rules from new findings                                                                             |
| `plugins.security_analytics.correlation.detector_cache_ttl`                   | Time      | `5m`          | TTL for the in-memory monitor-id to detector cache. Set to `0s` to disable the cache                                                   |
| `plugins.security_analytics.correlation.events_backpressure.enabled`          | Boolean   | `true`        | Write-block the events indices when the correlation backlog fills, so ingestion pauses and the backlog drains instead of the node running out of memory |
| `plugins.security_analytics.correlation.events_backpressure.high_watermark_percent` | Integer   | `100`         | Backlog level, as a percent of `correlation.max_pending_findings`, at or above which the events indices are write-blocked. Valid range: `1–100` |
| `plugins.security_analytics.correlation.events_backpressure.low_watermark_percent` | Integer   | `60`          | Backlog level, as a percent of `correlation.max_pending_findings`, at or below which the events-index write block is lifted. Valid range: `0–99` |
| `plugins.security_analytics.correlation.max_in_flight_findings`               | Integer   | `50`          | Maximum number of correlation pipelines running concurrently. Valid range: `1–1000`                                                    |
| `plugins.security_analytics.correlation.max_pending_findings`                 | Integer   | `10000`       | Maximum findings waiting for a free correlation slot. When the backlog is full, new findings are shed (correlation and enrichment skipped) so the node does not run out of memory under overload. Valid range: `1–1000000` |
| `plugins.security_analytics.correlation.metadata_cache_ttl`                   | Time      | `5m`          | TTL for the in-memory caches of log-type list and correlation rules by detector type. Set to `0s` to disable both caches               |
| `plugins.security_analytics.correlation_history_max_age`                      | Time      | `30d`         | Maximum age of a correlation history index before rollover                                                                             |
| `plugins.security_analytics.correlation_history_max_docs`                     | Long      | `1000`        | Maximum document count for a correlation history index before rollover. Minimum `0`                                                    |
| `plugins.security_analytics.correlation_history_retention_period`             | Time      | `60d`         | Retention period after which correlation history indices are deleted                                                                   |
| `plugins.security_analytics.correlation_history_rollover_period`              | Time      | `12h`         | How often the correlation history rollover job runs                                                                                    |
| `plugins.security_analytics.correlation_time_window`                          | Time      | `5m`          | Time window used to group findings into correlations                                                                                   |
| `plugins.security_analytics.enable_detectors_with_dedicated_query_indices`    | Boolean   | `true`        | Create dedicated query indices for new detectors                                                                                       |
| `plugins.security_analytics.enable_workflow_usage`                            | Boolean   | `true`        | Use Alerting composite workflows when running detectors                                                                                |
| `plugins.security_analytics.enriched_findings_bulk_size`                      | Integer   | `100`         | Number of enriched findings buffered before a bulk index request is fired. Valid range: `10–1000`                                      |
| `plugins.security_analytics.enriched_findings_enrich_batch_size`              | Integer   | `100`         | Findings drained per in-flight permit; their source events are fetched in one combined MultiGet instead of one request per finding. Valid range: `1–1000` |
| `plugins.security_analytics.enriched_findings_flush_interval`                 | Integer   | `5`           | Seconds between periodic flushes of any leftover buffered enriched findings. Valid range: `1–60`                                       |
| `plugins.security_analytics.enriched_findings_index_enabled`                  | Boolean   | `true`        | Toggle the enriched findings pipeline (see [Architecture](architecture.md))                                                            |
| `plugins.security_analytics.enriched_findings_max_in_flight`                  | Integer   | `5`           | Maximum concurrent enrichment chains, to bound peak load on the transport layer. Valid range: `1–10`                                   |
| `plugins.security_analytics.enriched_findings_rule_cache_max_size`            | Integer   | `10000`       | Maximum rule-metadata entries cached in memory by the enrichment service. Minimum `0`. Static; requires a node restart to change       |
| `plugins.security_analytics.filter_by_backend_roles`                          | Boolean   | `false`       | Restrict access to detectors, rules, and findings based on the requester's backend roles                                               |
| `plugins.security_analytics.finding_history_max_age`                          | Time      | `30d`         | Maximum age of a finding history index before rollover                                                                                 |
| `plugins.security_analytics.finding_history_retention_period`                 | Time      | `60d`         | Retention period after which finding history indices are deleted                                                                       |
| `plugins.security_analytics.index_timeout`                                    | Time      | `60s`         | Timeout for Security Analytics index operations                                                                                        |
| `plugins.security_analytics.max_detectors`                                    | Integer   | `10`          | Maximum number of user-created detectors (Content Manager detectors do not count). Minimum `0`                                         |

<!-- // ANCHOR_END: settings-table -->

### History indices

Each history group (alerts, findings, correlations) is managed by an independent rollover job with the same five knobs: an enable toggle, a rollover period, a max age, a max document count, and a retention period after which old indices are deleted.

To tune retention for the alert history indices:

```yaml
# opensearch.yml
plugins.security_analytics.alert_history_enabled: true
plugins.security_analytics.alert_history_rollover_period: 12h
plugins.security_analytics.alert_history_max_age: 30d
plugins.security_analytics.alert_history_max_docs: 1000
plugins.security_analytics.alert_history_retention_period: 60d
```

The same pattern applies to finding history (`plugins.security_analytics.alert_finding_*`, `plugins.security_analytics.finding_history_*`), and correlation history (`plugins.security_analytics.correlation_history_*`).

> `plugins.security_analytics.alert_finding_max_docs` is deprecated. Configure finding history rollover through the other `finding_history_*` settings.

### Correlation tuning

The correlation engine runs after every matched finding and consults two in-memory caches plus a concurrency limiter:

```yaml
# opensearch.yml
plugins.security_analytics.correlation_time_window: 5m
plugins.security_analytics.auto_correlations_enabled: false
plugins.security_analytics.correlation.detector_cache_ttl: 5m
plugins.security_analytics.correlation.metadata_cache_ttl: 5m
plugins.security_analytics.correlation.max_in_flight_findings: 50
```

Both `detector_cache_ttl` and `metadata_cache_ttl` accept `0s` to disable the cache entirely, which forces a lookup against the corresponding system index on every finding. Lower `correlation.max_in_flight_findings` on resource-constrained nodes to bound peak demand on the search thread pool.
### Detector behavior

```yaml
# opensearch.yml
plugins.security_analytics.enable_detectors_with_dedicated_query_indices: true
plugins.security_analytics.enriched_findings_index_enabled: true
plugins.security_analytics.enable_workflow_usage: true
plugins.security_analytics.filter_by_backend_roles: false
```

Setting `enriched_findings_index_enabled` to `false` disables the Wazuh enriched findings pipeline described in [Architecture](architecture.md); raw SAP findings continue to be written to `.opensearch-sap-{category}-findings-*`, but no `wazuh-findings-v5-{category}*` documents are produced.

### Overload protection and enrichment throughput

Under sustained load, doc-level monitors publish findings faster than correlation and enrichment can process them. These settings bound that work so the node sheds or pauses load instead of running out of memory, and tune how efficiently the enrichment pipeline writes `wazuh-findings-v5-*`.

```yaml
# opensearch.yml
# Bound the correlation backlog
plugins.security_analytics.correlation.max_pending_findings: 10000

# Pause ingestion when the backlog fills, resume when it drains
plugins.security_analytics.correlation.events_backpressure.enabled: true
plugins.security_analytics.correlation.events_backpressure.high_watermark_percent: 100
plugins.security_analytics.correlation.events_backpressure.low_watermark_percent: 60

# Enrichment pipeline throughput
plugins.security_analytics.enriched_findings_bulk_size: 100
plugins.security_analytics.enriched_findings_enrich_batch_size: 100
plugins.security_analytics.enriched_findings_max_in_flight: 5
plugins.security_analytics.enriched_findings_flush_interval: 5
plugins.security_analytics.enriched_findings_rule_cache_max_size: 10000
```

Two independent overload guards act on the correlation backlog:

- `correlation.max_pending_findings` caps how many findings may wait for a free correlation slot (the slots themselves are limited by `correlation.max_in_flight_findings`). When the backlog is full and `events_backpressure` is disabled, extra findings are shed, so the node stays up.
- With `events_backpressure.enabled`, instead of shedding findings the plugin write-blocks the events indices when the backlog reaches `high_watermark_percent`, so no new events are indexed and the backlog can drain; the block is lifted at `low_watermark_percent`.

The enrichment throughput settings shape the load the pipeline puts on the cluster: `enrich_batch_size` findings are drained per in-flight permit and their source events are fetched in one combined MultiGet; enriched documents are buffered and written in bulks of `bulk_size`, flushed at least every `flush_interval` seconds; `max_in_flight` bounds the concurrent enrichment chains; and `rule_cache_max_size` bounds the in-memory rule-metadata cache.

### Updating a setting at runtime

Almost every Security Analytics setting is dynamic. To change one without restarting the node, use the Cluster Settings API:

```bash
curl -sk -u admin:admin -X PUT "https://192.168.56.6:9200/_cluster/settings" -H 'Content-Type: application/json' -d'
{
  "persistent": {
    "plugins.security_analytics.correlation.max_in_flight_findings": 100
  }
}'
```

### Notes

- Changes to `opensearch.yml` require a restart of the Wazuh Indexer to take effect. Dynamic settings can additionally be updated at runtime via the Cluster Settings API shown above.
- `index.correlation` is an index-scope setting and must be applied to individual indices (for example, via an index template or the `_settings` API), not to the cluster as a whole.
- Rollover jobs are enforced by the OpenSearch Job Scheduler. Actual rollover timing may vary slightly depending on cluster load.
