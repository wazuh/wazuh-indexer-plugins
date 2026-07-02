<!-- // ANCHOR: settings-table -->
## Security Analytics settings

The Security Analytics plugin is configured through settings in `opensearch.yml`. All node-scope settings use the `plugins.security_analytics` prefix. Almost every setting is dynamic and can be changed at runtime via the Cluster Settings API.

- **`plugins.security_analytics.alert_finding_enabled`** (Boolean, default `true`) — enable rollover and retention management for the finding history indices.
- **`plugins.security_analytics.alert_finding_max_docs`** (Long, default `1000`, minimum `0`) — **Deprecated.** Maximum document count for a finding history index before rollover.
- **`plugins.security_analytics.alert_finding_rollover_period`** (Time, default `12h`) — how often the finding history rollover job runs.
- **`plugins.security_analytics.alert_history_enabled`** (Boolean, default `true`) — enable rollover and retention management for the alert history indices.
- **`plugins.security_analytics.alert_history_max_age`** (Time, default `30d`) — maximum age of an alert history index before rollover.
- **`plugins.security_analytics.alert_history_max_docs`** (Long, default `1000`, minimum `0`) — maximum document count for an alert history index before rollover.
- **`plugins.security_analytics.alert_history_retention_period`** (Time, default `60d`) — retention period after which alert history indices are deleted.
- **`plugins.security_analytics.alert_history_rollover_period`** (Time, default `12h`) — how often the alert history rollover job runs.
- **`plugins.security_analytics.auto_correlations_enabled`** (Boolean, default `false`) — automatically generate correlation rules from new findings.
- **`plugins.security_analytics.correlation.detector_cache_ttl`** (Time, default `5m`) — TTL for the in-memory monitor-id to detector cache. Set to `0s` to disable the cache.
- **`plugins.security_analytics.correlation.max_in_flight_findings`** (Integer, default `50`, range 1–1000) — maximum number of correlation pipelines running concurrently.
- **`plugins.security_analytics.correlation.metadata_cache_ttl`** (Time, default `5m`) — TTL for the in-memory caches of log-type list and correlation rules by detector type. Set to `0s` to disable both caches.
- **`plugins.security_analytics.correlation_history_max_age`** (Time, default `30d`) — maximum age of a correlation history index before rollover.
- **`plugins.security_analytics.correlation_history_max_docs`** (Long, default `1000`, minimum `0`) — maximum document count for a correlation history index before rollover.
- **`plugins.security_analytics.correlation_history_retention_period`** (Time, default `60d`) — retention period after which correlation history indices are deleted.
- **`plugins.security_analytics.correlation_history_rollover_period`** (Time, default `12h`) — how often the correlation history rollover job runs.
- **`plugins.security_analytics.correlation_time_window`** (Time, default `5m`) — time window used to group findings into correlations.
- **`plugins.security_analytics.enable_detectors_with_dedicated_query_indices`** (Boolean, default `true`) — create dedicated query indices for new detectors.
- **`plugins.security_analytics.enable_workflow_usage`** (Boolean, default `true`) — use Alerting composite workflows when running detectors.
- **`plugins.security_analytics.enriched_findings_bulk_size`** (Integer, default `100`, range 10–1000) — number of enriched findings accumulated before a bulk index request is fired.
- **`plugins.security_analytics.enriched_findings_enrich_batch_size`** (Integer, default `100`, range 1–1000) — maximum number of findings drained from the queue per in-flight permit, fetched via a single combined MultiGet.
- **`plugins.security_analytics.enriched_findings_flush_interval`** (Integer, default `5`, range 1–60) — interval in seconds at which pending enriched findings are flushed regardless of batch size.
- **`plugins.security_analytics.enriched_findings_index_enabled`** (Boolean, default `true`) — toggle the enriched findings pipeline (see [Architecture](architecture.md)).
- **`plugins.security_analytics.enriched_findings_max_in_flight`** (Integer, default `5`, range 1–10) — maximum number of concurrent async enrichment chains.
- **`plugins.security_analytics.enriched_findings_rule_cache_max_size`** (Integer, default `10000`, minimum `0`) — maximum number of rule-metadata entries cached in memory. Least-recently-used entries are evicted past this size.
- **`plugins.security_analytics.filter_by_backend_roles`** (Boolean, default `false`) — restrict access to detectors, rules, and findings based on the requester's backend roles.
- **`plugins.security_analytics.finding_history_max_age`** (Time, default `30d`) — maximum age of a finding history index before rollover.
- **`plugins.security_analytics.finding_history_retention_period`** (Time, default `60d`) — retention period after which finding history indices are deleted.
- **`plugins.security_analytics.index_timeout`** (Time, default `60s`) — timeout for Security Analytics index operations.
- **`plugins.security_analytics.max_detectors`** (Integer, default `10`, minimum `0`) — maximum number of user-created detectors (Content Manager detectors do not count).

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

Setting `enriched_findings_index_enabled` to `false` disables the Wazuh enriched findings pipeline described in [Architecture](architecture.md); raw Security Analytics findings continue to be written to `.opensearch-sap-{category}-findings-*`, but no `wazuh-findings-v5-{category}*` documents are produced.

### Enrichment tuning

The enriched findings service batches index requests and limits concurrency to avoid overloading the transport layer. The settings below can be tuned independently:

```yaml
# opensearch.yml
plugins.security_analytics.enriched_findings_bulk_size: 100
plugins.security_analytics.enriched_findings_max_in_flight: 5
plugins.security_analytics.enriched_findings_flush_interval: 5
plugins.security_analytics.enriched_findings_enrich_batch_size: 100
plugins.security_analytics.enriched_findings_rule_cache_max_size: 10000
```

- **`bulk_size`** — findings are buffered until this count is reached, then flushed as a single bulk request. Lower it on low-throughput nodes to reduce latency; raise it on high-throughput nodes to improve indexing efficiency.
- **`max_in_flight`** — caps the number of concurrent enrichment chains (MultiGet + build + index). Lower it on resource-constrained nodes to reduce peak demand on the transport layer.
- **`flush_interval`** — interval in seconds at which any remaining buffered findings are flushed, regardless of `bulk_size`. Prevents findings from sitting in the buffer indefinitely during low-activity periods.
- **`enrich_batch_size`** — maximum number of findings drained from the queue per in-flight permit; their triggering events are fetched in a single combined MultiGet instead of one per finding, reducing round-trips under load.
- **`rule_cache_max_size`** — bounds the in-memory rule-metadata cache. Each cached entry holds a full rule document (compliance and MITRE maps included); least-recently-used entries are evicted past this size and re-fetched on demand.

### Updating a setting at runtime

Almost every Security Analytics setting is dynamic. To change one without restarting the node, use the Cluster Settings API:

```bash
curl -sk -u admin:admin -X PUT "https://127.0.0.1:9200/_cluster/settings" -H 'Content-Type: application/json' -d'
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
