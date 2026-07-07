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
| `plugins.security_analytics.correlation.max_in_flight_findings`               | Integer   | `50`          | Maximum number of correlation pipelines running concurrently. Valid range: `1–1000`                                                    |
| `plugins.security_analytics.correlation.metadata_cache_ttl`                   | Time      | `5m`          | TTL for the in-memory caches of log-type list and correlation rules by detector type. Set to `0s` to disable both caches               |
| `plugins.security_analytics.correlation_history_max_age`                      | Time      | `30d`         | Maximum age of a correlation history index before rollover                                                                             |
| `plugins.security_analytics.correlation_history_max_docs`                     | Long      | `1000`        | Maximum document count for a correlation history index before rollover. Minimum `0`                                                    |
| `plugins.security_analytics.correlation_history_retention_period`             | Time      | `60d`         | Retention period after which correlation history indices are deleted                                                                   |
| `plugins.security_analytics.correlation_history_rollover_period`              | Time      | `12h`         | How often the correlation history rollover job runs                                                                                    |
| `plugins.security_analytics.correlation_time_window`                          | Time      | `5m`          | Time window used to group findings into correlations                                                                                   |
| `plugins.security_analytics.enable_detectors_with_dedicated_query_indices`    | Boolean   | `true`        | Create dedicated query indices for new detectors                                                                                       |
| `plugins.security_analytics.enable_workflow_usage`                            | Boolean   | `true`        | Use Alerting composite workflows when running detectors                                                                                |
| `plugins.security_analytics.enriched_findings_bulk_size`                      | Integer   | `100`         | Number of enriched findings accumulated before a bulk index request is fired. Valid range: `10–1000`                                   |
| `plugins.security_analytics.enriched_findings_flush_interval`                 | Integer   | `5`           | Interval in seconds at which pending enriched findings are flushed regardless of batch size. Valid range: `1–60`                       |
| `plugins.security_analytics.enriched_findings_index_enabled`                  | Boolean   | `true`        | Toggle the enriched findings pipeline (see [Architecture](architecture.md))                                                            |
| `plugins.security_analytics.enriched_findings_max_in_flight`                  | Integer   | `5`           | Maximum number of concurrent async enrichment chains. Valid range: `1–10`                                                              |
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

### Enrichment tuning

The enriched findings service batches index requests and limits concurrency to avoid overloading the transport layer. The three settings below can be tuned independently:

```yaml
# opensearch.yml
plugins.security_analytics.enriched_findings_bulk_size: 100
plugins.security_analytics.enriched_findings_max_in_flight: 5
plugins.security_analytics.enriched_findings_flush_interval: 5
```

- **`bulk_size`** — findings are buffered until this count is reached, then flushed as a single bulk request. Lower it on low-throughput nodes to reduce latency; raise it on high-throughput nodes to improve indexing efficiency.
- **`max_in_flight`** — caps the number of concurrent enrichment chains (MultiGet + build + index). Lower it on resource-constrained nodes to reduce peak demand on the transport layer.
- **`flush_interval`** — interval in seconds at which any remaining buffered findings are flushed, regardless of `bulk_size`. Prevents findings from sitting in the buffer indefinitely during low-activity periods.

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
