# Configuration

The Alerting plugin is configured through cluster settings under the `plugins.alerting.*` namespace. All settings can be updated dynamically via the cluster settings API.

## Monitor settings

- **`plugins.alerting.monitor.max_monitors`** (Integer, default `10`) — maximum number of monitors allowed per node.
- **`plugins.alerting.monitor.max_triggers`** (Integer, default `10`, hard max `50`) — maximum number of triggers per monitor.
- **`plugins.alerting.monitor.doc_level_monitor_shard_fetch_size`** (Integer, default `10000`) — number of documents fetched per shard for document-level monitors.
- **`plugins.alerting.monitor.doc_level_monitor_fan_out_nodes`** (Integer, default `1000`) — maximum number of nodes to fan out document-level monitor queries to.
- **`plugins.alerting.monitor.doc_level_monitor_fanout_max_duration`** (TimeValue, default `3m`) — maximum duration for fan-out operations in document-level monitors.
- **`plugins.alerting.monitor.doc_level_monitor_execution_max_duration`** (TimeValue, default `4m`) — maximum total execution duration for document-level monitors.
- **`plugins.alerting.monitor.percolate_query_max_num_docs_in_memory`** (Integer, default `50000`) — maximum number of documents held in memory for percolate queries.
- **`plugins.alerting.monitor.percolate_query_docs_size_memory_percentage_limit`** (Integer, default `10`) — maximum percentage of JVM heap used for percolate query documents.
- **`plugins.alerting.monitor.doc_level_monitor_query_field_names_enabled`** (Boolean, default `true`) — enable field name extraction for document-level monitor queries.

## Timeout settings

- **`plugins.alerting.input_timeout`** (TimeValue, default `30s`) — timeout for monitor input (query) execution.
- **`plugins.alerting.index_timeout`** (TimeValue, default `30s`) — timeout for index operations (writing alerts, findings).
- **`plugins.alerting.bulk_timeout`** (TimeValue, default `30s`) — timeout for bulk index operations.
- **`plugins.alerting.request_timeout`** (TimeValue, default `10s`) — timeout for internal transport requests.

## Alert history settings

- **`plugins.alerting.alert_history_enabled`** (Boolean, default `true`) — enable alert history storage.
- **`plugins.alerting.alert_history_rollover_period`** (TimeValue, default `1d`) — how often to roll over the alert history index.
- **`plugins.alerting.alert_history_max_age`** (TimeValue, default `30d`) — maximum age of alert history indices before deletion.
- **`plugins.alerting.alert_history_max_docs`** (Long, default `1000000`) — maximum number of documents per alert history index.
- **`plugins.alerting.alert_history_retention_period`** (TimeValue, default `30d`) — retention period for alert history data.
- **`plugins.alerting.alert_backoff_millis`** (TimeValue, default `50ms`) — backoff interval between alert write retries.
- **`plugins.alerting.alert_backoff_count`** (Integer, default `3`) — number of retry attempts for failed alert writes.
- **`plugins.alerting.max_actionable_alert_count`** (Long, default `50`) — maximum number of alerts that can trigger actions in a single monitor execution.

## Finding history settings

- **`plugins.alerting.alert_finding_enabled`** (Boolean, default `true`) — enable finding history storage.
- **`plugins.alerting.alert_finding_rollover_period`** (TimeValue, default `12h`) — how often to roll over the finding history index.
- **`plugins.alerting.finding_history_max_age`** (TimeValue, default `30d`) — maximum age of finding history indices before deletion.
- **`plugins.alerting.alert_findings_indexing_batch_size`** (Integer, default `1000`) — batch size for bulk-indexing findings.

## Comment settings

- **`plugins.alerting.comments_enabled`** (Boolean, default `true`) — enable the alert comments feature.
- **`plugins.alerting.comments_history_max_docs`** (Long, default `1000`) — maximum number of documents per comments history index.
- **`plugins.alerting.comments_history_max_age`** (TimeValue, default `30d`) — maximum age of comments history indices before deletion.
- **`plugins.alerting.comments_history_rollover_period`** (TimeValue, default `12h`) — how often to roll over the comments history index.
- **`plugins.alerting.max_comment_character_length`** (Integer, default `2000`) — maximum character length for a single comment.
- **`plugins.alerting.max_comments_per_alert`** (Integer, default `500`) — maximum number of comments allowed per alert.
- **`plugins.alerting.max_comments_per_notification`** (Integer, default `3`) — maximum number of comments included in alert notification messages.

## General settings

- **`plugins.alerting.filter_by_backend_roles`** (Boolean, default `true`) — when enabled, users can only view monitors and alerts created by users who share the same backend role.
- **`plugins.alerting.action_throttle_max_value`** (TimeValue, default `24h`) — maximum throttle duration for alert actions.
- **`plugins.alerting.cross_cluster_monitoring_enabled`** (Boolean, default `true`) — enable monitoring of indices on remote clusters via cross-cluster search.

## Updating settings

All settings can be updated at runtime through the cluster settings API:

```bash
curl -sk -u admin:admin -X PUT \
  "https://127.0.0.1:9200/_cluster/settings" \
  -H 'Content-Type: application/json' \
  -d '{
    "persistent": {
      "plugins.alerting.monitor.max_monitors": 20,
      "plugins.alerting.alert_history_max_age": "60d"
    }
  }'
```
