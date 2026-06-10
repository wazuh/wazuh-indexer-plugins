# Configuration

The Alerting plugin is configured through cluster settings under the `plugins.alerting.*` namespace. All settings can be updated dynamically via the cluster settings API.

## Monitor Settings

| Setting                                                                      | Type      | Default | Description                                                           |
| ---------------------------------------------------------------------------- | --------- | ------- | --------------------------------------------------------------------- |
| `plugins.alerting.monitor.max_monitors`                                      | Integer   | `10`    | Maximum number of monitors allowed per node.                          |
| `plugins.alerting.monitor.max_triggers`                                      | Integer   | `10`    | Maximum number of triggers per monitor (hard max: 50).                |
| `plugins.alerting.monitor.doc_level_monitor_shard_fetch_size`                | Integer   | `10000` | Number of documents fetched per shard for document-level monitors.    |
| `plugins.alerting.monitor.doc_level_monitor_fan_out_nodes`                   | Integer   | `1000`  | Maximum number of nodes to fan out document-level monitor queries to. |
| `plugins.alerting.monitor.doc_level_monitor_fanout_max_duration`             | TimeValue | `3m`    | Maximum duration for fan-out operations in document-level monitors.   |
| `plugins.alerting.monitor.doc_level_monitor_execution_max_duration`          | TimeValue | `4m`    | Maximum total execution duration for document-level monitors.         |
| `plugins.alerting.monitor.percolate_query_max_num_docs_in_memory`            | Integer   | `50000` | Maximum number of documents held in memory for percolate queries.     |
| `plugins.alerting.monitor.percolate_query_docs_size_memory_percentage_limit` | Integer   | `10`    | Maximum percentage of JVM heap used for percolate query documents.    |
| `plugins.alerting.monitor.doc_level_monitor_query_field_names_enabled`       | Boolean   | `true`  | Enable field name extraction for document-level monitor queries.      |

## Timeout Settings

| Setting                            | Type      | Default | Description                                              |
| ---------------------------------- | --------- | ------- | -------------------------------------------------------- |
| `plugins.alerting.input_timeout`   | TimeValue | `30s`   | Timeout for monitor input (query) execution.             |
| `plugins.alerting.index_timeout`   | TimeValue | `30s`   | Timeout for index operations (writing alerts, findings). |
| `plugins.alerting.bulk_timeout`    | TimeValue | `30s`   | Timeout for bulk index operations.                       |
| `plugins.alerting.request_timeout` | TimeValue | `10s`   | Timeout for internal transport requests.                 |

## Alert History Settings

| Setting                                           | Type      | Default   | Description                                                                      |
| ------------------------------------------------- | --------- | --------- | -------------------------------------------------------------------------------- |
| `plugins.alerting.alert_history_enabled`          | Boolean   | `true`    | Enable alert history storage.                                                    |
| `plugins.alerting.alert_history_rollover_period`  | TimeValue | `1d`      | How often to roll over the alert history index.                                  |
| `plugins.alerting.alert_history_max_age`          | TimeValue | `30d`     | Maximum age of alert history indices before deletion.                            |
| `plugins.alerting.alert_history_max_docs`         | Long      | `1000000` | Maximum number of documents per alert history index.                             |
| `plugins.alerting.alert_history_retention_period` | TimeValue | `30d`     | Retention period for alert history data.                                         |
| `plugins.alerting.alert_backoff_millis`           | TimeValue | `50ms`    | Backoff interval between alert write retries.                                    |
| `plugins.alerting.alert_backoff_count`            | Integer   | `3`       | Number of retry attempts for failed alert writes.                                |
| `plugins.alerting.max_actionable_alert_count`     | Long      | `50`      | Maximum number of alerts that can trigger actions in a single monitor execution. |

## Finding History Settings

| Setting                                               | Type      | Default | Description                                             |
| ----------------------------------------------------- | --------- | ------- | ------------------------------------------------------- |
| `plugins.alerting.alert_finding_enabled`              | Boolean   | `true`  | Enable finding history storage.                         |
| `plugins.alerting.alert_finding_rollover_period`      | TimeValue | `12h`   | How often to roll over the finding history index.       |
| `plugins.alerting.finding_history_max_age`            | TimeValue | `30d`   | Maximum age of finding history indices before deletion. |
| `plugins.alerting.alert_findings_indexing_batch_size` | Integer   | `1000`  | Batch size for bulk-indexing findings.                  |

## Comment Settings

| Setting                                             | Type      | Default | Description                                                         |
| --------------------------------------------------- | --------- | ------- | ------------------------------------------------------------------- |
| `plugins.alerting.comments_enabled`                 | Boolean   | `true`  | Enable the alert comments feature.                                  |
| `plugins.alerting.comments_history_max_docs`        | Long      | `1000`  | Maximum number of documents per comments history index.             |
| `plugins.alerting.comments_history_max_age`         | TimeValue | `30d`   | Maximum age of comments history indices before deletion.            |
| `plugins.alerting.comments_history_rollover_period` | TimeValue | `12h`   | How often to roll over the comments history index.                  |
| `plugins.alerting.max_comment_character_length`     | Integer   | `2000`  | Maximum character length for a single comment.                      |
| `plugins.alerting.max_comments_per_alert`           | Integer   | `500`   | Maximum number of comments allowed per alert.                       |
| `plugins.alerting.max_comments_per_notification`    | Integer   | `3`     | Maximum number of comments included in alert notification messages. |

## General Settings

| Setting                                             | Type      | Default | Description                                                                                             |
| --------------------------------------------------- | --------- | ------- | ------------------------------------------------------------------------------------------------------- |
| `plugins.alerting.filter_by_backend_roles`          | Boolean   | `true`  | When enabled, users can only view monitors and alerts created by users who share the same backend role. |
| `plugins.alerting.action_throttle_max_value`        | TimeValue | `24h`   | Maximum throttle duration for alert actions.                                                            |
| `plugins.alerting.cross_cluster_monitoring_enabled` | Boolean   | `true`  | Enable monitoring of indices on remote clusters via cross-cluster search.                               |

## Updating Settings

All settings can be updated at runtime through the cluster settings API:

```bash
curl -sk -u admin:admin -X PUT \
  "https://localhost:9200/_cluster/settings" \
  -H 'Content-Type: application/json' \
  -d '{
    "persistent": {
      "plugins.alerting.monitor.max_monitors": 20,
      "plugins.alerting.alert_history_max_age": "60d"
    }
  }'
```
