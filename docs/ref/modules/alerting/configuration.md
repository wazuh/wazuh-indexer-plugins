# Configuration

The Alerting plugin is configured through cluster settings under the `plugins.alerting.*` namespace. All settings can be updated dynamically via the cluster settings API.

## Monitor settings

- **`plugins.alerting.monitor.max_monitors`** (Integer, default `10`, minimum `0`, no upper bound) — maximum number of monitors in the cluster. Monitors created by [Ruleset Management](../ruleset-management/index.md) detectors don't count toward this limit.
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
- **`plugins.alerting.index_timeout`** (TimeValue, default `60s`) — timeout for index operations (writing alerts, findings).
- **`plugins.alerting.bulk_timeout`** (TimeValue, default `120s`) — timeout for bulk index operations.
- **`plugins.alerting.request_timeout`** (TimeValue, default `10s`) — timeout for internal transport requests.

## Alert history settings

- **`plugins.alerting.alert_history_enabled`** (Boolean, default `false`) — keep completed alerts in the alert history indices. While `false`, an alert that completes is deleted together with its comments, and no alert history index is created.
- **`plugins.alerting.alert_history_rollover_period`** (TimeValue, default `12h`) — how often the plugin checks whether the alert history index must roll over, and deletes alert history indices older than the retention period.
- **`plugins.alerting.alert_history_max_age`** (TimeValue, default `30d`) — age at which the current alert history index is rolled over to a new one. It doesn't delete anything; deletion is governed by `alert_history_retention_period`.
- **`plugins.alerting.alert_history_max_docs`** (Long, default `1000`) — number of documents at which the current alert history index is rolled over to a new one.
- **`plugins.alerting.alert_history_retention_period`** (TimeValue, default `60d`) — alert history indices older than this are deleted.
- **`plugins.alerting.alert_backoff_millis`** (TimeValue, default `50ms`) — backoff interval between alert write retries.
- **`plugins.alerting.alert_backoff_count`** (Integer, default `2`) — number of retry attempts for failed alert writes.
- **`plugins.alerting.move_alerts_backoff_millis`** (TimeValue, default `250ms`) — backoff interval between retries when moving alerts between indices.
- **`plugins.alerting.move_alerts_backoff_count`** (Integer, default `3`) — number of retry attempts when moving alerts between indices.
- **`plugins.alerting.max_actionable_alert_count`** (Long, default `50`) — maximum number of alerts that can trigger `per_alert` actions in a single monitor execution. Above it, the action runs once for the whole execution instead of once per alert; `-1` removes the limit. Does not apply to Active Response monitors, which always run their actions once per alert.

## Finding history settings

- **`plugins.alerting.alert_finding_enabled`** (Boolean, default `false`) — store findings in the finding history indices. While `false`, document-level monitors still generate findings, but they aren't stored: the findings API returns none and no finding history index is created. The enriched findings that Ruleset Management writes to `wazuh-findings-v5-*` are not affected.
- **`plugins.alerting.alert_finding_rollover_period`** (TimeValue, default `12h`) — how often the plugin checks whether the finding history index must roll over, and deletes finding history indices older than the retention period.
- **`plugins.alerting.finding_history_max_age`** (TimeValue, default `30d`) — age at which the current finding history index is rolled over to a new one. It doesn't delete anything; deletion is governed by `finding_history_retention_period`.
- **`plugins.alerting.alert_finding_max_docs`** (Long, default `1000`, deprecated) — number of documents at which the current finding history index is rolled over to a new one. The setting is deprecated but still applies.
- **`plugins.alerting.alert_findings_indexing_batch_size`** (Integer, default `1000`) — batch size for bulk-indexing findings.
- **`plugins.alerting.finding_history_retention_period`** (TimeValue, default `60d`) — finding history indices older than this are deleted.

## Comment settings

- **`plugins.alerting.comments_enabled`** (Boolean, default `false`) — enable the alert comments feature. While `false`, every comments API request is rejected with `403 Forbidden`.
- **`plugins.alerting.comments_history_max_docs`** (Long, default `1000`) — number of documents at which the current comments history index is rolled over to a new one.
- **`plugins.alerting.comments_history_max_age`** (TimeValue, default `30d`) — age at which the current comments history index is rolled over to a new one. It doesn't delete anything; deletion is governed by `comments_history_retention_period`.
- **`plugins.alerting.comments_history_rollover_period`** (TimeValue, default `12h`) — how often the plugin checks whether the comments history index must roll over, and deletes comments history indices older than the retention period.
- **`plugins.alerting.comments_history_retention_period`** (TimeValue, default `60d`) — comments history indices older than this are deleted.
- **`plugins.alerting.max_comment_character_length`** (Long, default `2000`) — maximum character length for a single comment.
- **`plugins.alerting.max_comments_per_alert`** (Long, default `500`) — maximum number of comments allowed per alert.
- **`plugins.alerting.max_comments_per_notification`** (Integer, default `3`) — maximum number of comments included in alert notification messages.

## General settings

- **`plugins.alerting.filter_by_backend_roles`** (Boolean, default `false`) — restrict monitors, workflows, alerts and findings to users who share a backend role with their creator. While `false`, every user with Alerting permissions sees every monitor and alert. Enabling it changes who can see existing monitors: users without the `all_access` role then only see those created by a user who shares at least one of their backend roles, and users with no backend role get `403 Forbidden` when creating, reading or deleting monitors and workflows.
- **`plugins.alerting.action_throttle_max_value`** (TimeValue, default `24h`) — maximum throttle duration for alert actions.
- **`plugins.alerting.cross_cluster_monitoring_enabled`** (Boolean, default `true`) — enable monitoring of indices on remote clusters via cross-cluster search.
- **`plugins.alerting.notification_context_results_allowed_roles`** (List&lt;String&gt;, default `[]`) — roles whose monitors may include the query results (`ctx.results`) in action messages. While the setting is unset, every monitor's messages can include them. Once it is set, only monitors created by a user who holds one of the listed roles can; for all other monitors the results are empty.

## Updating settings

All settings can be updated at runtime through the cluster settings API:

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X PUT \
  "https://127.0.0.1:9200/_cluster/settings" \
  -H 'Content-Type: application/json' \
  -d '{
    "persistent": {
      "plugins.alerting.monitor.max_monitors": 5,
      "plugins.alerting.alert_history_enabled": true
    }
  }'
```
