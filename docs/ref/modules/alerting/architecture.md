# Architecture

The Alerting plugin runs inside the Wazuh Indexer as an OpenSearch plugin. It schedules monitors that query indices, evaluates trigger conditions against the results, and executes actions (typically sending notifications) when conditions are met.

## Core concepts

The alerting pipeline follows a linear flow:

1. A **Monitor** runs on a schedule, executing a query against one or more indices.
2. The query results are evaluated against one or more **Triggers** — boolean conditions that determine whether an alert should fire.
3. When a trigger condition is met, the monitor executes its configured **Actions** — typically sending a notification through the Notifications plugin.
4. An **Alert** record is created to track the triggered condition through its lifecycle.
5. For document-level monitors, **Findings** record which specific documents matched the monitor's queries. Findings are generated whether or not the monitor defines a trigger, so a monitor with an empty trigger list still produces them. They are stored only when finding storage is enabled; see [Findings](#findings).

## Monitor types

| Monitor Type | Description | Trigger Type | Input Type |
| --- | --- | --- | --- |
| **Query-level** (per query) | Executes an OpenSearch query and evaluates the aggregation results as a whole. Suitable for threshold-based alerts (e.g., error count > 100). | `QueryLevelTrigger` | `SearchInput` |
| **Bucket-level** (per bucket) | Monitors aggregation bucket results individually. Each bucket that meets the trigger condition generates a separate alert. | `BucketLevelTrigger` | `SearchInput` (with aggregations) |
| **Cluster metrics** (per cluster metrics) | Periodically calls OpenSearch cluster APIs (cluster health, stats, tasks, etc.) and evaluates the response. Suitable for monitoring cluster state rather than indexed data. | `QueryLevelTrigger` | `ClusterMetricsInput` |
| **Document-level** (per document) | Matches individual documents using percolate queries. Creates a finding for each matching document. | `DocumentLevelTrigger` | `DocLevelMonitorInput` |
| **Composite** | Chains multiple monitors into a workflow and evaluates conditions across their alerts. See [Workflows](#workflows). | `ChainedAlertTrigger` | `CompositeInput` |
| **Active Response** | Wazuh-specific extension of document-level monitoring for automated response. See [Active Response](index.md#active-response). | `DocumentLevelTrigger` | `DocLevelMonitorInput` |

### Active Response monitor constraints

The Active Response monitor type enforces stricter validation than standard document-level monitors:

- Indices must match the `wazuh-findings-v5-*` prefix.
- The schedule must be an interval schedule (cron schedules are rejected), and the interval cannot exceed 60,000 milliseconds (1 minute).
- Only `DocumentLevelTrigger` is accepted — other trigger types are rejected.
- Actions must use the `per_alert` execution scope. A `per_execution` action is rejected, because each Active Response message carries a single `<doc_id>|<index>` reference and would answer only the first alert of a run.

At run time, actions of an Active Response monitor always run once per alert. Unlike other monitor types, they never fall back to a single execution for the whole run when the run exceeds `plugins.alerting.max_actionable_alert_count` or ends with an error.

## Triggers

Each monitor type uses a corresponding trigger type:

- **QueryLevelTrigger**: Evaluates a script condition against the full query response. The script has access to the query results, aggregations, and monitor metadata.
- **BucketLevelTrigger**: Evaluates a condition per aggregation bucket. Supports composite aggregations for paginating through large result sets.
- **DocumentLevelTrigger**: Defines per-document matching conditions using query DSL. Documents that match the trigger's queries generate alerts.
- **ChainedAlertTrigger**: Evaluates a condition over the alerts produced by the delegate monitors of a composite (workflow) monitor, allowing alerts to fire based on combinations of upstream monitor results.

Cluster metrics monitors reuse `QueryLevelTrigger`, evaluating a script condition against the cluster API response.

## Actions

Actions define what happens when a trigger fires. Each action specifies:

- A **destination** — a notification channel configured in the [Notifications](../notifications/index.md) plugin (Slack, email, webhook, etc.).
- A **message template** — a Mustache template that formats the alert details into the notification body.
- An optional **throttle** — a minimum interval between repeated notifications for the same alert (up to `plugins.alerting.action_throttle_max_value`, default 24 hours).

When a trigger fires, the plugin calls the Notifications plugin via its internal transport interface to deliver the message.

## Alert lifecycle

Alerts transition through the following states:

| State | Description |
| --- | --- |
| **Active** | The trigger condition is currently met. The alert was just created or continues to fire. |
| **Acknowledged** | A user has acknowledged the alert through the Dashboard or API. |
| **Completed** | The trigger condition is no longer met. The alert resolved naturally. |
| **Error** | An error occurred during monitor execution or action delivery. |

## Findings

Document-level monitors produce **findings** — records of individual documents that matched the monitor's queries. Each finding contains:

- The matching document IDs and source index.
- The queries (rules) that matched.
- A timestamp of when the match was detected.

Findings are stored only when `plugins.alerting.alert_finding_enabled` is `true`, which is off by default. Stored findings go to rolling indices (`.opensearch-alerting-finding-history-*`) and are deleted after 60 days by default; see [Alerting indices](#alerting-indices).

These raw alerting findings are not the same as the findings surfaced in the Wazuh context. Detectors managed by the [Ruleset Management](../ruleset-management/index.md) plugin run on document-level monitors internally, but produce their own enriched findings — augmented with the full event payload and rule metadata — which are written to `wazuh-findings-v5-*` indices. A plain document-level monitor only produces the raw findings described above; it does not perform this enrichment.

## Workflows

Workflows chain multiple monitors into a composite execution unit. A workflow defines an ordered sequence of monitors (delegates) that run together. This enables multi-stage detection scenarios where the output of one monitor informs the next.

Workflows have their own CRUD API and can be executed and managed independently of individual monitors. There is no separate workflow search endpoint: workflows are stored with the monitors and returned by the monitor search API.

## Alerting indices

The plugin manages the following system indices:

| Index | Description | Retention |
| --- | --- | --- |
| `.opendistro-alerting-alerts` | Current active alerts | — |
| `.opendistro-alerting-alert-history-*` | Historical alert records. Created only when `plugins.alerting.alert_history_enabled` is `true` (off by default) | 60 days |
| `.opensearch-alerting-finding-history-*` | Document-level monitor findings. Created only when `plugins.alerting.alert_finding_enabled` is `true` (off by default) | 60 days |
| `.opensearch-alerting-comments-history-*` | Alert comments and annotations. Used only when `plugins.alerting.comments_enabled` is `true` (off by default) | 60 days |
| `.opendistro-alerting-config` | Monitor and workflow definitions | — |
| `.opensearch-alerting-queries*` | Queries of document-level monitors, prepared for matching | — |
| `.opensearch-alerting-config-lock` | Short-lived locks that keep a monitor from running on two nodes at once | — |

Every 12 hours (the rollover period), the plugin checks each history index. It rolls the current index over to a new one if it holds 1,000 documents or is older than 30 days, and deletes the history indices that are older than 60 days. Alert and finding history only roll over while their setting (`alert_history_enabled`, `alert_finding_enabled`) is on, but the deletion of old indices runs either way; while the setting is on, the current write index is never deleted. Comments history rolls over and is pruned whether or not comments are enabled. The two limits do different things: `max_age` (30 days) only decides when a new index is started, while `retention_period` (60 days) decides when data is deleted.

Rollover periods, rollover limits and retention are configurable through [plugin settings](configuration.md).
