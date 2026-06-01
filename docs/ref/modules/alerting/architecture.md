# Architecture

The Alerting plugin runs inside the Wazuh Indexer as an OpenSearch plugin. It schedules monitors that query indices, evaluates trigger conditions against the results, and executes actions (typically sending notifications) when conditions are met.

## Core Concepts

The alerting pipeline follows a linear flow:

1. A **Monitor** runs on a schedule, executing a query against one or more indices.
2. The query results are evaluated against one or more **Triggers** — boolean conditions that determine whether an alert should fire.
3. When a trigger condition is met, the monitor executes its configured **Actions** — typically sending a notification through the Notifications plugin.
4. An **Alert** record is created to track the triggered condition through its lifecycle.
5. For document-level monitors, **Findings** record which specific documents matched the trigger.

## Monitor Types

| Monitor Type | Description | Trigger Type | Input Type |
| --- | --- | --- | --- |
| **Query-level** | Executes an OpenSearch query and evaluates the aggregation results as a whole. Suitable for threshold-based alerts (e.g., error count > 100). | `QueryLevelTrigger` | `SearchInput` |
| **Bucket-level** | Monitors aggregation bucket results individually. Each bucket that meets the trigger condition generates a separate alert. | `BucketLevelTrigger` | `SearchInput` (with aggregations) |
| **Document-level** | Matches individual documents using percolate queries. Creates a finding for each matching document. | `DocumentLevelTrigger` | `DocLevelMonitorInput` |
| **Active Response** | Wazuh-specific extension of document-level monitoring for automated response. See [Active Response](index.md#active-response). | `DocumentLevelTrigger` | `DocLevelMonitorInput` |

### Active Response Monitor Constraints

The Active Response monitor type enforces stricter validation than standard document-level monitors:

- Indices must match the `wazuh-findings-v5-*` prefix.
- Schedule interval cannot exceed 60,000 milliseconds (1 minute).
- Only `DocumentLevelTrigger` is accepted — other trigger types are rejected.

## Triggers

Each monitor type uses a corresponding trigger type:

- **QueryLevelTrigger**: Evaluates a script condition against the full query response. The script has access to the query results, aggregations, and monitor metadata.
- **BucketLevelTrigger**: Evaluates a condition per aggregation bucket. Supports composite aggregations for paginating through large result sets.
- **DocumentLevelTrigger**: Defines per-document matching conditions using query DSL. Documents that match the trigger's queries generate findings.

## Actions

Actions define what happens when a trigger fires. Each action specifies:

- A **destination** — a notification channel configured in the [Notifications](../notifications/index.md) plugin (Slack, email, webhook, etc.).
- A **message template** — a Mustache template that formats the alert details into the notification body.
- An optional **throttle** — a minimum interval between repeated notifications for the same alert (up to `plugins.alerting.action_throttle_max_value`, default 24 hours).

When a trigger fires, the plugin calls the Notifications plugin via its internal transport interface to deliver the message.

## Alert Lifecycle

Alerts transition through the following states:

| State | Description |
| --- | --- |
| **Active** | The trigger condition is currently met. The alert was just created or continues to fire. |
| **Acknowledged** | A user has acknowledged the alert through the Dashboard or API. |
| **Completed** | The trigger condition is no longer met. The alert resolved naturally. |
| **Error** | An error occurred during monitor execution or action delivery. |

## Findings

Document-level monitors produce **findings** — records of individual documents that matched the monitor's trigger conditions. Each finding contains:

- The matching document IDs and source index.
- The queries (rules) that matched.
- A timestamp of when the match was detected.

Findings are stored in rolling indices (`.opensearch-alerting-finding-history-*`) with a default retention of 30 days.

In the Wazuh context, the [Security Analytics](../security-analytics/index.md) plugin enriches raw findings with the full event payload and rule metadata before writing them to `wazuh-findings-v5-*` indices.

## Workflows

Workflows chain multiple monitors into a composite execution unit. A workflow defines an ordered sequence of monitors (delegates) that run together. This enables multi-stage detection scenarios where the output of one monitor informs the next.

Workflows have their own CRUD API and can be executed, searched, and managed independently of individual monitors.

## Alerting Indices

The plugin manages the following system indices:

| Index | Description | Retention |
| --- | --- | --- |
| `.opendistro-alerting-alerts` | Current active alerts | — |
| `.opendistro-alerting-alert-history-*` | Historical alert records | 30 days (daily rollover) |
| `.opensearch-alerting-finding-history-*` | Document-level monitor findings | 30 days (12-hour rollover) |
| `.opensearch-alerting-comments-history-*` | Alert comments and annotations | 30 days (12-hour rollover) |
| `.scheduled-jobs` | Monitor and workflow definitions | — |

Rollover periods and retention are configurable through [plugin settings](configuration.md).
