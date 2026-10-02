# API reference

The Alerting plugin exposes a REST API under the `/_plugins/_alerting/` base path. This page summarizes the available endpoints. For full request/response schemas, see the [OpenSearch Alerting API documentation](https://docs.opensearch.org/docs/3.6/observing-your-data/alerting/api/).

## Sections

- [Monitors](#monitors)
- [Workflows](#workflows)
- [Alerts](#alerts)
- [Findings](#findings)
- [Comments](#comments)
- [Destinations (legacy)](#destinations-legacy)
- [Statistics and remote indices](#statistics-and-remote-indices)
- [Examples](#examples)

## Endpoint summary

### Monitors

| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/_plugins/_alerting/monitors` | Create a monitor |
| `PUT` | `/_plugins/_alerting/monitors/{id}` | Update a monitor |
| `GET` | `/_plugins/_alerting/monitors/{id}` | Get a monitor by ID |
| `DELETE` | `/_plugins/_alerting/monitors/{id}` | Delete a monitor |
| `GET`, `POST` | `/_plugins/_alerting/monitors/_search` | Search monitors and workflows |
| `POST` | `/_plugins/_alerting/monitors/{id}/_execute` | Execute a monitor immediately |
| `POST` | `/_plugins/_alerting/monitors/_execute` | Execute a monitor definition sent in the request body, without saving it |

### Workflows

| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/_plugins/_alerting/workflows` | Create a workflow |
| `PUT` | `/_plugins/_alerting/workflows/{id}` | Update a workflow |
| `GET` | `/_plugins/_alerting/workflows/{id}` | Get a workflow by ID |
| `DELETE` | `/_plugins/_alerting/workflows/{id}` | Delete a workflow |
| `POST` | `/_plugins/_alerting/workflows/{id}/_execute` | Execute a workflow immediately |

There is no separate workflow search endpoint. Workflows are returned by `/_plugins/_alerting/monitors/_search`.

### Alerts

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/_plugins/_alerting/monitors/alerts` | List alerts across all monitors. Filter by monitor with the `monitorId` query parameter |
| `GET` | `/_plugins/_alerting/workflows/alerts` | List workflow alerts. Filter by workflow with the `workflowIds` query parameter |
| `POST` | `/_plugins/_alerting/monitors/{id}/_acknowledge/alerts` | Acknowledge one or more alerts of a monitor |
| `POST` | `/_plugins/_alerting/workflows/{id}/_acknowledge/alerts` | Acknowledge one or more alerts of a workflow |

### Findings

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/_plugins/_alerting/findings/_search` | Search the findings of document-level monitors. Get a single finding with the `findingId` query parameter |

Only stored findings are returned, and findings are stored only when `plugins.alerting.alert_finding_enabled` is `true` (off by default). See [Configuration](configuration.md#finding-history-settings).

### Comments

| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/_plugins/_alerting/comments/{alertId}` | Add a comment to an alert |
| `PUT` | `/_plugins/_alerting/comments/{commentId}` | Update a comment |
| `DELETE` | `/_plugins/_alerting/comments/{commentId}` | Delete a comment |
| `GET`, `POST` | `/_plugins/_alerting/comments/_search` | Search comments. The query goes in the request body |

Comments are disabled by default: every comments endpoint returns `403 Forbidden` until `plugins.alerting.comments_enabled` is set to `true`. See [Configuration](configuration.md#comment-settings).

### Destinations (legacy)

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/_plugins/_alerting/destinations` | List destinations |
| `GET` | `/_plugins/_alerting/destinations/{id}` | Get a destination by ID |
| `GET` | `/_plugins/_alerting/destinations/email_accounts/{id}` | Get an email account by ID |
| `GET`, `POST` | `/_plugins/_alerting/destinations/email_accounts/_search` | Search email accounts |
| `GET` | `/_plugins/_alerting/destinations/email_groups/{id}` | Get an email group by ID |
| `GET`, `POST` | `/_plugins/_alerting/destinations/email_groups/_search` | Search email groups |

> **Note:** Destination management has been migrated to the [Notifications](../notifications/index.md) plugin. Use the Notifications API (`/_plugins/_notifications/`) for creating and managing notification channels.

### Statistics and remote indices

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/_plugins/_alerting/stats` | Monitor scheduling statistics for every node |
| `GET` | `/_plugins/_alerting/stats/{metric}` | A single statistics metric: `job_scheduling_metrics` or `jobs_info` |
| `GET` | `/_plugins/_alerting/{nodeId}/stats` | Monitor scheduling statistics for the given nodes |
| `GET` | `/_plugins/_alerting/{nodeId}/stats/{metric}` | A single statistics metric for the given nodes |
| `GET` | `/_plugins/_alerting/remote/indexes` | List the indices, with their health, that match the patterns in the `indexes` query parameter on the local and remote clusters (`<cluster>:<pattern>`), for cross-cluster monitoring |

## Examples

### Create a query-level monitor

This example creates a monitor that checks every 5 minutes whether the number of error-level events (`log.level` is `error`) in the last hour exceeds 100:

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X POST \
  "https://127.0.0.1:9200/_plugins/_alerting/monitors" \
  -H 'Content-Type: application/json' \
  -d '{
    "type": "monitor",
    "name": "High error rate",
    "monitor_type": "query_level_monitor",
    "enabled": true,
    "schedule": {
      "period": {
        "interval": 5,
        "unit": "MINUTES"
      }
    },
    "inputs": [
      {
        "search": {
          "indices": ["wazuh-events-v5-*"],
          "query": {
            "size": 0,
            "query": {
              "bool": {
                "filter": [
                  { "range": { "@timestamp": { "gte": "now-1h" } } },
                  { "term": { "log.level": "error" } }
                ]
              }
            },
            "aggs": {
              "error_count": {
                "value_count": { "field": "@timestamp" }
              }
            }
          }
        }
      }
    ],
    "triggers": [
      {
        "query_level_trigger": {
          "name": "Error threshold exceeded",
          "severity": "1",
          "condition": {
            "script": {
              "source": "ctx.results[0].aggregations.error_count.value > 100",
              "lang": "painless"
            }
          },
          "actions": []
        }
      }
    ]
  }'
```

To test a monitor definition without saving it, send the same request body to `POST /_plugins/_alerting/monitors/_execute?dryrun=true`. The response shows the query results and whether each trigger fired.

### Acknowledge alerts

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X POST \
  "https://127.0.0.1:9200/_plugins/_alerting/monitors/{monitorId}/_acknowledge/alerts" \
  -H 'Content-Type: application/json' \
  -d '{
    "alerts": ["alert-id-1", "alert-id-2"]
  }'
```

### Execute a monitor on-demand

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X POST \
  "https://127.0.0.1:9200/_plugins/_alerting/monitors/{monitorId}/_execute"
```
