# API Reference

The Alerting plugin exposes a REST API under the `/_plugins/_alerting/` base path. This page summarizes the available endpoints. For full request/response schemas, see the [OpenSearch Alerting API documentation](https://docs.opensearch.org/docs/latest/observing-your-data/alerting/api/).

## Endpoint Summary

### Monitors

| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/_plugins/_alerting/monitors` | Create a monitor |
| `PUT` | `/_plugins/_alerting/monitors/{id}` | Update a monitor |
| `GET` | `/_plugins/_alerting/monitors/{id}` | Get a monitor by ID |
| `DELETE` | `/_plugins/_alerting/monitors/{id}` | Delete a monitor |
| `GET` | `/_plugins/_alerting/monitors/_search` | Search monitors |
| `POST` | `/_plugins/_alerting/monitors/{id}/_execute` | Execute a monitor immediately |

### Workflows

| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/_plugins/_alerting/workflows` | Create a workflow |
| `PUT` | `/_plugins/_alerting/workflows/{id}` | Update a workflow |
| `GET` | `/_plugins/_alerting/workflows/{id}` | Get a workflow by ID |
| `DELETE` | `/_plugins/_alerting/workflows/{id}` | Delete a workflow |
| `POST` | `/_plugins/_alerting/workflows/{id}/_execute` | Execute a workflow immediately |

### Alerts

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/_plugins/_alerting/alerts` | List alerts across all monitors |
| `GET` | `/_plugins/_alerting/workflows/{id}/alerts` | List alerts for a specific workflow |
| `POST` | `/_plugins/_alerting/monitors/{id}/_acknowledge/alerts` | Acknowledge one or more alerts |

### Findings

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/_plugins/_alerting/findings` | List findings from document-level monitors |

### Comments

| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/_plugins/_alerting/comments/{alertId}` | Add a comment to an alert |
| `PUT` | `/_plugins/_alerting/comments/{commentId}` | Update a comment |
| `DELETE` | `/_plugins/_alerting/comments/{commentId}` | Delete a comment |
| `GET` | `/_plugins/_alerting/comments/_search` | Search comments |

### Destinations (Legacy)

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/_plugins/_alerting/destinations/{id}` | Get a destination by ID |
| `GET` | `/_plugins/_alerting/destinations/_search` | Search destinations |

> **Note:** Destination management has been migrated to the [Notifications](../notifications/index.md) plugin. Use the Notifications API (`/_plugins/_notifications/`) for creating and managing notification channels.

## Examples

### Create a Query-Level Monitor

This example creates a monitor that checks every 5 minutes whether the number of error-level events in the last hour exceeds 100:

```bash
curl -sk -u admin:admin -X POST \
  "https://localhost:9200/_plugins/_alerting/monitors" \
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
                  { "term": { "event.severity": "error" } }
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

### Acknowledge Alerts

```bash
curl -sk -u admin:admin -X POST \
  "https://localhost:9200/_plugins/_alerting/monitors/{monitorId}/_acknowledge/alerts" \
  -H 'Content-Type: application/json' \
  -d '{
    "alerts": ["alert-id-1", "alert-id-2"]
  }'
```

### Execute a Monitor On-Demand

```bash
curl -sk -u admin:admin -X POST \
  "https://localhost:9200/_plugins/_alerting/monitors/{monitorId}/_execute"
```
