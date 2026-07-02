# Case Management

Case management allows analysts to track and manage the lifecycle of findings produced by Security Analytics detectors. Each finding can be annotated with case metadata enabling triage workflows directly on the indexed data.

## Overview

When a detection rule matches an event, Security Analytics creates a **finding**. By default, findings contain only detection fields. Case management extends findings with a `wazuh.case` object that supports:

- **Title and description** - summarize the case content
- **Status tracking** - move findings through a workflow (e.g., `ACTIVE` → `ACKNOWLEDGED` → `COMPLETED`)
- **Classification** - triage findings with `severity`, `priority` and `tlp` (Traffic Light Protocol)
- **Comments** - hold a discussion thread of multiple comments, each with its own author and timestamps
- **Tags** - organize findings with keyword labels
- **User attribution** - record which analyst updated the finding
- **Timestamps** - track when the case was created and last updated

## Case fields

The following fields are available under `wazuh.case` in the findings data stream:

| Field | Type | Description |
| --- | --- | --- |
| `wazuh.case.title` | `match_only_text` | Title summarizing the case |
| `wazuh.case.description` | `match_only_text` | Detailed description of the case |
| `wazuh.case.status` | `keyword` | Current status. One of: `ACTIVE`, `ACKNOWLEDGED`, `COMPLETED`, `ERROR`, `DELETED`, `AUDIT` |
| `wazuh.case.severity` | `keyword` | Severity. One of: `INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `wazuh.case.priority` | `keyword` | Priority. One of: `LOW`, `MEDIUM`, `HIGH`, `URGENT` |
| `wazuh.case.tlp` | `keyword` | Traffic Light Protocol classification. One of: `TLP:RED`, `TLP:AMBER`, `TLP:GREEN`, `TLP:CLEAR` |
| `wazuh.case.tags` | `keyword[]` | Tags for organization and filtering |
| `wazuh.case.created_at` | `date` | Timestamp when the case was first created. Managed by the UI |
| `wazuh.case.updated_at` | `date` | Timestamp of the last update. Managed by the UI |
| `wazuh.case.user.name` | `keyword` | Name of the user who last updated the case. Managed by the UI |
| `wazuh.case.comments` | `nested[]` | Discussion thread. Array of comment objects |
| `wazuh.case.comments.author` | `keyword` | Name of the user that authored the comment |
| `wazuh.case.comments.comment` | `match_only_text` | Text content of the comment |
| `wazuh.case.comments.created_at` | `date` | Timestamp when the comment was created |
| `wazuh.case.comments.updated_at` | `date` | Timestamp when the comment was last updated |

> **Note:** All enum values are stored lowercase, except `tlp`, which is uppercase and keeps the `TLP:` prefix (e.g. `TLP:CLEAR`).

## Updating findings

Use the **Update Findings** endpoint to set or modify case fields on one or more existing findings.

### Request

```
PUT /_plugins/_security_analytics/findings/_update
```

#### Body

```json
{
  "findings": [
    {
      "_id": "<finding-document-id>",
      "_index": "<finding-index-name>",
      "case": {
        "title": "Suspicious login activity",
        "description": "Multiple failed logins followed by a success",
        "status": "acknowledged",
        "severity": "medium",
        "priority": "high",
        "tlp": "TLP:AMBER",
        "tags": ["critical", "reviewed"],
        "created_at": "2026-06-10T08:00:00.000Z",
        "updated_at": "2026-06-10T09:00:00.000Z",
        "user": {
          "name": "analyst1"
        },
        "comments": [
          {
            "author": "analyst1",
            "comment": "Reviewed by SOC analyst",
            "created_at": "2026-06-10T09:00:00.000Z",
            "updated_at": "2026-06-10T09:00:00.000Z"
          }
        ]
      }
    }
  ]
}
```

> **Note:** The fields `created_at`, `updated_at`, `user.name`, and each comment's `author`, `created_at` and `updated_at` are automatically managed by the Wazuh Dashboard. They should not be set manually.

| Field | Required | Description |
| --- | --- | --- |
| `findings` | Yes | Array of finding updates (max 50 per request) |
| `findings[]._id` | Yes | Document ID of the finding |
| `findings[]._index` | Yes | Index where the finding is stored |
| `findings[].case` | Yes | Object with the case fields to set or update |

All fields inside `case` are optional, you can update only the fields you need (partial update).

### Response

```json
{
  "took": 12,
  "errors": false,
  "items": [
    {
      "_id": "abc123",
      "_index": "wazuh-findings-v5-threat-000001",
      "status": 200,
      "result": "updated"
    }
  ]
}
```

### Error responses

| Status | Condition |
| --- | --- |
| `400` | Invalid JSON, missing required fields, empty array, or exceeding 50-item limit |
| `207` | Partial failure, some items succeeded, some failed (e.g., document not found) |

## Example: triage workflow

> **Note:** Case management is designed to be performed through the Wazuh Dashboard, which handles timestamps and user attribution automatically. The examples below use `curl` for illustration purposes.

```bash
# 1. Acknowledge a finding
curl -X PUT "https://localhost:9200/_plugins/_security_analytics/findings/_update" \
  -H "Content-Type: application/json" \
  -d '{
    "findings": [{
      "_id": "finding-001",
      "_index": "wazuh-findings-v5-threat-000001",
      "case": {
        "status": "acknowledged",
        "comments": [
          { "author": "analyst1", "comment": "Under investigation" }
        ]
      }
    }]
  }'

# 2. Close the finding after investigation
curl -X PUT "https://localhost:9200/_plugins/_security_analytics/findings/_update" \
  -H "Content-Type: application/json" \
  -d '{
    "findings": [{
      "_id": "finding-001",
      "_index": "wazuh-findings-v5-threat-000001",
      "case": {
        "status": "completed",
        "comments": [
          { "author": "analyst1", "comment": "False positive - benign admin activity" }
        ]
      }
    }]
  }'
```

## Querying findings by case status

Since `wazuh.case.status` is a `keyword` field, you can filter findings by status using standard queries:

```bash
# Get all acknowledged findings
curl -XGET "https://127.0.0.1:9200/wazuh-findings-v5-*/_search" -H 'Content-Type: application/json' -d'
{
  "query": {
    "term": {
      "wazuh.case.status": {
        "value": "ACKNOWLEDGED"
      }
    }
  }
}'
```
