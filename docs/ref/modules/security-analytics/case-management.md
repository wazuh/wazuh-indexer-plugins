# Case management

> **Status:** This page describes the case management schema as revised for [issue #1220 follow-up](https://github.com/wazuh/wazuh-indexer-plugins/issues/1220), which has not yet been merged into the stable branch. The fields, examples, and behavior below reflect the target design.

Case management allows analysts to track and manage the lifecycle of findings produced by Security Analytics detectors. Each finding can be annotated with case metadata enabling triage workflows directly on the indexed data.

## Overview

When a detection rule matches an event, Security Analytics creates a **finding**. By default, findings contain only detection fields. Case management extends findings with a `wazuh.case` object that supports:

- **Classification** — a `title`, `description`, `severity`, `priority`, and TLP (Traffic Light Protocol) label to support prioritization and triage.
- **Status tracking** — move findings through a workflow (e.g., `active` → `acknowledged` → `completed`).
- **Multiple comments** — a discussion thread of any number of comments, each with its own author and timestamps, independent of the case-level user and timestamps.
- **Tags** — organize findings with keyword labels.
- **User attribution** — record which analyst last updated the case.
- **Timestamps** — track when the case was created and last updated.

## Case fields

The following fields are available under `wazuh.case` in the findings data stream:

- **`wazuh.case.title`** (`match_only_text`) — short summary of the case.
- **`wazuh.case.description`** (`match_only_text`) — longer free-form description of the case.
- **`wazuh.case.tags`** (`keyword[]`) — tags for organization and filtering.
- **`wazuh.case.user.name`** (`keyword`) — name of the user who last updated the case. Managed by the UI, not editable directly.
- **`wazuh.case.status`** (`keyword`) — current status. One of `active`, `acknowledged`, `completed`, `error`, `deleted`, `audit` (lowercase).
- **`wazuh.case.severity`** (`keyword`) — one of `informational`, `low`, `medium`, `high`, `critical` (lowercase).
- **`wazuh.case.priority`** (`keyword`) — one of `low`, `medium`, `high`, `urgent` (lowercase).
- **`wazuh.case.tlp`** (`keyword`) — Traffic Light Protocol classification. One of `TLP:RED`, `TLP:AMBER`, `TLP:GREEN`, `TLP:CLEAR` — uppercase, with the `TLP:` prefix, unlike the other enum fields.
- **`wazuh.case.comments`** (`nested`) — array of comment objects (replaces the earlier single `comment` field). Each comment has:
  - **`wazuh.case.comments.author`** (`keyword`) — the user who wrote the comment.
  - **`wazuh.case.comments.created_at`** (`date`) — when the comment was created.
  - **`wazuh.case.comments.updated_at`** (`date`) — when the comment was last edited.
  - **`wazuh.case.comments.comment`** (`match_only_text`) — the comment text.

A case with a single comment is represented as a one-element `comments` array — there's no separate single-comment shape.

## Updating findings

Use the **update findings** endpoint to set or modify case fields on one or more existing findings.

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
        "title": "Sample Case Title",
        "description": "This is a sample description for the case.",
        "tags": ["tag1", "tag2", "tag3"],
        "user": {
          "name": "admin"
        },
        "status": "acknowledged",
        "severity": "medium",
        "priority": "medium",
        "tlp": "TLP:CLEAR",
        "comments": [
          {
            "author": "admin",
            "created_at": "2026-06-10T08:00:00.000Z",
            "updated_at": "2026-06-10T08:00:00.000Z",
            "comment": "Reviewed by SOC analyst"
          }
        ]
      }
    }
  ]
}
```

> **Note:** The fields `user.name`, `comments[].created_at`, and `comments[].updated_at` are automatically managed by the Wazuh Dashboard. They should not be set manually.

- **`findings`** (required) — array of finding updates (max 50 per request).
- **`findings[]._id`** (required) — document ID of the finding.
- **`findings[]._index`** (required) — index where the finding is stored.
- **`findings[].case`** (required) — object with the case fields to set or update.

All fields inside `case` are optional — you can update only the fields you need (partial update). To add a new comment without disturbing existing ones, submit the full `comments` array including the previous entries plus the new one; the update replaces the array rather than appending to it.

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

- **400** — invalid JSON, missing required fields, empty array, or exceeding the 50-item limit.
- **207** — partial failure; some items succeeded, some failed (e.g., document not found).

## Example: triage workflow

> **Note:** Case management is designed to be performed through the Wazuh Dashboard, which handles timestamps and user attribution automatically. The examples below use `curl` for illustration purposes.

```bash
# 1. Classify and acknowledge a finding
curl -sk -u admin:admin -X PUT "https://127.0.0.1:9200/_plugins/_security_analytics/findings/_update" \
  -H "Content-Type: application/json" \
  -d '{
    "findings": [{
      "_id": "finding-001",
      "_index": "wazuh-findings-v5-threat-000001",
      "case": {
        "title": "Suspicious SSH activity",
        "severity": "high",
        "priority": "high",
        "tlp": "TLP:AMBER",
        "status": "acknowledged",
        "comments": [
          {
            "author": "admin",
            "comment": "Under investigation"
          }
        ]
      }
    }]
  }'

# 2. Add a follow-up comment and close the finding after investigation
curl -sk -u admin:admin -X PUT "https://127.0.0.1:9200/_plugins/_security_analytics/findings/_update" \
  -H "Content-Type: application/json" \
  -d '{
    "findings": [{
      "_id": "finding-001",
      "_index": "wazuh-findings-v5-threat-000001",
      "case": {
        "status": "completed",
        "comments": [
          {
            "author": "admin",
            "comment": "Under investigation"
          },
          {
            "author": "admin",
            "comment": "False positive - benign admin activity"
          }
        ]
      }
    }]
  }'
```

## Querying findings by case status

Since `wazuh.case.status` is a `keyword` field, you can filter findings by status using standard queries:

```bash
# Get all acknowledged findings
curl -sk -u admin:admin -X GET "https://127.0.0.1:9200/wazuh-findings-v5-*/_search" -H 'Content-Type: application/json' -d'
{
  "query": {
    "term": {
      "wazuh.case.status": {
        "value": "acknowledged"
      }
    }
  }
}'
```
