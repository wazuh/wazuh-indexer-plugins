# Engine Filters Index

This directory contains the index definition for the `.engine-filters` index, which stores user-generated filters for the Wazuh Engine.

## Overview

Filters are conceptually similar to decoders but have a reduced and specialized structure. They do not perform parsing or normalization and are used only to decide whether an event should continue through the pipeline.

## Filter Types

- **pre-filter**: Applied before processing
- **post-filter**: Applied after processing

## Schema

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `filter.name` | keyword | Filter identifier (e.g., "filter/prefilter/0") |
| `filter.id` | keyword | UUID for the filter |
| `filter.enabled` | boolean | Whether the filter is active |
| `filter.type` | keyword | Type of filter: "pre-filter" or "post-filter" |
| `filter.check` | text | Filter expression (e.g., "$host.os.platform == 'ubuntu'") |
| `filter.metadata.description` | text | Description of the filter purpose |
| `filter.metadata.author.name` | keyword | Author name |
| `filter.metadata.author.url` | keyword | Author URL |
| `filter.metadata.author.date` | date | Creation date |

## Example Document

```json
{
  "filter": {
    "name": "filter/prefilter/0",
    "id": "fef71314-00c6-41f5-ab26-15e271e9f913",
    "enabled": true,
    "type": "pre-filter",
    "check": "$host.os.platform == 'ubuntu'",
    "metadata": {
      "description": "Default filter to allow all events (for default ruleset)",
      "author": {
        "name": "Wazuh, Inc.",
        "url": "https://wazuh.com",
        "date": "2022/11/08"
      }
    }
  }
}
```
