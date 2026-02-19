# Wazuh Indexer Setup Plugin — Development Guide

This document describes how to extend the Wazuh Indexer setup plugin to create new index templates and index management policies (ISM) for OpenSearch.

---

## 📦 Creating a New Index

### 1. Add a New Index Template

Create a new JSON file in the directory: `/plugins/setup/src/main/resources`

Follow the existing structure and naming convention. Example:

```json
{
  "index_patterns": ["<pattern>"],
  "mappings": {
    "date_detection": false,
    "dynamic": "strict",
    "properties": {
      <custom mappings and fields>
    }
  },
  "order": 1,
  "settings": {
    "index": {
      "number_of_shards": 1,
      "number_of_replicas": 1
    }
  }
}
```

### 2. Register the Index in the Code

Edit the constructor of the `SetupPlugin` class located at: `/plugins/setup/src/main/java/com/wazuh/setup/SetupPlugin.java`

Add the template and index entry to the `indices` map. There are two kind of indices:

- **Stream index**. Stream indices contain time-based events of any kind (alerts, statistics, logs...).
- **Stateful index**. Stateful indices represent the most recent information of a subject (active vulnerabilities, installed packages, open ports, ...). These indices are different of Stream indices as they do not contain timestamps. The information is not based on time, as they always represent the most recent state.

```java
/**
* Main class of the Indexer Setup plugin. This plugin is responsible for the creation of the index
* templates and indices required by Wazuh to work properly.
*/
public class SetupPlugin extends Plugin implements ClusterPlugin {

  // ...

  // Stream indices
  this.indices.add(new StreamIndex("my-stream-index-000001", "my-index-template-1", "my-alias"));
  // State indices
  this.indices.add(new StateIndex("my-state-index", "my-index-template-2"));

  //...
}
```

> ✅ Verifying Template and Index Creation
> After building the plugin and deploying the Wazuh Indexer with it, you can verify the index templates and indices using the following commands:
> ```bash
> curl -X GET <indexer-IP>:9200/_index_template/
> curl -X GET <indexer-IP>:9200/_cat/indices?v
> ```
Alternatively, use the Developer Tools console from the Wazuh Dashboard, or your browser.
## 🔁 Creating a New ISM (Index State Management) Policy
### 1. Add Rollover Alias to the Index Template
Edit the existing index template JSON file and add the following setting:
```json
"plugins.index_state_management.rollover_alias": "<index-name>"
```
### 2. Define the ISM Policy
Refer to the [OpenSearch ISM Policies documentation](https://docs.opensearch.org/3.3/im-plugin/ism/policies/) for more details.

Here is an example ISM policy:
```json
{
  "policy": {
    "policy_id": "<index-name>-rollover-policy",
    "description": "<policy-description>",
    "last_updated_time": <unix-timestamp-in-milliseconds>,
    "schema_version": 21,
    "error_notification": null,
    "default_state": "rollover",
    "states": [
      {
        "name": "rollover",
        "actions": [
          {
            "rollover": {
              "min_doc_count": 200000000,
              "min_index_age": "7d",
              "min_primary_shard_size": "25gb"
            }
          }
        ],
        "transitions": []
      }
    ],
    "ism_template": [
      {
        "index_patterns": [
          "wazuh-<pattern1>-*"
          // Optional additional patterns
          // "wazuh-<pattern2>-*"
        ],
        "priority": <priority-int>,
        "last_updated_time": <unix-timestamp-in-milliseconds>
      }
    ]
  }
}
```

### 3. Register the ISM Policy in the Plugin Code
Edit the `IndexStateManagement` class located at: `/plugins/setup/src/main/java/com/wazuh/setup/index/IndexStateManagement.java`

Register the new policy constant and add it in the constructor:
```java
// ISM policy name constant (filename without .json extension)
static final String MY_POLICY = "my-policy-filename";

...

/**
 * Constructor
 *
 * @param index    Index name
 * @param template Index template name
 */
public IndexStateManagement(String index, String template) {
    super(index, template);
    this.policies = new ArrayList<>();

    // Register the ISM policy to be created
    this.policies.add(MY_POLICY);
}
```

## 📌 Additional Notes
Always follow existing naming conventions to maintain consistency.

Use epoch timestamps (in milliseconds) for `last_updated_time` fields.

ISM policies and templates must be properly deployed before the indices are created.

---

## 🚀 Unclassified Events Data Stream (`wazuh-events-v5-unclassified`)

### Overview

The **wazuh-events-v5-unclassified** data stream is a specialized stream designed to capture and store events that do not match any predefined event categories. This provides visibility into edge cases, parsing failures, and events that may require new categorization rules.

### Purpose

- **Investigation and Troubleshooting**: Analyze uncategorized events to identify patterns or issues
- **Rule Development**: Identify events that need new categorization rules
- **System Monitoring**: Track parsing failures and anomalies

### Data Stream Configuration

#### Index Template
- **Location**: `plugins/setup/src/main/resources/templates/streams/unclassified.json`
- **Index Pattern**: `wazuh-events-v5-unclassified*`
- **Rollover Alias**: `wazuh-events-v5-unclassified`
- **Priority**: 2 (higher priority than standard event streams for proper template selection)

#### Fields Included
- **@timestamp**: Event timestamp
- **event.original**: Raw, unprocessed event data
- **wazuh.agent.***: Agent metadata (id, name, version, type)
- **wazuh.cluster.***: Cluster information (name, node)
- **wazuh.space.name**: Wazuh space/tenant information
- **wazuh.schema.version**: Schema version
- **wazuh.integration.***: Integration metadata (category, name, decoders, rules)

#### Storage Settings
- **Number of Shards**: 3
- **Number of Replicas**: 0
- **Auto-expand Replicas**: 0-1
- **Refresh Interval**: 5 seconds
- **Dynamic Mapping**: Strict (prevents unintended field creation)

### ISM Policy

#### Policy Details
- **Policy Name**: `unclassified-events-policy`
- **Location**: `plugins/setup/src/main/resources/policies/unclassified-events-policy.json`
- **Retention Period**: 7 days
- **Priority**: 100

#### Policy States

1. **Hot State**
   - Actions: None (events are immediately indexed)
   - Transition Condition: Transitions to `delete` after 7 days

2. **Delete State**
   - Actions: Deletes the index
   - Retry Policy: 3 attempts with exponential backoff (1-minute initial delay)

### Use Cases

1. **Event Classification Issues**
   - Events that failed to match any category
   - Malformed or unusual event formats

2. **Parsing Failures**
   - Events that couldn't be decoded properly
   - Invalid event structures

3. **Rule Development**
   - Analyzing patterns that require new rules
   - Edge cases not covered by existing rules

4. **System Diagnostics**
   - Understanding integration performance
   - Identifying missing integrations or decoders

### Configuration

The data stream is created automatically during plugin initialization. Ensure:

1. The template file `unclassified.json` exists in `templates/streams/`
2. The ISM policy file `unclassified-events-policy.json` exists in `policies/`
3. Both are registered in `SetupPlugin.java` and `IndexStateManagement.java`

### Indexing Unclassified Events

To index events into this data stream, use:

```bash
POST /wazuh-events-v5-unclassified/_doc
{
  "@timestamp": "2024-02-19T10:00:00Z",
  "event": {
    "original": "raw uncategorized event data"
  },
  "wazuh": {
    "agent": {
      "id": "001",
      "name": "agent-name"
    },
    "space": {
      "name": "default"
    }
  }
}
```

### Monitoring and Analysis

#### Query Unclassified Events
```bash
GET /wazuh-events-v5-unclassified/_search
{
  "query": {
    "match_all": {}
  }
}
```

#### Count Events by Agent
```bash
GET /wazuh-events-v5-unclassified/_search
{
  "size": 0,
  "aggs": {
    "events_by_agent": {
      "terms": {
        "field": "wazuh.agent.id",
        "size": 100
      }
    }
  }
}
```

#### Time-based Analysis
```bash
GET /wazuh-events-v5-unclassified/_search
{
  "size": 0,
  "aggs": {
    "events_over_time": {
      "date_histogram": {
        "field": "@timestamp",
        "interval": "1h"
      }
    }
  }
}
```

### Testing

Integration tests for the unclassified data stream are located at:
`plugins/setup/src/test/java/com/wazuh/setup/UnclassifiedEventsIT.java`

These tests verify:
- Data stream creation
- Template application
- ISM policy creation and application
- Document indexing capability
- Correct field mappings
