# Wazuh Indexer Content Manager Plugin — Development Guide

This document describes how to extend and configure the Wazuh Indexer Content Manager plugin, which is responsible for managing and synchronizing security content from the Wazuh CTI API.

---

## 📋 Overview

The Content Manager plugin handles:
- **Content synchronization** from the Wazuh CTI API
- **Snapshot initialization** for a zip file
- **Incremental updates** using offset-based change tracking
- **Context management** to maintain synchronization state

The plugin manages two main indices:
- `wazuh-ruleset`: Contains the actual security content (rules, decoders, etc.)
- `wazuh-context`: Stores consumer information and synchronization state

---

## 🔧 Plugin Architecture

### Main Components

#### 1. **ContentManagerPlugin**
Main class located at: `/plugins/content-manager/src/main/java/com/wazuh/contentmanager/ContentManagerPlugin.java`

This is the entry point of the plugin. It initializes when the `wazuh-ruleset` index is created by the setup plugin.

#### 2. **ContentIndex**
Located at: `/plugins/content-manager/src/main/java/com/wazuh/contentmanager/index/ContentIndex.java`

Manages operations on the `wazuh-ruleset` index:
- Bulk indexing operations
- Document patching (add, update, delete)
- Query and retrieval operations

#### 3. **ContextIndex**
Located at: `/plugins/content-manager/src/main/java/com/wazuh/contentmanager/index/ContextIndex.java`

Manages the `wazuh-context` index which stores:
- Consumer ID and context information
- Current offset (last successfully applied change)
- Last available offset from the CTI API

#### 4. **ContentUpdater**
Located at: `/plugins/content-manager/src/main/java/com/wazuh/contentmanager/updater/ContentUpdater.java`

Orchestrates the update process by:
- Fetching changes from the CTI API
- Applying changes incrementally
- Updating offset information
- Handling update failures

#### 5. **SnapshotManager**
Located at: `/plugins/content-manager/src/main/java/com/wazuh/contentmanager/utils/SnapshotManager.java`

Handles initial content bootstrapping:
- Downloads snapshots from the CTI API
- Decompresses and indexes snapshot content
- Triggers after initialization or on offset reset

---

## ⚙️ Configuration Settings

The plugin is configured through the `PluginSettings` class. Settings can be defined in `opensearch.yml`:

### Available Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `content_manager.cti.api` | `https://cti.wazuh.com/api/v1` | CTI API base URL |
| `content_manager.cti.consumer` | `vd_4.8.0` | Consumer ID for tracking |
| `content_manager.cti.context` | `vd_1.0.0` | Context ID for versioning |
| `content_manager.cti.client.max_attempts` | `3` | Maximum retry attempts (2-5) |
| `content_manager.cti.client.sleep_time` | `60` | Initial retry delay in seconds (20-100) |
| `content_manager.client_timeout` | `10` | Client timeout in seconds |
| `content_manager.max_changes` | `1000` | Maximum changes per update batch |
| `content_manager.max_items_per_bulk` | `25` | Items per bulk request |
| `content_manager.max_concurrent_bulks` | `5` | Concurrent bulk operations |
| `content_manager.job.max_docs` | `1000` | Maximum documents per job |
| `content_manager.job.schedule` | `1` | Job schedule interval |

### Example Configuration

```yaml
# opensearch.yml
content_manager:
  cti:
    api: "https://cti.wazuh.com/api/v1"
    consumer: "vd_4.8.0"
    context: "vd_1.0.0"
    client:
      max_attempts: 3
      sleep_time: 60
  max_changes: 1000
  max_items_per_bulk: 25
  client_timeout: 10
```

---

## 🔄 How Content Synchronization Works

### 1. **Initialization Phase**

When the plugin starts on a cluster manager node:

1. Waits for the `wazuh-ruleset` index to be created by the setup plugin
2. Creates the `wazuh-context` index if it doesn't exist
3. Checks the consumer's offset:
   - **If offset = 0**: Downloads and indexes a snapshot
   - **If offset > 0**: Proceeds with incremental updates

### 2. **Update Phase**

The update process follows these steps:

1. Fetches current consumer information from `wazuh-context`
2. Compares `offset` with `lastOffset` from CTI API
3. If different, fetches changes in batches (max `content_manager.max_changes`)
4. Applies changes using JSON Patch operations (add, update, delete)
5. Updates the offset after successful application
6. Repeats until `offset == lastOffset`

### 3. **Error Handling**

- **Recoverable errors**: Updates offset and retries later
- **Critical failures**: Resets offset to 0, triggering snapshot re-initialization

---

## 🔍 Debugging

### Check Consumer Status

```bash
GET /wazuh-context/_search
{
  "query": {
    "match_all": {}
  }
}
```

### Check Content Index

```bash
GET /wazuh-ruleset/_search
{
  "size": 10
}
```

### Monitor Plugin Logs

Look for entries from `ContentManagerPlugin`, `ContentUpdater`, and `SnapshotManager` in the OpenSearch logs.

```bash
tail -f logs/opensearch.log | grep -E "ContentManager|ContentUpdater|SnapshotManager"
```

---

## 📌 Important Notes

- The plugin only runs on **cluster manager nodes**
- Requires the **setup plugin** to create the `wazuh-ruleset` index first
- CTI API must be accessible for content synchronization
- Offset-based synchronization ensures no content is missed
- Snapshot initialization provides a fast bootstrap mechanism
- All operations are performed with appropriate privileges using the `Privileged` wrapper

---

## 🔗 Related Documentation

- [Setup Plugin Guide](./setup.md)
- [OpenSearch Plugin Development](https://opensearch.org/docs/latest/install-and-configure/plugins/)
