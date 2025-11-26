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
- `.cti-consumers`: Stores consumer information and synchronization state

---

## 🔧 Plugin Architecture

### Main Components

#### 1. **ContentManagerPlugin**
Main class located at: `/plugins/content-manager/src/main/java/com/wazuh/contentmanager/ContentManagerPlugin.java`

This is the entry point of the plugin.

#### 2. **ContentIndex**
Located at: `/plugins/content-manager/src/main/java/com/wazuh/contentmanager/index/ContentIndex.java`

Manages operations on the `wazuh-ruleset` index:
- Bulk indexing operations
- Document patching (add, update, delete)
- Query and retrieval operations

#### 3. **ConsumersIndex**
Located at: `/plugins/content-manager/src/main/java/com/wazuh/contentmanager/index/ConsumersIndex.java`

Manages the `.cti-consumers` index which stores:
- Consumer name
- Local offset (last successfully applied change)
- Remote offset (last available offset from the CTI API)
- Snapshot link from where the index was initialized

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


## 🔄 How Content Synchronization Works

### 1. **Initialization Phase**

When the plugin starts on a cluster manager node:

1. Creates the `.cti-consumers` index if it doesn't exist
2. Checks the consumer's local_offset:
   - **If local_offset = 0**: Downloads and indexes a snapshot
   - **If local_offset > 0**: Proceeds with incremental updates

### 2. **Update Phase**

The update process follows these steps:

1. Fetches current consumer information from `.cti-consumers`
2. Compares `local_offset` with `remote_offset` from CTI API
3. If different, fetches changes in batches (max `content_manager.max_changes`)
4. Applies changes using JSON Patch operations (add, update, delete)
5. Updates the local_offset after successful application
6. Repeats until `local_offset == remote_offset`

### 3. **Error Handling**

- **Recoverable errors**: Updates local_offset and retries later
- **Critical failures**: Resets local_offset to 0, triggering snapshot re-initialization

---

## 🔍 Debugging

### Check Consumer Status

```bash
GET /.cti-consumers/_search
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
- CTI API must be accessible for content synchronization
- Offset-based synchronization ensures no content is missed
- Snapshot initialization provides a fast bootstrap mechanism

---

## 🔗 Related Documentation

- [Setup Plugin Guide](./setup.md)
- [OpenSearch Plugin Development](https://opensearch.org/docs/latest/install-and-configure/plugins/)
