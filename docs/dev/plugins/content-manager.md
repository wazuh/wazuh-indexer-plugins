# Wazuh Indexer Content Manager Plugin — Development Guide

This document describes how to extend and configure the Wazuh Indexer Content Manager plugin, which is responsible for managing and synchronizing security content from the Wazuh CTI API.

---

## 📋 Overview

The Content Manager plugin handles:
- **Authentication** Manages subscriptions and tokens with the CTI Console.
- **Job Scheduling** Periodically checks for updates using the OpenSearch Job Scheduler.
- **Content Synchronization** Keeps local indices in sync with the Wazuh CTI Catalog.
- **Snapshot Initialization** Downloads and indexes full content via zip snapshots.
- **Incremental Updates** Applies JSON Patch operations based on offsets.
- **Context management** to maintain synchronization state

The plugin manages several indices:
- `.cti-consumers`: Stores consumer information and synchronization state
- `.wazuh-content-manager-jobs`: Stores job scheduler metadata.
- Content Indices: Indices for specific content types following the naming `.<context>-<consumer>-<type>`.

---

## 🔧 Plugin Architecture

### Main Components

#### 1. **ContentManagerPlugin**
Main class located at: `/plugins/content-manager/src/main/java/com/wazuh/contentmanager/ContentManagerPlugin.java`

This is the entry point of the plugin:
- Registers REST handlers for subscription and update management.
- Initializes the `CatalogSyncJob` and schedules it via the OpenSearch Job Scheduler.
- Initializes the `CtiConsole` for authentication management.

#### 2. **CatalogSyncJob**
Located at: `/plugins/content-manager/src/main/java/com/wazuh/contentmanager/jobscheduler/jobs/CatalogSyncJob.java`

This class acts as the orchestrator (`JobExecutor`). It is responsible for:
- Executing the content synchronization logic
- Managing concurrency using semaphores to prevent overlapping jobs.
- Determining whether to trigger a Snapshot Initialization or an Incremental Update based on consumer offsets.

#### 3. **Services**
The logic is split into specialized services:

##### 3.1 **ConsumerService**
Located at: `/plugins/content-manager/src/main/java/com/wazuh/contentmanager/cti/catalog/service/ConsumerServiceImpl.java`

Retrieves `LocalConsumer` state from `.cti-consumers` and `RemoteConsumer` state from the CTI API.

##### 3.2 **SnapshotService**
Located at: `/plugins/content-manager/src/main/java/com/wazuh/contentmanager/cti/catalog/service/SnapshotServiceImpl.java`

Handles downloading zip snapshots, unzipping, parsing JSON files, and bulk indexing content when a consumer is new or reset.

##### 3.3 **UpdateService**
Located at: `/plugins/content-manager/src/main/java/com/wazuh/contentmanager/cti/catalog/service/UpdateServiceImpl.java`

Fetches specific changes (offsets) from the CTI API and applies them using JSON Patch (`Operation` class).

##### 3.4 **AuthService**
Located at: `/plugins/content-manager/src/main/java/com/wazuh/contentmanager/cti/console/service/AuthServiceImpl.java`

Manages the exchange of device codes for permanent access tokens.

#### 4. **Indices Management**

##### 4.1 **ConsumersIndex**
Located at: `/plugins/content-manager/src/main/java/com/wazuh/contentmanager/cti/catalog/index/ConsumersIndex.java`

Wraps operations for the `.cti-consumers` index.

##### 4.2 **ContentIndex**
Located at: `/plugins/content-manager/src/main/java/com/wazuh/contentmanager/cti/catalog/index/ContentIndex.java`

Manages operations for content indices. 

---

## ⚙️ Configuration Settings

The plugin is configured through the `PluginSettings` class. Settings can be defined in `opensearch.yml`:

| Setting                                 | Default                            | Description                                                                  |
|-----------------------------------------|------------------------------------|------------------------------------------------------------------------------|
| `content_manager.cti.api`               | `https://cti-pre.wazuh.com/api/v1` | Base URL for the Wazuh CTI API.                                              |
| `content_manager.catalog.sync_interval` | `60`                               | Interval (in minutes) for the periodic synchronization job.                  |
| `content_manager.max_items_per_bulk`    | `25`                               | Maximum number of documents per bulk request during snapshot initialization. |
| `content_manager.max_concurrent_bulks`  | `5`                                | Maximum number of concurrent bulk requests.                                  |
| `content_manager.client.timeout`        | `10`                               | Timeout (in seconds) for HTTP and Indexing operations.                       |


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

Resets local_offset to 0, triggering snapshot re-initialization

## 📡 REST API

### Subscription Management

#### GET /subscription

Retrieves the current subscription token. 

`GET /_plugins/content-manager/subscription`

#### POST /subscription 

Creates or updates a subscription. 

`POST /_plugins/content-manager/subscription { "device_code": "...", "client_id": "...", "expires_in": 3600, "interval": 5 }`

#### DELETE /subscription

Deletes the current token/subscription. 

`DELETE /_plugins/content-manager/subscription`

### Update Trigger

#### POST /update 

Manually triggers the `CatalogSyncJob`. 

`POST /_plugins/content-manager/update`

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
GET /.cti-rules/_search
{
  "size": 10
}
```

### Monitor Plugin Logs

Look for entries from `ContentManagerPlugin`, `CatalogSyncJob`, `SnapshotServiceImpl`  and `UpdateServiceImpl` in the OpenSearch logs.

```bash
tail -f logs/opensearch.log | grep -E "ContentManager|CatalogSyncJob|SnapshotServiceImpl|UpdateServiceImpl"
```

---

## 📌 Important Notes

- The plugin only runs on **cluster manager nodes**
- CTI API must be accessible for content synchronization
- Offset-based synchronization ensures no content is missed

---

## 🔗 Related Documentation

- [Setup Plugin Guide](./setup.md)
- [OpenSearch Plugin Development](https://opensearch.org/docs/latest/install-and-configure/plugins/)
