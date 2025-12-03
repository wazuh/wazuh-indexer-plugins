# Architecture

The Content Manager plugin operates within the Wazuh Indexer environment. It is composed of several key components that handle REST API requests, background job scheduling, and content synchronization logic.

## High-Level Components

### 1. REST Layer
The plugin exposes a set of REST endpoints under `/_plugins/content-manager/` to manage subscriptions and trigger updates. These handlers interact with the `CtiConsole` and `CatalogSyncJob` to perform operations.

### 2. CTI Console
The `CtiConsole` acts as the authentication manager. It handles the storage and retrieval of authentication tokens required to communicate with the remote Wazuh CTI API.

### 3. Job Scheduler & Sync Job
The plugin implements the `JobSchedulerExtension` to register the `CatalogSyncJob`. This job runs periodically (configured via `content_manager.catalog.sync_interval`) to synchronize content. It manages synchronization for different contexts, such as `rules` and `decoders`.

## Synchronization Services

The core logic is divided into three services:

* **Consumer Service (`ConsumerServiceImpl`)**:
    * Manages the state of "Consumers" (entities that consume content, e.g., a Rules consumer).
    * Compares the local state (stored in the `.cti-consumers` index) with the remote state from the CTI API.
    * Decides whether to perform a Snapshot Initialization or a Differential Update.

* **Snapshot Service (`SnapshotServiceImpl`)**:
    * Used when a consumer is new or empty.
    * Downloads a full ZIP snapshot from the CTI provider.
    * Extracts the content and indexes it into specific indices (e.g., `.cti-rules`).
    * Performs data enrichment, such as converting JSON payloads to YAML for decoders.

* **Update Service (`UpdateServiceImpl`)**:
    * Used when the local content is behind the remote content.
    * Fetches a list of changes based on the current offset.
    * Applies operations (CREATE, UPDATE, DELETE) to the content indices.
    * Updates the consumer offset upon success.

## Data Persistence

The plugin uses system indices to store data:
* **`.cti-consumers`**: Stores metadata about the synchronization state (offsets, snapshot links) for each consumer.
* **Content Indices**: Stores the actual CTI content.