# Architecture

The Content Manager plugin operates within the Wazuh Indexer environment. It is composed of several components that handle REST API requests, background job scheduling, content synchronization, user-generated content management, and Engine communication.

## Components

### REST Layer

Exposes HTTP endpoints under `/_plugins/_content_manager/` for:
- Subscription management (register, get, delete CTI tokens)
- Manual content sync trigger
- CUD operations on rules, decoders, integrations, and KVDBs
- Policy management
- Promotion preview and execution
- Logtest execution
- Content validation and promotion

### CTI Console

Manages authentication with the Wazuh CTI API. Stores subscription tokens used for all CTI requests. Without a valid token, sync operations are rejected.

### Job Scheduler (CatalogSyncJob)

Implements the OpenSearch `JobSchedulerExtension` interface. Registers a periodic job (`wazuh-catalog-sync-job`) that triggers content synchronization at a configurable interval (default: 60 minutes). The job metadata is stored in `.wazuh-content-manager-jobs`.

### Consumer Service

Orchestrates synchronization for each context/consumer pair. Compares local offsets (from `.cti-consumers`) with remote offsets from the CTI API, then delegates to either the Snapshot Service or Update Service.

### Snapshot Service

Handles initial content loading. Downloads a ZIP snapshot from the CTI API, extracts it, and bulk-indexes content into the appropriate system indices. Performs data enrichment (e.g., converting JSON payloads to YAML for decoders).

### Update Service

Handles incremental updates. Fetches change batches from the CTI API based on offset differences and applies create, update, and delete operations to content indices.

### Security Analytics Service

Interfaces with the OpenSearch Security Analytics plugin. Creates, updates, and deletes Security Analytics rules, integrations, and detectors to keep them in sync with CTI content.

### Space Service

Manages the four content spaces (standard, draft, test, custom). Routes CUD operations to the correct space partitions within system indices. Handles promotion by computing diffs between spaces in the promotion chain (Draft → Test → Custom).

### Engine Client

Communicates with the Wazuh Engine via Unix domain socket at `/usr/share/wazuh-indexer/engine/sockets/engine-api.sock`. Used for logtest execution, content validation, and configuration reload.

## Data Flows

### CTI Sync (Snapshot)

```
Job Scheduler triggers
  → Consumer Service checks .cti-consumers (offset = 0)
  → Snapshot Service downloads ZIP from CTI API
  → Extracts and bulk-indexes into .cti-rules, .cti-decoders, etc.
  → Updates .cti-consumers with new offset
  → Security Analytics Service creates detectors
```

### CTI Sync (Incremental)

```
Job Scheduler triggers
  → Consumer Service checks .cti-consumers (local_offset < remote_offset)
  → Update Service fetches change batches from CTI API
  → Applies CREATE/UPDATE/DELETE to content indices
  → Updates .cti-consumers offset
  → Security Analytics Service syncs changes
```

### User-Generated Content (CUD)

```
REST request (POST/PUT/DELETE)
  → Space Service routes to draft space
  → Writes to .cti-rules / .cti-decoders / .cti-integrations / .cti-kvdbs
  → Returns created/updated/deleted resource
```

### Promotion

```
GET /promote?space=draft
  → Space Service computes diff (draft vs standard)
  → Returns changes preview (adds, updates, deletes per content type)

POST /promote
  → Space Service sends draft content to Engine via Unix socket
  → Engine validates configuration
  → Engine reloads configuration
  → Standard space updated to match promoted content
```

## Index Structure

Each content index (e.g., `.cti-rules`) stores documents from all three spaces. Documents are differentiated by internal metadata fields that indicate their space membership. The document `_id` is a UUID assigned at creation time.

Example document structure in `.cti-rules`:

```json
{
  "_index": ".cti-rules",
  "_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "_source": {
    "title": "SSH brute force attempt",
    "integration": "openssh",
    "space.name": "draft",
    ...
  }
}
```

The `.cti-consumers` index stores one document per context/consumer pair:

```json
{
  "_index": ".cti-consumers",
  "_id": "development_0.0.3_development_0.0.3_test",
  "_source": {
    "name": "development_0.0.3_test",
    "context": "development_0.0.3",
    "local_offset": 3932,
    "remote_offset": 3932,
    "snapshot_link": "https://cti-pre.wazuh.com/store/contexts/development_0.0.3/consumers/development_0.0.3_test/3932_1770988130.zip"
  }
}
```
