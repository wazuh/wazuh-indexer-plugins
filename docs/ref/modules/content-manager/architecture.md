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

### Update Check Service (TelemetryPingJob)

Implements a daily heartbeat job (`wazuh-telemetry-ping-job`) that calls the CTI Update check API endpoint (`/ping`).

- Enabled by default through `plugins.content_manager.telemetry.enabled`.
- Can be toggled at runtime because it is a dynamic setting.
- Sends deployment metadata required for update checks (cluster UUID and deployed Wazuh version).
- Job metadata is stored in `.wazuh-content-manager-jobs`.

### Consumer Service

Orchestrates synchronization for each context/consumer pair. Compares local offsets (from `.wazuh-cti-consumers`) with remote offsets from the CTI API, then delegates to either the Snapshot Service or Update Service. Tracks the sync lifecycle through the `status` field in `.wazuh-cti-consumers`: set to `updating` at the start of `synchronize()` and back to `idle` only once all post-sync work (hash recalculation, Security Analytics sync, Engine notification) is complete.

### Snapshot Service

Handles initial content loading. Downloads a ZIP snapshot from the CTI API, extracts it, and bulk-indexes content into the appropriate system indices. Performs data enrichment (e.g., converting JSON payloads to YAML for decoders).

### Update Service

Handles incremental updates. Fetches change batches from the CTI API based on offset differences and applies create, update, and delete operations to content indices.

### Security Analytics Service

Interfaces with the OpenSearch Security Analytics plugin. Creates, updates, and deletes Security Analytics rules, integrations, and detectors to keep them in sync with CTI content.

**Document ID model**: SAP documents use their own auto-generated UUIDs as primary IDs, independent of the CTI document UUIDs. Each SAP document stores:
- `document.id` — the UUID of the original CTI document in the Content Manager.
- `source` — the space the document belongs to, with the first letter capitalized (e.g., "Draft", "Test", "Custom", or "Sigma" for standard).

This design allows the same CTI resource to exist across multiple spaces without ID collisions. Association and lookup between CTI and SAP documents is performed by querying `document.id` + `source`.

> **Note:** SAP enforces a maximum of 100 rules per detector. If an integration has more than 100 enabled rules, the detector creation or update request will be rejected. See [Security Analytics — Detector constraints](../security-analytics/index.md#detector-constraints) for details.

### Space Service

Manages the four content spaces (standard, draft, test, custom). Routes CUD operations to the correct space partitions within system indices. Handles promotion by computing diffs between spaces in the promotion chain (Draft → Test → Custom).

### Engine Client

Communicates with the Wazuh Engine via Unix domain socket at `/usr/share/wazuh-indexer/engine/sockets/engine-api.sock`. Used for logtest execution, content validation, and configuration reload.

## Data Flows

### CTI Sync (Snapshot)

```
Job Scheduler triggers
  → Consumer Service checks .wazuh-cti-consumers (offset = 0)
  → Snapshot Service downloads ZIP from CTI API
  → Extracts and bulk-indexes into wazuh-threatintel-rules, wazuh-threatintel-decoders, etc.
  → Updates .wazuh-cti-consumers with new offset
  → Security Analytics Service creates detectors (max 100 rules per detector)
```

### CTI Sync (Incremental)

```
Job Scheduler triggers
  → Consumer Service checks .wazuh-cti-consumers (local_offset < remote_offset)
  → Update Service fetches change batches from CTI API
  → Applies CREATE/UPDATE/DELETE to content indices
  → Updates .wazuh-cti-consumers offset
  → Security Analytics Service syncs changes
```

### Update Check Heartbeat

```
Job Scheduler triggers (every 24h)
  → TelemetryPingJob checks plugins.content_manager.telemetry.enabled
  → Reads cluster UUID and current Wazuh version
  → TelemetryClient sends GET /ping to CTI Update check API
  → Wazuh Dashboard can surface update availability to users
```

### User-Generated Content (CUD)

```
REST request (POST/PUT/DELETE)
  → Space Service routes to draft space
  → Writes to wazuh-threatintel-rules / wazuh-threatintel-decoders / wazuh-threatintel-integrations / wazuh-threatintel-kvdbs
  → Returns created/updated/deleted resource
```

### Standard Policy Engine Loading

The local Wazuh Engine must always reflect the latest version of the standard space policy. Whenever the standard space `space.hash` changes, the full policy — including all referenced integrations, decoders, kvdbs, filters, and rules — is built and sent to the Engine via `EngineService.promote()`.

The `space.hash` is an aggregate SHA-256 computed from the individual hashes of the policy and every resource it references. Any change to the policy will trigger a reload. These changes include:

- New or updated integrations, decoders, rules, kvdbs, or filters (via CTI sync)
- Changes to policy settings (`enabled`, `index_unclassified_events`, `index_discarded_events`)
- Changes to the enrichment types list
- Reordering of the filters list

The engine load is best-effort: if the Engine is unreachable, the error is logged but the operation (sync or REST update) still succeeds.

### Promotion

```
GET /promote?space=draft
  → Space Service computes diff (draft vs test, or test vs custom)
  → Returns changes preview (adds, updates, deletes per content type)

POST /promote
  → Capture pre-promotion snapshots of target-space resources
  → Engine validates configuration (draft → test only)
  → Consolidate changes to CM indices (tracked for rollback)
      → Apply adds/updates: policy, integrations, kvdbs, decoders, filters, rules
      → Apply deletes: integrations, kvdbs, decoders, filters, rules
  → Sync integrations and rules to SAP:
      → ADDs use POST (new SAP document)
      → UPDATEs use PUT (existing SAP document)
  → Delete removed integrations/rules from SAP
```

### Rollback on Failure

If any Content Manager index mutation fails during the consolidation phase, the
promotion endpoint automatically performs a LIFO (Last-In, First-Out) rollback
to restore the system to its pre-promotion state.

#### Pre-Promotion Snapshots

Before any writes, the system captures:
- **Old versions** (`captureOldVersions`): For each resource being added or updated,
  the current target-space version is fetched and stored. If the resource does not exist
  in the target space, `null` is stored.
- **Delete snapshots** (`captureDeleteSnapshots`): For each resource being deleted, the
  full document is fetched from the source space and stored.

#### CM Index Rollback

Each successful index mutation is recorded as a `RollbackStep(kind, resourceType)`. On
failure, steps are replayed in strict reverse (LIFO) order:

| Forward operation | Old version | Rollback action |
|---|---|---|
| ADD (apply) | `null` | Delete the newly created document |
| UPDATE (apply) | non-null | Restore the previous version |
| DELETE | snapshot | Re-index the snapshotted document |

Individual rollback step failures are logged and skipped so remaining steps can proceed.

#### SAP Reconciliation

After CM rollback completes, a best-effort SAP reconciliation runs in dependency order:

1. **Revert applied rules** — ADDs are deleted from SAP; UPDATEs are restored to old version.
2. **Revert applied integrations** — Same as above.
3. **Restore deleted integrations** — Re-created from pre-deletion snapshots via POST.
4. **Restore deleted rules** — Same as above.

SAP reconciliation failures are logged as warnings but do not cause the overall rollback
to fail, since SAP sync is considered best-effort.

```
Consolidation fails at step N
  → LIFO rollback: undo step N-1, N-2, ..., 1
      → APPLY + null old version → delete from target index
      → APPLY + old version → restore old version to target index
      → DELETE → re-index snapshot to target index
  → SAP reconciliation (best-effort):
      → Delete rules that were added to SAP
      → Restore rules that were updated in SAP
      → Restore integrations that were added/updated in SAP
      → Re-create integrations/rules that were deleted from SAP
  → Return 500 with error message
```

## Index Structure

Each content index (e.g., `wazuh-threatintel-rules`) stores documents from all three spaces. Documents are differentiated by internal metadata fields that indicate their space membership. The document `_id` is a UUID assigned at creation time.

Example document structure in `wazuh-threatintel-rules`:

```json
{
  "_index": "wazuh-threatintel-rules",
  "_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "_source": {
    "title": "SSH brute force attempt",
    "integration": "openssh",
    "space.name": "draft",
    ...
  }
}
```

The `.wazuh-cti-consumers` index stores one document per context/consumer pair:

```json
{
  "_index": ".wazuh-cti-consumers",
  "_id": "t1-ruleset-5_public-ruleset-5",
  "_source": {
    "name": "public-ruleset-5",
    "context": "t1-ruleset-5",
    "status": "idle",
    "local_offset": 3932,
    "remote_offset": 3932,
    "snapshot_link": "https://api.pre.cloud.wazuh.com/store/contexts/t1-ruleset-5/consumers/public-ruleset-5/168_1776070234.zip"
  }
}
```

The `status` field reflects the consumer's synchronization lifecycle:

| Value | Meaning |
| --------- | ----------------------------------------------------------------------- |
| `idle` | Sync is complete; content indices are up-to-date and safe to read. |
| `updating` | Sync is in progress; content may be partially written or inconsistent. |

The status is set to `updating` at the very start of a sync cycle and only transitions back to `idle` after all post-sync work finishes — including hash recalculation, Security Analytics Plugin synchronization, and Engine IoC notification. If a sync fails mid-cycle, the status remains `updating` as an observable failure signal.
