# Architecture

The Content Manager plugin operates within the Wazuh Indexer environment. It is composed of several components that handle REST API requests, background job scheduling, content synchronization, user-generated content management, and Engine communication.

## Components

### REST layer

Exposes HTTP endpoints under `/_plugins/_content_manager/` for:
- Subscription management (store CTI access token)
- Manual content sync trigger
- Version check
- CUD operations on rules, decoders, integrations, filters, and KVDBs
- Policy management
- Promotion preview and execution
- Logtest execution (combined, normalization-only, and detection-only)
- Space reset

### Credentials store

Manages the CTI access token used for all CTI API requests. The token is submitted via `POST /subscription`, persisted in the `.wazuh-internal-state` hidden index, and cached in memory. On node startup, the token is loaded from the index into memory. Without a registered token, sync and update operations are rejected.

All HTTP clients that communicate with CTI services send a custom `User-Agent` header in the format `Wazuh Indexer <version>` (e.g., `Wazuh Indexer 5.0.0`). This applies to the Catalog API client, Snapshot client, and Telemetry client.

### Job scheduler

Registers a periodic job that triggers content synchronization at a configurable interval (default: 60 minutes). The job metadata is stored in `.wazuh-content-manager-jobs`.

### Update check service

Runs a daily heartbeat job that calls the CTI Update check API endpoint (`/ping`).

- Enabled by default through `plugins.content_manager.telemetry.enabled`.
- Can be toggled at runtime because it is a dynamic setting.
- Sends deployment metadata required for update checks (cluster UUID, deployed Wazuh version, and user-agent).
- Job metadata is stored in `.wazuh-content-manager-jobs`.
- The first ping is dispatched immediately after the job is registered in the scheduler; subsequent runs follow the 1-day interval.

### Consumer service

Orchestrates synchronization for each catalog consumer type (ruleset, IoCs, vulnerabilities). Compares local offsets (from `.wazuh-cti-consumers`) with remote offsets from the CTI API, then delegates to either the snapshot service or the update service. Tracks the sync lifecycle through the `status` field in `.wazuh-cti-consumers` — see [Index structure](#index-structure) below for the status values.

### Snapshot service

Handles initial content loading. Initializes from either a remote CTI snapshot (when a custom consumer URL is configured) or a local packaged snapshot, then extracts and bulk-indexes content into the appropriate system indices. Performs data enrichment (e.g., converting JSON payloads to YAML for decoders).

### Update service

Handles incremental updates. Fetches change batches from the CTI API based on offset differences and applies create, update, and delete operations to content indices.

### Security Analytics service

Interfaces with the Security Analytics plugin. Creates, updates, and deletes Security Analytics rules, integrations, and detectors to keep them in sync with CTI content.

**Dynamic configuration**: instead of using hardcoded defaults, the service extracts the enabled state, interval, and source index patterns directly from the CTI integration payload. This allows CTI to control detector behavior dynamically.

**Document ID model**: Security Analytics documents use their own auto-generated UUIDs as primary IDs, independent of the CTI document UUIDs. Each Security Analytics document stores the UUID of the original CTI document and the space it belongs to (draft, test, custom, or standard), so the same CTI resource can exist across multiple spaces without ID collisions.

> **Note:** Security Analytics enforces a maximum of 100 rules per detector. If an integration has more than 100 enabled rules, the detector creation or update request will be rejected. See [Security Analytics — Detector constraints](../security-analytics/index.md#detector-constraints) for details.

### Space service

Manages the four content spaces (standard, draft, test, custom). Routes CUD operations to the correct space partitions within system indices. Handles promotion by computing diffs between spaces in the promotion chain (draft → test → custom).

### Engine client

Communicates with the Wazuh Engine via Unix domain socket at `/usr/share/wazuh-indexer/engine/sockets/engine-api.sock`. Used for logtest execution, content validation, and configuration reload.

## Data flows

### CTI sync (snapshot)

```
Job scheduler triggers
  → Consumer service checks .wazuh-cti-consumers (offset = 0)
  → If custom catalog URL is configured: try remote snapshot first
  → If remote init fails: fallback to local packaged snapshot
  → If no custom catalog URL: initialize from local packaged snapshot
  → Extracts and bulk-indexes into wazuh-threatintel-rules, wazuh-threatintel-decoders, etc.
  → Updates .wazuh-cti-consumers with new offset
  → Security Analytics service creates detectors using dynamic CTI configuration (max 100 rules per detector)
```

### CTI sync (incremental)

```
Job scheduler triggers
  → Consumer service checks .wazuh-cti-consumers (local_offset < remote_offset)
  → Update service fetches change batches from CTI API
  → Applies create/update/delete operations to content indices
  → Updates .wazuh-cti-consumers offset
  → Security Analytics service syncs changes
```

### Update check heartbeat

```
Registration (on node start or dynamic enable)
  → Heartbeat job document indexed in .wazuh-content-manager-jobs
  → Immediate first ping fired once the document is written

Job scheduler triggers (every 24h thereafter)
  → Checks plugins.content_manager.telemetry.enabled
  → Reads cluster UUID and current Wazuh version
  → Sends GET /ping to CTI Update check API
  → Wazuh Dashboard can surface update availability to users
```

### User-generated content (CUD)

```
REST request (POST/PUT/DELETE)
  → Space service routes to draft space
  → Writes to wazuh-threatintel-rules / wazuh-threatintel-decoders / wazuh-threatintel-integrations / wazuh-threatintel-kvdbs
  → Returns created/updated/deleted resource
```

### Standard policy Engine loading

The local Wazuh Engine must always reflect the latest version of the standard space policy. Whenever the standard space policy hash changes, the full policy — including all referenced integrations, decoders, KVDBs, filters, and rules — is built and sent to the Engine for loading.

The policy hash is an aggregate SHA-256 computed from the individual hashes of the policy and every resource it references. Any change to the policy will trigger a reload. These changes include:

- New or updated integrations, decoders, rules, KVDBs, or filters (via CTI sync)
- Changes to policy settings (`enabled`, `index_unclassified_events`, `index_discarded_events`)
- Changes to the enrichment types list
- Reordering of the filters list

The engine load is best-effort: if the Engine is unreachable, the error is logged but the operation (sync or REST update) still succeeds.

### Promotion

```
GET /promote?space=draft
  → Space service computes diff (draft vs test, or test vs custom)
  → Returns changes preview (adds, updates, deletes per content type)

POST /promote
  → Capture pre-promotion snapshots of target-space resources
  → Engine validates configuration (draft → test only, and only when the
    changeset includes decoders, kvdbs, or filters — promotions limited to
    integrations, rules, or the policy skip the engine call)
  → Consolidate changes to Content Manager indices (tracked for rollback)
      → Apply adds/updates: policy, integrations, kvdbs, decoders, filters, rules
      → Apply deletes: integrations, kvdbs, decoders, filters, rules
  → Sync integrations and rules to Security Analytics:
      → Adds use POST (new document)
      → Updates use PUT (existing document)
  → Delete removed integrations/rules from Security Analytics
```

### Rollback on failure

If any Content Manager index mutation fails during the consolidation phase, the promotion endpoint automatically performs a last-in-first-out (LIFO) rollback to restore the system to its pre-promotion state.

#### Pre-promotion snapshots

Before any writes, the system captures:
- **Old versions**: for each resource being added or updated, the current target-space version is fetched and stored. If the resource does not exist in the target space, no version is stored.
- **Delete snapshots**: for each resource being deleted, the full document is fetched from the source space and stored.

#### Content Manager index rollback

Each successful index mutation is recorded as a rollback step. On failure, steps are replayed in strict reverse (LIFO) order:

| Forward operation | Old version | Rollback action |
|---|---|---|
| Add (apply) | none | Delete the newly created document |
| Update (apply) | exists | Restore the previous version |
| Delete | snapshot | Re-index the snapshotted document |

Individual rollback step failures are logged and skipped so remaining steps can proceed.

#### Security Analytics reconciliation

After the Content Manager rollback completes, a best-effort Security Analytics reconciliation runs in dependency order:

1. **Revert applied rules** — adds are deleted from Security Analytics; updates are restored to the old version.
2. **Revert applied integrations** — same as above.
3. **Restore deleted integrations** — re-created from pre-deletion snapshots via POST.
4. **Restore deleted rules** — same as above.

Security Analytics reconciliation failures are logged as warnings but do not cause the overall rollback to fail, since the sync is considered best-effort.

```
Consolidation fails at step N
  → LIFO rollback: undo step N-1, N-2, ..., 1
      → Add + no old version → delete from target index
      → Add/update + old version → restore old version to target index
      → Delete → re-index snapshot to target index
  → Security Analytics reconciliation (best-effort):
      → Delete rules that were added
      → Restore rules that were updated
      → Restore integrations that were added/updated
      → Re-create integrations/rules that were deleted
  → Return 500 with error message
```

## Plan change handling (blue/green swap)

When a subscription plan changes (e.g., free → pro, or vice versa), all downloaded content must be replaced with the content matching the new plan. The Content Manager uses a **blue/green index swap** to perform this replacement without any user-visible downtime.

### How it works

1. **Detection.** During each sync cycle, the Content Manager compares the plan-provided catalog URL against the one stored locally. If they differ, a plan change is detected.
2. **Shadow download.** New content is downloaded into hidden staging indices. These shadow indices are invisible to users, dashboards, and REST queries during the rebuild.
3. **User content preservation.** Any user-created content (draft rules, test decoders, custom integrations, etc.) is copied from the live indices into the shadow indices.
4. **Atomic switch.** Once the shadow indices are fully ready, all index aliases are swapped in a single atomic operation. Users see either the entire old content or the entire new content — never a mix or an empty state.
5. **Cleanup.** The old indices are deleted, freeing the temporary disk space.

### Failure behavior

If the new content cannot be downloaded or processed (network error, source unavailable, etc.), the swap is abandoned cleanly: the staging indices are discarded, users continue to see the old content, and the system retries on the next scheduled sync. A failed swap is invisible to the end user.

## Index structure

Each content index (e.g., `wazuh-threatintel-rules`) is backed by an **alias**. The public alias name is the stable identifier used by all queries, dashboards, and REST APIs. The actual data lives in a physical index suffixed with `-a` or `-b`:

| Public alias (stable name) | Physical index (actual storage) |
|---|---|
| `wazuh-threatintel-rules` | `wazuh-threatintel-rules-a` or `wazuh-threatintel-rules-b` |

Only one physical index is live at a time. The other is reserved as the staging slot for the next plan-change swap. Administrators and users should always address indices by their alias name — the physical suffix is an internal implementation detail.

Each content index stores documents from all spaces. Documents are differentiated by internal metadata fields that indicate their space membership. The document `_id` is a UUID assigned at creation time.

Example document structure in `wazuh-threatintel-rules`:

```json
{
  "_index": "wazuh-threatintel-rules-a",
  "_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "_source": {
    "title": "SSH brute force attempt",
    "integration": "openssh",
    "space.name": "draft",
    ...
  }
}
```

The `.wazuh-cti-consumers` index stores one document per consumer type:

```json
{
  "_index": ".wazuh-cti-consumers",
  "_id": "cti:catalog:consumer:ruleset",
  "_source": {
    "name": "public-ruleset-5",
    "context": "beta-2-ruleset-5",
    "type": "cti:catalog:consumer:ruleset",
    "resource": "https://api.pre.cloud.wazuh.com/api/v1/catalog/contexts/beta-2-ruleset-5/consumers/public-ruleset-5",
    "is_public": true,
    "status": "ready",
    "local_offset": 3932,
    "remote_offset": 3932
  }
}
```

The `status` field reflects the consumer's synchronization lifecycle:

| Value | Meaning |
| --------- | ----------------------------------------------------------------------- |
| `ready` | Sync is complete; content indices are up-to-date and safe to read. |
| `running` | Sync is in progress; content may be partially written or inconsistent. |
| `failed` | The previous sync cycle was interrupted by an unexpected exception. |

The status is set to `running` at the very start of a sync cycle and transitions to `ready` after all post-sync work finishes — including hash recalculation, Security Analytics Plugin synchronization, and Engine IoC notification — or to `failed` if an unexpected exception interrupts the cycle. The job scheduler logs the failure and retries on the next scheduled run regardless of the consumer's status.
