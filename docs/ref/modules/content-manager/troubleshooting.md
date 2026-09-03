# Troubleshooting

Common issues and diagnostic procedures for the Content Manager plugin.

## Common errors

### "Error communicating with Engine socket: Connection refused"

The Wazuh Engine is not running or the Unix socket is not accessible.

Resolution:
1. Check the socket file exists:
   ```bash
   ls -la /usr/share/wazuh-indexer/engine/sockets/engine-api-http.sock
   ```

2. Ensure the Wazuh Indexer process has permission to access the socket file.

### "Token not found"

No CTI access token has been registered. The Content Manager cannot sync content without a valid token.

#### Resolution

Register credentials by posting the CTI access token:
```bash
curl -sk -u admin:admin -X POST \
  "https://127.0.0.1:9200/_plugins/_content_manager/subscription" \
  -H 'Content-Type: application/json' \
  -d '{
    "access_token": "<your-cti-access-token>"
  }'
```

A successful registration returns `{"message":"Credentials received","status":201}`. The token is persisted in `.wazuh-internal-state` and loaded into memory immediately.

### Sync not running

Content is not being updated despite having a valid subscription.

#### Diagnosis

1. Check consumer state and offsets:
   ```bash
   curl -sk -u admin:admin \
     "https://127.0.0.1:9200/.wazuh-cti-consumers/_search?pretty"
   ```

   If `local_offset` equals `remote_offset`, the content is already up-to-date.

2. Check the sync job is registered and enabled:
   ```bash
   curl -sk -u admin:admin \
     "https://127.0.0.1:9200/.wazuh-content-manager-jobs/_search?pretty"
   ```

   Verify the job has `"enabled": true` and the schedule interval matches your configuration.

3. Check if scheduled sync is enabled in `opensearch.yml`:
   ```yaml
   plugins.content_manager.catalog.update_on_schedule: true
   ```

4. Trigger a manual sync to test:
   ```bash
   curl -sk -u admin:admin -X POST \
     "https://127.0.0.1:9200/_plugins/_content_manager/update"
   ```

### Engine validation rejects a temporary field

**Symptoms:** Creating or updating a decoder (or any resource with a `check`/`detection` expression) fails with an Engine validation error naming a field that looks correct, for example:

```
{"message":"Engine validation failed. Failed to validate resource of type 'decoder': Validation failed for 'decoder': Failed to build operation 'tmp_json.event.action: string_equal(\"netflow_flow\")': Field 'tmp_json.event.action' is not defined in WCS schema and is not a temporary field"}
```

**Cause:** The Engine validates every field referenced in a `check` or `detection` expression against the Wazuh Common Schema (WCS). A field that is intentionally temporary — used only during decoding and not part of the final normalized event — is not in WCS by definition, so the Engine only accepts it if it's prefixed with an underscore.

#### Resolution

Prefix temporary fields with `_` in both the check expression and anywhere else the field is referenced within the same resource:

```json
{
  "check": [
    {
      "_tmp_json.event.action": "string_equal(\"netflow_flow\")"
    }
  ]
}
```

Fields that are part of WCS (e.g., `event.action`, `source.ip`) never need the underscore prefix — only add it for genuinely temporary, decoder-internal fields.

### Socket file not found

The Unix socket used for Engine communication does not exist.

**Expected path:** `/usr/share/wazuh-indexer/engine/sockets/engine-api-http.sock`

#### Resolution

1. Verify the Wazuh Engine is installed and running.
2. Check the Engine configuration for the socket path.
3. Ensure the `engine/sockets/` directory exists under the Wazuh Indexer installation path.

### Sync fails with a request timeout during a CTI rate-limit

A synchronization pass fails and the log shows a timeout on a CTI request, e.g.:

```
Error during content update: Timeout deadline: 10000 MILLISECONDS, actual: 10000 MILLISECONDS
```

This means the CTI API rate-limited the request (HTTP 429). The client now honors the response `Retry-After` header and retries automatically (see [CTI rate-limit retries](configuration.md#cti-rate-limit-retries-http-429)), so a transient rate-limit self-recovers within the pass.

#### Resolution

1. If the failure is transient, no action is needed — the request is retried and the next scheduled sync resumes from the last checkpoint (no data is lost or duplicated).
2. If 429s persist across passes, the instance is being rate-limited by CTI for longer than the retry budget. Increase `plugins.content_manager.client.max_retries` and/or `plugins.content_manager.client.retry_backoff_base_seconds`.
3. Look for the warning `CTI API rate-limited request [...] (HTTP 429); retrying in {}s` in the logs to confirm the retry path is engaging.

### Resource creation fails with a missing `indices:admin/create` permission

A `POST` to `/rules`, `/decoders`, `/integrations`, `/kvdbs` or `/filters` returns HTTP 429 with
`Too many concurrent requests creating this resource. Please retry.` even though there is no
concurrency, and the indexer log shows the security plugin denying `indices:admin/create` on the lock
index for the requesting user:

```
[INFO ][o.o.s.p.PrivilegesEvaluatorImpl] No index-level perm match for User [name=wazuh-demo, ...]
  Resolved [... allIndices=[.wazuh-content-manager-resource-locks] ...]:
  Insufficient permissions for the referenced index [Action [indices:admin/create]]
[WARN ][c.w.c.t.AbstractTransportCreateAction] Failed to acquire resource-creation lock for [integration]:
  no permissions for [indices:admin/create] and User [name=wazuh-demo, ...]
```

The `.wazuh-content-manager-resource-locks` index is created at node startup and every operation on
it runs as the plugin, so this can only happen on a node that never completed that startup step
(check the log for `Failed to create .wazuh-content-manager-resource-locks index, due to: ...`).

Note that the index is hidden and has no alias, so its absence cannot be confirmed with
`_cat/aliases` or a plain `_cat/indices`.

#### Resolution

1. Confirm whether the index exists:

   ```bash
   curl -k -u user:pass "https://localhost:9200/_cat/indices/.wazuh-content-manager-resource-locks?expand_wildcards=all&v"
   ```

2. If it is missing, restart the node — the plugin recreates it during initialization — and check the
   startup log for the reason it failed the first time (a red cluster or a node still joining are the
   usual causes).
3. If a restart is not an option, create it manually with an account that holds
   `indices:admin/create` (for example via the admin certificate). Only the `acquired_at` field is
   needed:

   ```bash
   curl -k -u admin:pass -X PUT "https://localhost:9200/.wazuh-content-manager-resource-locks" \
     -H 'Content-Type: application/json' -d '{
       "settings": { "index": { "number_of_replicas": 0, "auto_expand_replicas": "0-1", "hidden": true, "refresh_interval": "-1" } },
       "mappings": { "dynamic": "strict", "properties": { "acquired_at": { "type": "long" } } }
     }'
   ```

4. Do **not** add `indices:admin/create` to the user's role to work around this. No role needs
   index-level privileges on the lock index — see
   [Access control — Plugin-internal indices](../../security/access-control.md#plugin-internal-indices).

## Diagnostic commands

### Check consumer state

View synchronization state for all content contexts:

```bash
curl -sk -u admin:admin \
  "https://127.0.0.1:9200/.wazuh-cti-consumers/_search?pretty"
```

Example output:

```json
{
  "hits": {
    "hits": [
      {
        "_id": "cti:catalog:consumer:ruleset",
        "_source": {
          "name": "public-ruleset-5",
          "context": "beta-2-ruleset-5",
          "type": "cti:catalog:consumer:ruleset",
          "resource": "https://api.pre.cloud.wazuh.com/api/v1/catalog/contexts/beta-2-ruleset-5/consumers/public-ruleset-5",
          "is_public": true,
          "status": "ready",
          "local_offset": 3932,
          "remote_offset": 3932,
          "pending_sync_phases": []
        }
      }
    ]
  }
}
```

- `status == ready`: Sync is complete; content is safe to read.
- `status == running`: Sync is in progress. If this persists after a sync should have finished, the node process may have been interrupted (e.g. killed) mid-cycle without a chance to record `failed`.
- `status == failed`: The previous sync cycle was interrupted by an unexpected exception. Check the Content Manager logs around the time this consumer was last synced; the job retries automatically on its next scheduled run.
- `local_offset == remote_offset`: Content is up-to-date.
- `local_offset < remote_offset`: Content needs updating.
- `local_offset == 0`: Content has never been synced (snapshot required).
- `pending_sync_phases`: for the ruleset consumer, lists which of `integrations`, `rules`, and `detectors` failed to sync to Security Analytics and are retried on the next scheduled sync; empty means all sub-phases are in sync.

### Check sync job

View the periodic sync job configuration:

```bash
curl -sk -u admin:admin \
  "https://127.0.0.1:9200/.wazuh-content-manager-jobs/_search?pretty"
```

### Count content documents

Check how many rules, decoders, etc. have been indexed:

```bash
# Rules
curl -sk -u admin:admin "https://127.0.0.1:9200/wazuh-threatintel-rules/_count?pretty"

# Decoders
curl -sk -u admin:admin "https://127.0.0.1:9200/wazuh-threatintel-decoders/_count?pretty"

# Integrations
curl -sk -u admin:admin "https://127.0.0.1:9200/wazuh-threatintel-integrations/_count?pretty"

# KVDBs
curl -sk -u admin:admin "https://127.0.0.1:9200/wazuh-threatintel-kvdbs/_count?pretty"

# IoCs
curl -sk -u admin:admin "https://127.0.0.1:9200/wazuh-threatintel-enrichments/_count?pretty"
```

## Job scheduling on startup

During node startup, `scheduleCatalogSyncJob` and `scheduleTelemetryPingJob` both require the `.wazuh-content-manager-jobs` index to reach yellow status with at least one active shard before they can register their job documents. On a freshly initialized or resource-constrained cluster this can time out, producing entries like:

```
INFO   ... Failed to schedule Telemetry Ping Job: Index .wazuh-content-manager-jobs not ready
INFO   ... Retrying Telemetry Ping Job (attempt 1/3) in 15s.
```

The plugin automatically retries each registration up to 3 times with a linear backoff (15 s, 30 s, 45 s). Each attempt logs the failure reason and the scheduled retry delay at `INFO` — these are expected during startup and do not require action.

If all retries fail, the plugin logs `ERROR ... Giving up scheduling <job> after 3 attempts.` and the job will only be retried on the next node start. A persistent failure usually indicates the cluster cannot allocate shards — check cluster health with `GET _cluster/health` and verify index allocation settings.

## Log monitoring

Content Manager logs are part of the Wazuh Indexer logs. Use the following patterns to filter relevant entries:

```bash
# General Content Manager activity
grep -i "content.manager\|ContentManager\|CatalogSync" \
  /var/log/wazuh-indexer/wazuh-indexer.log

# Sync job execution
grep -i "CatalogSyncJob\|consumer-sync" \
  /var/log/wazuh-indexer/wazuh-indexer.log

# CTI API communication
grep -i "cti\|CTIClient" \
  /var/log/wazuh-indexer/wazuh-indexer.log

# Engine socket communication
grep -i "engine.*socket\|EngineClient" \
  /var/log/wazuh-indexer/wazuh-indexer.log

# Errors only
grep -i "ERROR.*content.manager" \
  /var/log/wazuh-indexer/wazuh-indexer.log
```

## Resetting content

To force a full re-sync from snapshot, delete the consumer state document and restart the indexer:

```bash
# Delete consumer state (forces snapshot on next sync)
curl -sk -u admin:admin -X DELETE \
  "https://127.0.0.1:9200/.wazuh-cti-consumers/_doc/*"

# Restart indexer to trigger sync
systemctl restart wazuh-indexer
```

> **Warning**: This will re-download and re-index all content from scratch. Use only when troubleshooting persistent sync issues.
