# Troubleshooting

Common issues and diagnostic procedures for the Content Manager plugin.

## Common Errors

### "Error communicating with Engine socket: Connection refused"

The Wazuh Engine is not running or the Unix socket is not accessible.

**Resolution:**
1. Check the socket file exists:
   ```bash
   ls -la /usr/share/wazuh-indexer/engine/sockets/engine-api.sock
   ```
   
2. Ensure the Wazuh Indexer process has permission to access the socket file.

### "Token not found"

No CTI subscription has been registered. The Content Manager cannot sync content without a valid subscription token.

**Resolution:**

1. Check the current subscription status:
   ```bash
   curl -sk -u admin:admin \
     "https://192.168.56.6:9200/_plugins/_content_manager/subscription"
   ```

2. If the response is `{"message":"Token not found","status":404}`, register a subscription using a device code from the Wazuh CTI Console:
   ```bash
   curl -sk -u admin:admin -X POST \
     "https://192.168.56.6:9200/_plugins/_content_manager/subscription" \
     -H 'Content-Type: application/json' \
     -d '{
       "device_code": "<your-device-code>",
       "client_id": "<your-client-id>",
       "expires_in": 900,
       "interval": 5
     }'
   ```

### Sync Not Running

Content is not being updated despite having a valid subscription.

**Diagnosis:**

1. Check consumer state and offsets:
   ```bash
   curl -sk -u admin:admin \
     "https://192.168.56.6:9200/.wazuh-cti-consumers/_search?pretty"
   ```

   If `local_offset` equals `remote_offset`, the content is already up-to-date.

2. Check the sync job is registered and enabled:
   ```bash
   curl -sk -u admin:admin \
     "https://192.168.56.6:9200/.wazuh-content-manager-jobs/_search?pretty"
   ```

   Verify the job has `"enabled": true` and the schedule interval matches your configuration.

3. Check if scheduled sync is enabled in `opensearch.yml`:
   ```yaml
   plugins.content_manager.catalog.update_on_schedule: true
   ```

4. Trigger a manual sync to test:
   ```bash
   curl -sk -u admin:admin -X POST \
     "https://192.168.56.6:9200/_plugins/_content_manager/update"
   ```

### Socket File Not Found

The Unix socket used for Engine communication does not exist.

**Expected path:** `/usr/share/wazuh-indexer/engine/sockets/engine-api.sock`

**Resolution:**

1. Verify the Wazuh Engine is installed and running.
2. Check the Engine configuration for the socket path.
3. Ensure the `engine/sockets/` directory exists under the Wazuh Indexer installation path.

## Diagnostic Commands

### Check Consumer State

View synchronization state for all content contexts:

```bash
curl -sk -u admin:admin \
  "https://192.168.56.6:9200/.wazuh-cti-consumers/_search?pretty"
```

Example output:

```json
{
  "hits": {
    "hits": [
      {
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
    ]
  }
}
```

- `status == idle`: Sync is complete; content is safe to read.
- `status == updating`: Sync is in progress. If this persists after a sync should have finished, the previous sync may have failed mid-cycle.
- `local_offset == remote_offset`: Content is up-to-date.
- `local_offset < remote_offset`: Content needs updating.
- `local_offset == 0`: Content has never been synced (snapshot required).

### Check Sync Job

View the periodic sync job configuration:

```bash
curl -sk -u admin:admin \
  "https://192.168.56.6:9200/.wazuh-content-manager-jobs/_search?pretty"
```

### Count Content Documents

Check how many rules, decoders, etc. have been indexed:

```bash
# Rules
curl -sk -u admin:admin "https://192.168.56.6:9200/wazuh-threatintel-rules/_count?pretty"

# Decoders
curl -sk -u admin:admin "https://192.168.56.6:9200/wazuh-threatintel-decoders/_count?pretty"

# Integrations
curl -sk -u admin:admin "https://192.168.56.6:9200/wazuh-threatintel-integrations/_count?pretty"

# KVDBs
curl -sk -u admin:admin "https://192.168.56.6:9200/wazuh-threatintel-kvdbs/_count?pretty"

# IoCs
curl -sk -u admin:admin "https://192.168.56.6:9200/wazuh-threatintel-enrichments/_count?pretty"
```

## Job Scheduling on Startup

During node startup, `scheduleCatalogSyncJob` and `scheduleTelemetryPingJob` both require the `.wazuh-content-manager-jobs` index to reach yellow status with at least one active shard before they can register their job documents. On a freshly initialized or resource-constrained cluster this can time out, producing entries like:

```
INFO   ... Failed to schedule Telemetry Ping Job: Index .wazuh-content-manager-jobs not ready
INFO   ... Retrying Telemetry Ping Job (attempt 1/3) in 15s.
```

The plugin automatically retries each registration up to 3 times with a linear backoff (15 s, 30 s, 45 s). Each attempt logs the failure reason and the scheduled retry delay at `INFO` — these are expected during startup and do not require action.

If all retries fail, the plugin logs `ERROR ... Giving up scheduling <job> after 3 attempts.` and the job will only be retried on the next node start. A persistent failure usually indicates the cluster cannot allocate shards — check cluster health with `GET _cluster/health` and verify index allocation settings.

## Log Monitoring

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

## Resetting Content

To force a full re-sync from snapshot, delete the consumer state document and restart the indexer:

```bash
# Delete consumer state (forces snapshot on next sync)
curl -sk -u admin:admin -X DELETE \
  "https://192.168.56.6:9200/.wazuh-cti-consumers/_doc/*"

# Restart indexer to trigger sync
systemctl restart wazuh-indexer
```

> **Warning**: This will re-download and re-index all content from scratch. Use only when troubleshooting persistent sync issues.
