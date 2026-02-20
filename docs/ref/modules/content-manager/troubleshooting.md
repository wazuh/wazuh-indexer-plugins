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
     "https://192.168.56.6:9200/.cti-consumers/_search?pretty"
   ```

   If `local_offset` equals `remote_offset`, the content is already up to date.

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
  "https://192.168.56.6:9200/.cti-consumers/_search?pretty"
```

Example output:

```json
{
  "hits": {
    "hits": [
      {
        "_id": "development_0.0.3_development_0.0.3_test",
        "_source": {
          "name": "development_0.0.3_test",
          "context": "development_0.0.3",
          "local_offset": 3932,
          "remote_offset": 3932,
          "snapshot_link": "https://cti-pre.wazuh.com/store/..."
        }
      }
    ]
  }
}
```

- `local_offset == remote_offset`: Content is up to date.
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
curl -sk -u admin:admin "https://192.168.56.6:9200/.cti-rules/_count?pretty"

# Decoders
curl -sk -u admin:admin "https://192.168.56.6:9200/.cti-decoders/_count?pretty"

# Integrations
curl -sk -u admin:admin "https://192.168.56.6:9200/.cti-integrations/_count?pretty"

# KVDBs
curl -sk -u admin:admin "https://192.168.56.6:9200/.cti-kvdbs/_count?pretty"

# IoCs
curl -sk -u admin:admin "https://192.168.56.6:9200/.cti-iocs/_count?pretty"
```

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
  "https://192.168.56.6:9200/.cti-consumers/_doc/*"

# Restart indexer to trigger sync
systemctl restart wazuh-indexer
```

> **Warning**: This will re-download and re-index all content from scratch. Use only when troubleshooting persistent sync issues.
