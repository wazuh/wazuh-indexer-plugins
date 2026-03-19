# Troubleshooting

Common issues and solutions when working with the Common Utils plugin.

---

## Socket Communication Issues



### Engine communication fails with timeout (W1002)

**Symptoms:** Internal plugin operations (like sending an alert or triggering an active response) fail with a `W1002 SOCKET_TIMEOUT` error.

**Possible causes:**

1. **Wazuh Engine is overloaded/down.** The underlying Wazuh Manager service is not responding to the Unix Domain Socket in a timely manner.
2. **Timeout too short.** The default socket timeout is 5000 ms. If the Engine is under heavy load, this might not be enough.
3. **Queue exhaustion.** The thread pool queue is full, causing requests to time out before they even reach the socket.

**Resolution:**

```bash
# Verify the socket connection directly
curl -sk -u admin:admin -X POST \
  "https://localhost:9200/_plugins/_wazuh/_common/test_connection"

# Increase timeouts via cluster settings
curl -X PUT "https://localhost:9200/_cluster/settings" \
  -H 'Content-Type: application/json' \
  -d '{
    "persistent": {
      "wazuh.common.core.socket.timeout_ms": 15000,
      "wazuh.common.core.socket.max_retries": 5
    }
  }'
```

Check the `connection_status` in the response to determine if the socket is reachable.

---

### Socket path not found or connection refused

**Symptoms:** Plugin startup logs show errors binding to the socket, or the test connection API returns a `No such file or directory` error.

**Possible causes:**

1. **Incorrect path.** The socket path configured does not match the actual Wazuh Engine socket location.
2. **Permissions.** The `wazuh-indexer` user does not have read/write permissions for `/var/ossec/queue/indexer/conn`.
3. **Distributed architecture mismatch.** The Wazuh Manager is not installed on the same node as the Wazuh Indexer, so the local Unix socket does not exist.

**Resolution:**

Verify the socket path and permissions on the OS level:

```bash
ls -l /var/ossec/queue/indexer/conn
```

If the path needs to be updated, change the setting:

```bash
curl -X PUT "https://localhost:9200/_cluster/settings" \
  -H 'Content-Type: application/json' \
  -d '{
    "persistent": {
      "wazuh.common.core.socket.path": "/custom/path/to/socket"
    }
  }'
```

---

## Validation Issues

### Valid payloads rejected with W1001 (INVALID_INPUT)

**Symptoms:** API calls to other Wazuh plugins fail with a `W1001` error, claiming a field is unknown, even though the configuration seems correct.

**Cause:** The setting `wazuh.common.plugin.validation.strict_mode_default` is `true`, and the JSON payload contains undocumented fields, or the `SchemaCache` is serving an outdated schema version.

**Resolution:**

- Verify the JSON payload exactly matches the schema.
- Or, temporarily disable strict mode default to allow the payload:

```bash
curl -X PUT "https://localhost:9200/_cluster/settings" \
  -H 'Content-Type: application/json' \
  -d '{
    "persistent": {
      "wazuh.common.plugin.validation.strict_mode_default": false
    }
  }'
```

---

## Security & Masking Issues

### Custom masking key not found

**Symptoms:** The Indexer logs show errors related to the `SecurityProvider` failing to initialize, or sensitive data appears in plaintext.

**Cause:** You have configured the system to use a custom masking key for payloads, but the key is missing from the keystore.

**Resolution:** Custom masking keys must be stored in the Wazuh Indexer Keystore, not in `opensearch.yml`.

```bash
bin/opensearch-keystore add wazuh.common.plugin.security.masking_key
```

Restart the Wazuh Indexer node after adding keystore entries.

---

## Plugin Stats

To inspect the plugin's internal metrics and check for anomalies (such as thread pool exhaustion, high cache misses, or socket latency):

```bash
curl -sk -u admin:admin \
  "https://localhost:9200/_plugins/_wazuh/_common/_local/stats"
```

This returns counters for thread pools, socket managers, and cache hits, which can help identify resource bottlenecks before they impact other plugins.

---

## Logs

Enable debug logging for the Common Utils plugin:

```bash
curl -X PUT "https://localhost:9200/_cluster/settings" \
  -H 'Content-Type: application/json' \
  -d '{
    "persistent": {
      "logger.org.wazuh.indexer.common": "DEBUG",
      "logger.org.wazuh.indexer.common.socket": "DEBUG"
    }
  }'
```

Check the Wazuh Indexer logs for entries prefixed with `wazuh-common:` or `WazuhLogger`.
