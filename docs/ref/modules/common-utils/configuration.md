# Configuration

The Common Utils plugin is configured through settings in `opensearch.yml` (or `wazuh-indexer.yml`) and cluster-level dynamic settings. The plugin also supports default values from a YAML configuration file bundled with the plugin.

## Configuration Files

On startup, the plugin loads default settings from:

- **Core defaults:** `<wazuh-indexer-config>/wazuh-common-utils-core/common-utils-core.yml`
- **Plugin defaults:** `<wazuh-indexer-config>/wazuh-common-utils/common-utils.yml`

These files provide initial values that can be overridden by settings in the main indexer configuration file or through the cluster settings API.

---

## Core Settings (`wazuh.common.core.*`)

These settings control the core resource management, thread pooling, and engine communication shared across Wazuh plugins.

### Engine Communication (Unix Socket) Settings

| Setting | Type | Default | Description |
|---|---|---|---|
| `wazuh.common.core.socket.path` | String | `/var/ossec/queue/indexer/conn` | The file path to the Unix Domain Socket used for communicating with the Wazuh Engine. |
| `wazuh.common.core.socket.timeout_ms` | Integer | `5000` | Connection and read timeout in milliseconds for socket operations. |
| `wazuh.common.core.socket.max_retries` | Integer | `3` | Maximum number of delivery attempts to the engine before throwing a `W1002` exception. |
| `wazuh.common.core.socket.buffer_size_kb` | Integer | `1024` | Maximum buffer size (in KB) for socket serialization. |

### Thread Pool Settings

| Setting | Type | Default | Description |
|---|---|---|---|
| `wazuh.common.core.thread_pool.active_workers` | Integer | `4` | Number of active threads dedicated to shared background tasks. |
| `wazuh.common.core.thread_pool.queue_size` | Integer | `1000` | Maximum number of pending tasks in the serialization and delivery queue. |

### Schema Cache Settings

| Setting | Type | Default | Description |
|---|---|---|---|
| `wazuh.common.core.cache.schema_ttl_minutes` | Integer | `60` | Time to live (TTL) in minutes for JSON schemas kept in memory. |
| `wazuh.common.core.cache.max_size_mb` | Integer | `50` | Maximum memory allocated for the schema and validation cache. |

---

## Plugin Settings (`wazuh.common.plugin.*`)

These settings control the plugin's general behavior regarding validation and security.

| Setting | Type | Default | Description |
|---|---|---|---|
| `wazuh.common.plugin.validation.strict_mode_default` | Boolean | `true` | When `true`, all payload validations will reject unknown fields by default unless specifically overridden in the API call. |
| `wazuh.common.plugin.security.masking_enabled` | Boolean | `true` | Enable or disable the `SecurityProvider` data masking globally. If `false`, sensitive fields will be written to internal logs in plain text. |
| `wazuh.common.plugin.logger.default_level` | String | `INFO` | Default logging level for the standardized `WazuhLogger` (`DEBUG`, `INFO`, `WARN`, `ERROR`). |

---

## Security Secure Settings

If you are using custom encryption keys for advanced payload masking before sending data over the socket, those keys are stored securely in the **Wazuh Indexer Keystore** rather than in plain text configuration files.

### Custom Masking Keys

To configure a custom AES key for the `SecurityProvider`:

```bash
# Add custom encryption key
bin/opensearch-keystore add wazuh.common.plugin.security.masking_key
```

The secure setting key is `wazuh.common.plugin.security.masking_key`. When this is present, the Common Utils plugin will use it instead of the default node-local key for masking sensitive payload fields.

---

## Example Configuration

A minimal `opensearch.yml` (or `wazuh-indexer.yml`) configuration for the Common Utils plugin:

```yaml
# Socket and Engine settings
wazuh.common.core.socket.path: "/var/ossec/queue/indexer/conn"
wazuh.common.core.socket.timeout_ms: 5000
wazuh.common.core.socket.max_retries: 3
wazuh.common.core.socket.buffer_size_kb: 1024

# Thread pool and resource management
wazuh.common.core.thread_pool.active_workers: 8
wazuh.common.core.thread_pool.queue_size: 2000

# Cache configuration
wazuh.common.core.cache.schema_ttl_minutes: 120
wazuh.common.core.cache.max_size_mb: 100

# Plugin behavior settings
wazuh.common.plugin.validation.strict_mode_default: true
wazuh.common.plugin.security.masking_enabled: true
wazuh.common.plugin.logger.default_level: "WARN"
```

---

## Dynamic Settings Update

All settings marked as `Dynamic` (such as timeouts, queue sizes, and log levels) can be updated at runtime through the cluster settings API without restarting the indexer node:

```bash
curl -X PUT "https://localhost:9200/_cluster/settings" \
  -H 'Content-Type: application/json' \
  -d '{
    "persistent": {
      "wazuh.common.core.socket.timeout_ms": 10000,
      "wazuh.common.plugin.logger.default_level": "DEBUG"
    }
  }'
```

---

¿Necesitas que prepare también algún archivo adicional de la documentación, como una guía de inicio rápido (`quickstart.md`) para este módulo?
