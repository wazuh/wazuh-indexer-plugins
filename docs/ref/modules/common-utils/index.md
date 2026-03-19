# Common Utils

The Wazuh Indexer Common Utils plugin is a specialized, foundational component designed to extend the Wazuh Indexer with centralized shared resources, data validation, communication protocols, and security sanitization. Instead of serving end-user requests directly, it acts as a core framework and resource manager for other internal Wazuh plugins (such as Alerting, Security, and Notifications).



## Key Capabilities

- **Centralized communication:** Manages persistent Unix Domain Socket connections to the underlying Wazuh Engine, handling connection pooling and retries safely.
- **Unified validation:** Provides centralized JSON schema validation to ensure all data passed between plugins and the engine adheres to strict Wazuh internal standards.
- **Diagnostic testing:** Validate socket connectivity and retrieve thread pool or memory stats through a single API surface at `/_plugins/_wazuh/_common/`.
- **Payload sanitization:** Intercepts and masks sensitive data (such as API keys and passwords) via the `SecurityProvider` before serialization or logging.
- **Standardized logging:** Enforces uniform log formats (`ISO8601`) and standardized Wazuh error codes (e.g., `W1001`, `W1002`) across all indexer components via the `WazuhLogger`.
- **Shared resource management:** Prevents CPU/memory exhaustion by providing shared thread pools and in-memory caches (like `SchemaCache`) for all consuming plugins.

## Supported Utility Types

| Utility Type | Category | Description |
|---|---|---|
| `socket` | IPC (Inter-Process) | Manages Stream-based Unix Domain Socket connections to the `/var/ossec/queue/indexer/conn` endpoint. |
| `schema_validator` | Validation | Validates JSON inputs against internal Wazuh schemas (e.g., `rule`, `decoder`, `agent_config`). |
| `logger` | Logging | Standardizes log formatting and error code mapping for consistent troubleshooting. |
| `data_masker` | Security | Redacts sensitive information from payloads and logs using configurable regex patterns. |
| `thread_pool` | Concurrency | Provides shared worker threads to handle background tasks and socket serialization queueing. |
| `cache` | Memory | Manages in-memory storage for frequently accessed data, reducing disk I/O for schemas. |

## Version

The current plugin version is **5.0.0-alpha0** (see `VERSION.json` in the repository root).

