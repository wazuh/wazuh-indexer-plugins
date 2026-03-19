
# Architecture

The Common Utils plugin follows a layered architecture that centralizes shared resources, data validation, communication protocols, and security sanitization for all Wazuh Indexer plugins.

## High-Level Architecture



The Common Utils plugin runs inside the Wazuh Indexer and acts as a foundational framework. Instead of serving end-user requests directly, it acts as a bridge and resource manager between internal Wazuh plugins (like Alerting, Security, or Notifications) and the underlying OS-level Wazuh Engine.

At a high level, the architecture is composed of three main parts:

- **Utility consumers (inside the Indexer)** Internal plugins such as **Alerting**, **Reporting**, **Security**, and other Wazuh components process data and require standardized logging, payload validation, or engine communication.
  When they need to perform a shared operation (for example, masking a password or sending a message to the Engine), they call the **Common Utils plugin** either through:
    - Internal **Java method calls** (library consumption), or
    - Internal **transport actions**.

- **Common Utils plugin (inside the Indexer)** The plugin itself is structured in several layers:

    - **REST / Transport layer** - Exposes the `/_plugins/_wazuh/_common/...` REST endpoints for diagnostics.
        - Receives requests to validate configuration payloads, test socket connectivity, and retrieve thread pool or memory stats.
        - Validates requests and delegates the work to internal transport actions.

    - **Security integration** - Interacts closely with the **Security plugin** to provide payload sanitization (`SecurityProvider`).
        - Ensures sensitive data (like API keys or SMTP passwords) is masked before being passed to loggers or external services.

    - **Core SPI layer** - Defines common contracts and models such as `WazuhLogger`, `WazuhValidator`, and concrete utility interfaces like `SocketClient` and `DataMasker`.
        - Encapsulates standardized error responses (`WazuhError`) and status codes.

    - **Core implementation (transport logic)** - Implements concrete shared tools:
        - `SocketManager` for handling persistent Stream-based Unix Domain Sockets to communicate with the Wazuh Engine.
        - `SchemaValidator` for parsing and validating JSON inputs against official Wazuh schemas.
        - `ThreadPoolManager` for sharing background task execution threads among multiple plugins.
        - Manages buffer sizes, socket timeouts, serialization queues, and cache eviction policies.

    - **Persistence and configuration** - Manages in-memory caches (such as the `SchemaCache` to avoid reloading JSON schemas from disk).
        - Reads centralized settings from configuration files (`book.toml`, `opensearch.yml`) and cluster settings.
        - Exposes internal metrics through the stats endpoint so operators can inspect resource bottlenecks.

- **External dependencies (local to the node)** After the plugin processes a request that requires external interaction, it communicates with:
    - **Wazuh Engine** via the local Unix Socket (`/var/ossec/queue/indexer/conn`).
    - **File System** to read updated schemas or write standardized logs.

## Plugin Layers

### 1. Core SPI (`common-spi`)

The **Service Provider Interface** layer defines the contracts and models used by all other plugins:

- **`WazuhLogger`**: Interface that standardizes log formats (`ISO8601`, specific Wazuh error codes) across all indexer components.
- **`SocketClient`**: Abstract base interface for IPC (Inter-Process Communication) with the Wazuh Engine.
- **`WazuhValidator`**: Interface for validating structured data payloads.
- **`WazuhError`**: Standardized object mapping internal exceptions to API-friendly HTTP codes (e.g., `W1001`, `W1002`).

### 2. Core Implementation (`common-core`)

The **Core** layer provides the actual utility logic:

- **Communication Providers:**
    - `UnixSocketManager` — handles connection pooling, byte serialization, and heartbeat mechanisms for `/var/ossec/queue/indexer/conn`.
- **Validation & Security:**
    - `JsonSchemaValidator` — validates inputs against loaded schemas with a strict mode toggle.
    - `SecurityProvider` — implements the `maskSensitiveData()` logic to redact fields matching specific regex patterns (e.g., passwords, tokens).
- **Resource Management:**
    - `SharedThreadPool` manages a global pool of workers to prevent individual plugins from exhausting node CPU resources.
    - `SchemaCache` keeps frequently used validation schemas in memory with a configurable TTL.

### 3. Common Utils Plugin (`common-utils`)

The **Plugin** module ties the internal utilities to the REST and cluster management layers:

- **REST Handlers:** Map diagnostic and testing HTTP requests to internal transport actions (see API Reference).
- **Transport Actions:** Asynchronous action classes (`ValidateConfigAction`, `GetCommonStatsAction`, `TestSocketConnectionAction`, `GetSchemasAction`).
- **Metrics:** Track counters for serialization latency, socket timeouts, cache hits/misses, and schema validation failures.
- **Settings (`CommonSettings`):** Tunable parameters — socket timeouts, cache sizes, active thread limits — dynamically updatable via cluster settings.

## Schema Validation Sequence

The following sequence describes the flow when a plugin (e.g., Alerting) needs to validate user input:

1. A user submits a configuration payload to the Alerting REST API.
2. The Alerting plugin calls the `WazuhValidator` interface provided by Common Utils.
3. The `JsonSchemaValidator` checks if the requested schema (e.g., `rule`, `decoder`) exists in the **SchemaCache**.
4. If missing, it loads the schema from the local file system into memory.
5. The payload is validated. If it fails, a standardized `W1001 INVALID_INPUT` error is constructed.
6. The validation result is returned to the Alerting plugin, which either proceeds with the operation or blocks the user request.

## Engine Communication Sequence

The following sequence describes how Indexer plugins communicate with the underlying Wazuh Engine securely:

1. An internal plugin requests to send an event to the Wazuh Manager.
2. The plugin passes the payload to the `UnixSocketManager`.
3. The `SecurityProvider` intercepts the payload and masks any known sensitive fields before serialization.
4. The payload is serialized into a byte stream and queued in the `SharedThreadPool`.
5. A worker thread grabs an available socket connection from the pool and writes the stream to `/var/ossec/queue/indexer/conn`.
6. The thread awaits a confirmation ACK from the engine. If the `timeout_ms` is reached, a `W1002 SOCKET_TIMEOUT` exception is raised and logged via `WazuhLogger`.
