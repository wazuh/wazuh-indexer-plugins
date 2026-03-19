# API Reference

All Common Utils plugin endpoints use the base path `/_plugins/_common_utils`.

---

## Utility Configs

### Create a Utility Config

Creates a new common utility configuration (such as socket profiles, shared caches, or logging channels).

| | |
|---|---|
| **Method** | `POST` |
| **URI** | `/_plugins/_common_utils/configs` |

**Request body:**

```json
{
  "config": {
    "name": "<config-name>",
    "description": "<config-description>",
    "config_type": "<utility-type>",
    "is_enabled": true,
    "<utility-type>": {
      // utility-specific fields
    }
  }
}
```

**Socket profile example:**

```json
{
  "config": {
    "name": "engine-primary-socket",
    "description": "Primary Unix socket for Engine communication",
    "config_type": "socket",
    "is_enabled": true,
    "socket": {
      "path": "/var/ossec/queue/indexer/conn",
      "timeout_ms": 5000
    }
  }
}
```

**Logger example:**

```json
{
  "config": {
    "name": "audit-logger",
    "description": "Shared audit logger configuration",
    "config_type": "logger",
    "is_enabled": true,
    "logger": {
      "level": "INFO",
      "format": "json",
      "destination": "internal_index"
    }
  }
}
```

**Cache profile example:**

```json
{
  "config": {
    "name": "schema-cache",
    "description": "In-memory cache for validation schemas",
    "config_type": "cache",
    "is_enabled": true,
    "cache": {
      "max_size_mb": 50,
      "ttl_seconds": 3600
    }
  }
}
```

**Response:**

```json
{
  "config_id": "<generated-config-id>"
}
```

---

### Update a Utility Config

Updates an existing utility configuration.

| | |
|---|---|
| **Method** | `PUT` |
| **URI** | `/_plugins/_common_utils/configs/{config_id}` |

**Request body:** Same structure as create. All fields in the `config` object are replaced.

```json
{
  "config": {
    "name": "updated-engine-socket",
    "description": "Updated timeout description",
    "config_type": "socket",
    "is_enabled": true,
    "socket": {
      "path": "/var/ossec/queue/indexer/conn",
      "timeout_ms": 10000
    }
  }
}
```

**Response:**

```json
{
  "config_id": "<config-id>"
}
```

---

### Get a Utility Config

Retrieves a specific utility configuration by ID.

| | |
|---|---|
| **Method** | `GET` |
| **URI** | `/_plugins/_common_utils/configs/{config_id}` |

**Response:**

```json
{
  "config_list": [
    {
      "config_id": "<config-id>",
      "last_updated_time_ms": 1234567890,
      "created_time_ms": 1234567890,
      "config": {
        "name": "engine-primary-socket",
        "description": "Primary Unix socket for Engine communication",
        "config_type": "socket",
        "is_enabled": true,
        "socket": {
          "path": "/var/ossec/queue/indexer/conn",
          "timeout_ms": 5000
        }
      }
    }
  ],
  "total_hits": 1
}
```

---

### List Utility Configs

Retrieves utility configurations with filtering, sorting, and pagination.

| | |
|---|---|
| **Method** | `GET` |
| **URI** | `/_plugins/_common_utils/configs` |

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `config_id` | String | Filter by a single config ID. |
| `config_id_list` | String | Comma-separated list of config IDs. |
| `from_index` | Integer | Pagination offset (default: `0`). |
| `max_items` | Integer | Maximum items to return (default: `100`). |
| `sort_field` | String | Field to sort by (e.g., `config_type`, `name`, `last_updated_time_ms`). |
| `sort_order` | String | Sort order: `asc` or `desc`. |
| `config_type` | String | Filter by utility type (e.g., `socket,logger`). |
| `is_enabled` | Boolean | Filter by enabled status. |
| `name` | String | Filter by name (text search). |
| `description` | String | Filter by description (text search). |
| `last_updated_time_ms` | String | Range filter (e.g., `1609459200000..1640995200000`). |
| `created_time_ms` | String | Range filter. |
| `socket.path` | String | Filter by socket path. |
| `logger.level` | String | Filter by log level. |
| `query` | String | Search across all keyword and text filter fields. |
| `text_query` | String | Search across text filter fields only. |

**Example:**

```bash
curl -sk -u admin:admin \
  "https://localhost:9200/_plugins/_common_utils/configs?config_type=socket&max_items=10&sort_order=desc"
```

---

### Delete a Utility Config

Deletes one or more utility configurations.

| | |
|---|---|
| **Method** | `DELETE` |
| **URI** | `/_plugins/_common_utils/configs/{config_id}` |

Or for bulk delete:

| | |
|---|---|
| **Method** | `DELETE` |
| **URI** | `/_plugins/_common_utils/configs?config_id_list=id1,id2,id3` |

**Response:**

```json
{
  "delete_response_list": {
    "<config-id>": "OK"
  }
}
```

---

## Resources

### List Shared Resources

Returns a simplified list of all active common utility resources (ID, name, type, and enabled status).

| | |
|---|---|
| **Method** | `GET` |
| **URI** | `/_plugins/_common_utils/resources` |

**Response:**

```json
{
  "resource_list": [
    {
      "config_id": "<id>",
      "name": "engine-primary-socket",
      "config_type": "socket",
      "is_enabled": true
    }
  ],
  "total_hits": 1
}
```

---

## Features

### Get Plugin Features

Returns the utility features and allowed config types supported by the Common Utils plugin.

| | |
|---|---|
| **Method** | `GET` |
| **URI** | `/_plugins/_common_utils/features` |

**Response:**

```json
{
  "allowed_config_type_list": [
    "socket",
    "logger",
    "cache",
    "schema_validator"
  ],
  "plugin_features": {
    "hot_reload_support": "true"
  }
}
```

---

## Test Connectivity

### Send Test Ping

Sends a test payload to a configured utility (like a socket or logger) to validate the configuration.

| | |
|---|---|
| **Method** | `POST` |
| **URI** | `/_plugins/_common_utils/feature/test/{config_id}` |

**Example:**

```bash
curl -sk -u admin:admin -X POST \
  "https://localhost:9200/_plugins/_common_utils/feature/test/<config-id>"
```

**Response:**

```json
{
  "status_list": [
    {
      "config_id": "<config-id>",
      "config_type": "socket",
      "config_name": "engine-primary-socket",
      "delivery_status": {
        "status_code": "200",
        "status_text": "ok"
      }
    }
  ]
}
```

---

## Stats

### Get Plugin Stats

Returns internal plugin metrics and counters.

| | |
|---|---|
| **Method** | `GET` |
| **URI** | `/_plugins/_common_utils/_local/stats` |

**Response:** A JSON object with flattened metric counters including:

- Request totals and interval counts for each API operation (create, update, delete, info, features, resources, send test).

---

## Summary Table

| Endpoint | Method | Description |
|---|---|---|
| `/_plugins/_common_utils/configs` | `POST` | Create a new utility config. |
| `/_plugins/_common_utils/configs/{id}` | `PUT` | Update an existing utility config. |
| `/_plugins/_common_utils/configs/{id}` | `GET` | Get a specific utility config. |
| `/_plugins/_common_utils/configs` | `GET` | List/search utility configs with filters. |
| `/_plugins/_common_utils/configs/{id}` | `DELETE` | Delete a utility config. |
| `/_plugins/_common_utils/configs` | `DELETE` | Bulk delete (with `config_id_list` param). |
| `/_plugins/_common_utils/resources` | `GET` | List all resources (simplified view). |
| `/_plugins/_common_utils/features` | `GET` | Get supported features and config types. |
| `/_plugins/_common_utils/feature/test/{id}` | `POST` | Send a test ping/payload. |
| `/_plugins/_common_utils/_local/stats` | `GET` | Get plugin metrics. |
