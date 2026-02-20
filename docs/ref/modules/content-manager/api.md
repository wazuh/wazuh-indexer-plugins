# API Reference

The Content Manager plugin exposes a REST API under `/_plugins/_content_manager/`. All endpoints require authentication.

---

## Subscription Management

### Get CTI Subscription

Retrieves the current CTI subscription token.

**Request**
- Method: `GET`
- Path: `/_plugins/_content_manager/subscription`

**Example Request**

```bash
curl -sk -u admin:admin \
  "https://192.168.56.6:9200/_plugins/_content_manager/subscription"
```

**Example Response (subscription exists)**

```json
{
  "access_token": "AYjcyMzY3ZDhiNmJkNTY",
  "token_type": "Bearer"
}
```

**Example Response (no subscription)**

```json
{
  "message": "Token not found",
  "status": 404
}
```

**Status Codes**

| Code | Description |
|---|---|
| 200 | Subscription token returned |
| 404 | No subscription registered |

---

### Register CTI Subscription

Registers a new CTI subscription using a device code obtained from the Wazuh CTI Console.

**Request**
- Method: `POST`
- Path: `/_plugins/_content_manager/subscription`

**Request Body**

| Field | Type | Required | Description |
|---|---|---|---|
| `device_code` | String | Yes | Device authorization code from CTI Console |
| `client_id` | String | Yes | OAuth client identifier |
| `expires_in` | Integer | Yes | Token expiration time in seconds |
| `interval` | Integer | Yes | Polling interval in seconds |

**Example Request**

```bash
curl -sk -u admin:admin -X POST \
  "https://192.168.56.6:9200/_plugins/_content_manager/subscription" \
  -H 'Content-Type: application/json' \
  -d '{
    "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
    "client_id": "a17c21ed",
    "expires_in": 1800,
    "interval": 5
  }'
```

**Example Response**

```json
{
  "message": "Subscription created successfully",
  "status": 201
}
```

**Status Codes**

| Code | Description |
|---|---|
| 201 | Subscription registered successfully |
| 400 | Missing required fields (`device_code`, `client_id`, `expires_in`, `interval`) |
| 401 | Unauthorized — endpoint accessed by unexpected user |
| 500 | Internal error |

---

### Delete CTI Subscription

Removes the current CTI subscription token and revokes all associated credentials.

**Request**
- Method: `DELETE`
- Path: `/_plugins/_content_manager/subscription`

**Example Request**

```bash
curl -sk -u admin:admin -X DELETE \
  "https://192.168.56.6:9200/_plugins/_content_manager/subscription"
```

**Example Response (success)**

```json
{
  "message": "Subscription deleted successfully",
  "status": 200
}
```

**Example Response (no subscription)**

```json
{
  "message": "Token not found",
  "status": 404
}
```

**Status Codes**

| Code | Description |
|---|---|
| 200 | Subscription deleted |
| 404 | No subscription to delete |

---

## Content Updates

### Trigger Manual Sync

Triggers an immediate content synchronization with the CTI API. Requires a valid subscription.

**Request**
- Method: `POST`
- Path: `/_plugins/_content_manager/update`

**Example Request**

```bash
curl -sk -u admin:admin -X POST \
  "https://192.168.56.6:9200/_plugins/_content_manager/update"
```

**Example Response (success)**

```json
{
  "message": "Content update triggered successfully",
  "status": 200
}
```

**Example Response (no subscription)**

```json
{
  "message": "Token not found. Please create a subscription before attempting to update.",
  "status": 404
}
```

**Status Codes**

| Code | Description |
|---|---|
| 200 | Sync triggered successfully |
| 404 | No subscription token found |
| 409 | A content update is already in progress |
| 429 | Rate limit exceeded |
| 500 | Internal error during sync |

---

## Logtest

### Execute Logtest

Sends a log event to the Wazuh Engine for analysis and returns the decoded and matched result. The Indexer acts as a pass-through: it forwards the payload to the Engine via Unix socket and returns the Engine's response.

> **Note**: A testing policy must be loaded in the Engine for logtest to execute successfully. Load a policy via the policy promotion endpoint.

**Request**
- Method: `POST`
- Path: `/_plugins/_content_manager/logtest`

**Request Body**

| Field | Type | Required | Description |
|---|---|---|---|
| `queue` | Integer | Yes | Queue number for logtest execution |
| `location` | String | Yes | Log file path or logical source location |
| `event` | String | Yes | Raw log event to test |
| `agent_metadata` | Object | No | Optional agent metadata passed to the Engine |
| `trace_level` | String | No | Trace verbosity: `NONE`, `BASIC`, or `FULL` |

**Example Request**

```bash
curl -sk -u admin:admin -X POST \
  "https://192.168.56.6:9200/_plugins/_content_manager/logtest" \
  -H 'Content-Type: application/json' \
  -d '{
    "queue": 1,
    "location": "/var/log/auth.log",
    "agent_metadata": {},
    "event": "Dec 19 12:00:00 host sshd[123]: Failed password for root from 10.0.0.1 port 12345 ssh2",
    "trace_level": "NONE"
  }'
```

**Example Response (success)**

```json
{
  "status": "OK",
  "result": {
    "output": "{\"wazuh\":{\"protocol\":{\"queue\":1,\"location\":\"syscheck\"},\"integration\":{\"category\":\"Security\",\"name\":\"integration/wazuh-core/0\",\"decoders\":[\"core-wazuh-message\",\"integrations\"]}},\"event\":{\"original\":\"Dec 19 12:00:00 host sshd[123]: Failed password for root from 10.0.0.1 port 12345 ssh2\"},\"@timestamp\":\"2026-02-19T12:00:00Z\"}",
    "asset_traces": [
      {
        "asset": "decoder/core-wazuh-message/0",
        "success": true,
        "traces": ["@timestamp: get_date -> Success"]
      }
    ]
  }
}
```

**Example Response (Engine unavailable)**

```json
{
  "message": "Error communicating with Engine socket: Connection refused",
  "status": 500
}
```

**Status Codes**

| Code | Description |
|---|---|
| 200 | Logtest executed successfully |
| 400 | Invalid request body |
| 500 | Engine socket communication error |

---

## Policy

### Update Draft Policy

Updates the routing policy in the draft space. The policy defines which integrations are active, the root decoder, enrichment types, and how events are routed through the Engine.

> **Note**: The `integrations` array allows reordering but does not allow adding or removing entries — integration membership is managed via the integration CRUD endpoints.

**Request**
- Method: `PUT`
- Path: `/_plugins/_content_manager/policy`

**Request Body**

| Field | Type | Required | Description |
|---|---|---|---|
| `resource` | Object | Yes | The policy resource object |

Fields within `resource`:

| Field | Type | Required | Description |
|---|---|---|---|
| `title` | String | No | Human-readable policy name |
| `root_decoder` | String | No | Identifier of the root decoder for event processing |
| `integrations` | Array | No | List of integration IDs (reorder only, no add/remove) |
| `filters` | Array | No | List of filter UUIDs |
| `enrichments` | Array | No | Enrichment types: `file`, `domain-name`, `ip`, `url`, `geo` (no duplicates) |
| `author` | String | Yes | Author of the policy |
| `description` | String | Yes | Brief description |
| `documentation` | String | Yes | Documentation text or URL |
| `references` | Array | Yes | External reference URLs |

**Example Request**

```bash
curl -sk -u admin:admin -X PUT \
  "https://192.168.56.6:9200/_plugins/_content_manager/policy" \
  -H 'Content-Type: application/json' \
  -d '{
    "resource": {
      "title": "Draft policy",
      "root_decoder": "",
      "integrations": [
        "f16f33ec-a5ea-4dc4-bf33-616b1562323a"
      ],
      "filters": [],
      "enrichments": [],
      "author": "Wazuh Inc.",
      "description": "Custom policy",
      "documentation": "",
      "references": [
        "https://wazuh.com"
      ]
    }
  }'
```

**Example Response**

```json
{
  "message": "kQPmV5wBi_TgruUn97RT",
  "status": 200
}
```

The `message` field contains the OpenSearch document ID of the updated policy.

**Status Codes**

| Code | Description |
|---|---|
| 200 | Policy updated |
| 400 | Missing `resource` field, missing required fields, or invalid enrichments |
| 500 | Internal error |

---

## Rules

### Create Rule

Creates a new detection rule in the draft space. The rule is linked to the specified parent integration and validated by the Security Analytics Plugin.

**Request**
- Method: `POST`
- Path: `/_plugins/_content_manager/rules`

**Request Body**

| Field | Type | Required | Description |
|---|---|---|---|
| `integration` | String | Yes | UUID of the parent integration (must be in draft space) |
| `resource` | Object | Yes | The rule definition |

Fields within `resource`:

| Field | Type | Required | Description |
|---|---|---|---|
| `title` | String | Yes | Rule title (must be unique within the draft space) |
| `description` | String | No | Rule description |
| `author` | String | No | Rule author |
| `sigma_id` | String | No | Sigma rule ID |
| `references` | Array | No | Reference URLs |
| `enabled` | Boolean | No | Whether the rule is enabled |
| `status` | String | No | Rule status (e.g., `experimental`, `stable`) |
| `level` | String | No | Alert level (e.g., `low`, `medium`, `high`, `critical`) |
| `logsource` | Object | No | Log source definition (`product`, `category`) |
| `detection` | Object | No | Sigma detection logic with `condition` and selection fields |

**Example Request**

```bash
curl -sk -u admin:admin -X POST \
  "https://192.168.56.6:9200/_plugins/_content_manager/rules" \
  -H 'Content-Type: application/json' \
  -d '{
    "integration": "6b7b7645-00da-44d0-a74b-cffa7911e89c",
    "resource": {
      "title": "Test Rule",
      "description": "A Test rule",
      "author": "Tester",
      "sigma_id": "string",
      "references": [
        "https://wazuh.com"
      ],
      "enabled": true,
      "status": "experimental",
      "logsource": {
        "product": "system",
        "category": "system"
      },
      "detection": {
        "condition": "selection",
        "selection": {
          "event.action": [
            "hash_test_event"
          ]
        }
      },
      "level": "low"
    }
  }'
```

**Example Response**

```json
{
  "message": "6e1c43f1-f09b-4cec-bb59-00e3a52b7930",
  "status": 201
}
```

The `message` field contains the UUID of the created rule.

**Status Codes**

| Code | Description |
|---|---|
| 201 | Rule created |
| 400 | Missing fields, duplicate title, integration not in draft space, or validation failure |
| 500 | Internal error or SAP unavailable |

---

### Update Rule

Updates an existing rule in the draft space.

**Request**
- Method: `PUT`
- Path: `/_plugins/_content_manager/rules/{id}`

**Parameters**

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `id` | Path | String (UUID) | Yes | Rule document ID |

**Request Body**

| Field | Type | Required | Description |
|---|---|---|---|
| `resource` | Object | Yes | Updated rule definition (same fields as create) |

**Example Request**

```bash
curl -sk -u admin:admin -X PUT \
  "https://192.168.56.6:9200/_plugins/_content_manager/rules/6e1c43f1-f09b-4cec-bb59-00e3a52b7930" \
  -H 'Content-Type: application/json' \
  -d '{
    "resource": {
      "title": "Test Hash Generation Rule",
      "description": "A rule to verify that SHA-256 hashes are calculated correctly upon creation.",
      "author": "Tester",
      "status": "experimental",
      "logsource": {
        "product": "system",
        "category": "system"
      },
      "detection": {
        "condition": "selection",
        "selection": {
          "event.action": [
            "hash_test_event"
          ]
        }
      },
      "level": "low"
    }
  }'
```

**Example Response**

```json
{
  "message": "6e1c43f1-f09b-4cec-bb59-00e3a52b7930",
  "status": 200
}
```

**Status Codes**

| Code | Description |
|---|---|
| 200 | Rule updated |
| 400 | Invalid request, not in draft space, or validation failure |
| 404 | Rule not found |
| 500 | Internal error |

---

### Delete Rule

Deletes a rule from the draft space. The rule is also removed from any integrations that reference it.

**Request**
- Method: `DELETE`
- Path: `/_plugins/_content_manager/rules/{id}`

**Parameters**

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `id` | Path | String (UUID) | Yes | Rule document ID |

**Example Request**

```bash
curl -sk -u admin:admin -X DELETE \
  "https://192.168.56.6:9200/_plugins/_content_manager/rules/6e1c43f1-f09b-4cec-bb59-00e3a52b7930"
```

**Example Response**

```json
{
  "message": "6e1c43f1-f09b-4cec-bb59-00e3a52b7930",
  "status": 200
}
```

**Status Codes**

| Code | Description |
|---|---|
| 200 | Rule deleted |
| 404 | Rule not found |
| 500 | Internal error |

---

## Decoders

### Create Decoder

Creates a new log decoder in the draft space. The decoder is validated against the Wazuh Engine before being stored, and automatically linked to the specified integration.

> **Note**: A testing policy must be loaded in the Engine for decoder validation to succeed.

**Request**
- Method: `POST`
- Path: `/_plugins/_content_manager/decoders`

**Request Body**

| Field | Type | Required | Description |
|---|---|---|---|
| `integration` | String | Yes | UUID of the parent integration (must be in draft space) |
| `resource` | Object | Yes | The decoder definition |

Fields within `resource`:

| Field | Type | Description |
|---|---|---|
| `name` | String | Decoder name identifier (e.g., `decoder/core-wazuh-message/0`) |
| `enabled` | Boolean | Whether the decoder is enabled |
| `check` | Array | Decoder check logic — array of condition objects |
| `normalize` | Array | Normalization rules — array of mapping objects |
| `metadata` | Object | Decoder metadata (see below) |

Fields within `metadata`:

| Field | Type | Description |
|---|---|---|
| `title` | String | Human-readable decoder title |
| `description` | String | Decoder description |
| `module` | String | Module name |
| `compatibility` | String | Compatibility description |
| `author` | Object | Author info (`name`, `email`, `url`) |
| `references` | Array | Reference URLs |
| `versions` | Array | Supported versions |

**Example Request**

```bash
curl -sk -u admin:admin -X POST \
  "https://192.168.56.6:9200/_plugins/_content_manager/decoders" \
  -H 'Content-Type: application/json' \
  -d '{
    "integration": "0aa4fc6f-1cfd-4a7c-b30b-643f32950f1f",
    "resource": {
      "enabled": true,
      "metadata": {
        "author": {
          "name": "Wazuh, Inc."
        },
        "compatibility": "All wazuh events.",
        "description": "Base decoder to process Wazuh message format.",
        "module": "wazuh",
        "references": [
          "https://documentation.wazuh.com/"
        ],
        "title": "Wazuh message decoder",
        "versions": [
          "Wazuh 5.*"
        ]
      },
      "name": "decoder/core-wazuh-message/0",
      "check": [
        {
          "tmp_json.event.action": "string_equal(\"netflow_flow\")"
        }
      ],
      "normalize": [
        {
          "map": [
            {
              "@timestamp": "get_date()"
            }
          ]
        }
      ]
    }
  }'
```

**Example Response**

```json
{
  "message": "d_0a6aaebe-dd0b-44cc-a787-ffefd4aac175",
  "status": 201
}
```

The `message` field contains the UUID of the created decoder (prefixed with `d_`).

**Status Codes**

| Code | Description |
|---|---|
| 201 | Decoder created |
| 400 | Missing `integration` field, integration not in draft space, or Engine validation failure |
| 500 | Engine unavailable or internal error |

---

### Update Decoder

Updates an existing decoder in the draft space. The decoder is re-validated against the Wazuh Engine.

**Request**
- Method: `PUT`
- Path: `/_plugins/_content_manager/decoders/{id}`

**Parameters**

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `id` | Path | String | Yes | Decoder document ID |

**Request Body**

| Field | Type | Required | Description |
|---|---|---|---|
| `resource` | Object | Yes | Updated decoder definition (same fields as create) |

**Example Request**

```bash
curl -sk -u admin:admin -X PUT \
  "https://192.168.56.6:9200/_plugins/_content_manager/decoders/bb6d0245-8c1d-42d1-8edb-4e0907cf45e0" \
  -H 'Content-Type: application/json' \
  -d '{
    "resource": {
      "name": "decoder/test-decoder/0",
      "enabled": false,
      "metadata": {
        "title": "Test Decoder UPDATED",
        "description": "Updated description",
        "author": {
          "name": "Hello there"
        }
      },
      "check": [],
      "normalize": []
    }
  }'
```

**Example Response**

```json
{
  "message": "bb6d0245-8c1d-42d1-8edb-4e0907cf45e0",
  "status": 200
}
```

**Status Codes**

| Code | Description |
|---|---|
| 200 | Decoder updated |
| 400 | Invalid request, not in draft space, or Engine validation failure |
| 404 | Decoder not found |
| 500 | Internal error |

---

### Delete Decoder

Deletes a decoder from the draft space. The decoder is also removed from any integrations that reference it.

**Request**
- Method: `DELETE`
- Path: `/_plugins/_content_manager/decoders/{id}`

**Parameters**

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `id` | Path | String | Yes | Decoder document ID |

**Example Request**

```bash
curl -sk -u admin:admin -X DELETE \
  "https://192.168.56.6:9200/_plugins/_content_manager/decoders/acbdba85-09c4-45a0-a487-61c8eeec58e6"
```

**Example Response**

```json
{
  "message": "acbdba85-09c4-45a0-a487-61c8eeec58e6",
  "status": 200
}
```

**Status Codes**

| Code | Description |
|---|---|
| 200 | Decoder deleted |
| 404 | Decoder not found |
| 500 | Internal error |

---

## Integrations

### Create Integration

Creates a new integration in the draft space. An integration is a logical grouping of related rules, decoders, and KVDBs. The integration is validated against the Engine and registered in the Security Analytics Plugin.

**Request**
- Method: `POST`
- Path: `/_plugins/_content_manager/integrations`

**Request Body**

| Field | Type | Required | Description |
|---|---|---|---|
| `resource` | Object | Yes | The integration definition |

Fields within `resource`:

| Field | Type | Required | Description |
|---|---|---|---|
| `title` | String | Yes | Integration title (must be unique in draft space) |
| `author` | String | Yes | Author of the integration |
| `category` | String | Yes | Category (e.g., `cloud-services`, `network-activity`, `security`, `system-activity`) |
| `description` | String | No | Description |
| `documentation` | String | No | Documentation text or URL |
| `references` | Array | No | Reference URLs |
| `enabled` | Boolean | No | Whether the integration is enabled |

> **Note**: Do not include the `id` field — it is auto-generated by the Indexer.

**Example Request**

```bash
curl -sk -u admin:admin -X POST \
  "https://192.168.56.6:9200/_plugins/_content_manager/integrations" \
  -H 'Content-Type: application/json' \
  -d '{
    "resource": {
      "title": "azure-functions",
      "author": "Wazuh Inc.",
      "category": "cloud-services",
      "description": "This integration supports Azure Functions app logs.",
      "documentation": "https://docs.wazuh.com/integrations/azure-functions",
      "references": [
        "https://wazuh.com"
      ],
      "enabled": true
    }
  }'
```

**Example Response**

```json
{
  "message": "94e5a2af-505e-4164-ab62-576a71873308",
  "status": 201
}
```

The `message` field contains the UUID of the created integration.

**Status Codes**

| Code | Description |
|---|---|
| 201 | Integration created |
| 400 | Missing required fields (`title`, `author`, `category`), duplicate title, or validation failure |
| 500 | Internal error or SAP/Engine unavailable |

---

### Update Integration

Updates an existing integration in the draft space. Only integrations in the draft space can be updated.

**Request**
- Method: `PUT`
- Path: `/_plugins/_content_manager/integrations/{id}`

**Parameters**

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `id` | Path | String (UUID) | Yes | Integration document ID |

**Request Body**

| Field | Type | Required | Description |
|---|---|---|---|
| `resource` | Object | Yes | Updated integration definition |

Fields within `resource` (all required for update):

| Field | Type | Required | Description |
|---|---|---|---|
| `title` | String | Yes | Integration title |
| `author` | String | Yes | Author |
| `category` | String | Yes | Category |
| `description` | String | Yes | Description |
| `documentation` | String | Yes | Documentation text or URL |
| `references` | Array | Yes | Reference URLs |
| `enabled` | Boolean | No | Whether the integration is enabled |
| `rules` | Array | Yes | Ordered list of rule IDs |
| `decoders` | Array | Yes | Ordered list of decoder IDs |
| `kvdbs` | Array | Yes | Ordered list of KVDB IDs |

> **Note**: The `rules`, `decoders`, and `kvdbs` arrays are mandatory on update to allow reordering. Pass empty arrays `[]` if the integration has none.

**Example Request**

```bash
curl -sk -u admin:admin -X PUT \
  "https://192.168.56.6:9200/_plugins/_content_manager/integrations/94e5a2af-505e-4164-ab62-576a71873308" \
  -H 'Content-Type: application/json' \
  -d '{
    "resource": {
      "title": "azure-functions-update",
      "author": "Wazuh Inc.",
      "category": "cloud-services",
      "description": "This integration supports Azure Functions app logs.",
      "documentation": "updated documentation",
      "references": [],
      "enabled": true,
      "rules": [],
      "decoders": [],
      "kvdbs": []
    }
  }'
```

**Example Response**

```json
{
  "message": "94e5a2af-505e-4164-ab62-576a71873308",
  "status": 200
}
```

**Status Codes**

| Code | Description |
|---|---|
| 200 | Integration updated |
| 400 | Invalid request, missing required fields, not in draft space, or duplicate title |
| 404 | Integration not found |
| 500 | Internal error |

---

### Delete Integration

Deletes an integration from the draft space. The integration must have no attached decoders, rules, or KVDBs — delete those first.

**Request**
- Method: `DELETE`
- Path: `/_plugins/_content_manager/integrations/{id}`

**Parameters**

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `id` | Path | String (UUID) | Yes | Integration document ID |

**Example Request**

```bash
curl -sk -u admin:admin -X DELETE \
  "https://192.168.56.6:9200/_plugins/_content_manager/integrations/94e5a2af-505e-4164-ab62-576a71873308"
```

**Example Response**

```json
{
  "message": "94e5a2af-505e-4164-ab62-576a71873308",
  "status": 200
}
```

**Example Response (has dependencies)**

```json
{
  "message": "Cannot delete integration because it has decoders attached",
  "status": 400
}
```

**Status Codes**

| Code | Description |
|---|---|
| 200 | Integration deleted |
| 400 | Integration has dependent resources (decoders/rules/kvdbs) |
| 404 | Integration not found |
| 500 | Internal error |

---

## KVDBs

### Create KVDB

Creates a new key-value database in the draft space, linked to the specified integration.

**Request**
- Method: `POST`
- Path: `/_plugins/_content_manager/kvdbs`

**Request Body**

| Field | Type | Required | Description |
|---|---|---|---|
| `integration` | String | Yes | UUID of the parent integration (must be in draft space) |
| `resource` | Object | Yes | The KVDB definition |

Fields within `resource`:

| Field | Type | Required | Description |
|---|---|---|---|
| `title` | String | Yes | KVDB title |
| `author` | String | Yes | Author |
| `content` | Object | Yes | Key-value data (at least one entry required) |
| `name` | String | No | KVDB identifier name |
| `enabled` | Boolean | No | Whether the KVDB is enabled |
| `description` | String | No | Description |
| `documentation` | String | No | Documentation |
| `references` | Array | No | Reference URLs |

**Example Request**

```bash
curl -sk -u admin:admin -X POST \
  "https://192.168.56.6:9200/_plugins/_content_manager/kvdbs" \
  -H 'Content-Type: application/json' \
  -d '{
    "integration": "f16f33ec-a5ea-4dc4-bf33-616b1562323a",
    "resource": {
      "title": "non_standard_timezones",
      "name": "non_standard_timezones",
      "enabled": true,
      "author": "Wazuh Inc.",
      "content": {
        "non_standard_timezones": {
          "AEST": "Australia/Sydney",
          "CEST": "Europe/Berlin",
          "CST": "America/Chicago",
          "EDT": "America/New_York",
          "EST": "America/New_York",
          "IST": "Asia/Kolkata",
          "MST": "America/Denver",
          "PKT": "Asia/Karachi",
          "SST": "Asia/Singapore",
          "WEST": "Europe/London"
        }
      },
      "description": "",
      "documentation": "",
      "references": [
        "https://wazuh.com"
      ]
    }
  }'
```

**Example Response**

```json
{
  "message": "9d4ec6d5-8e30-4ea3-be05-957968c02dae",
  "status": 201
}
```

The `message` field contains the UUID of the created KVDB.

**Status Codes**

| Code | Description |
|---|---|
| 201 | KVDB created |
| 400 | Missing `integration` or required resource fields, integration not in draft space |
| 500 | Internal error |

---

### Update KVDB

Updates an existing KVDB in the draft space.

**Request**
- Method: `PUT`
- Path: `/_plugins/_content_manager/kvdbs/{id}`

**Parameters**

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `id` | Path | String (UUID) | Yes | KVDB document ID |

**Request Body**

| Field | Type | Required | Description |
|---|---|---|---|
| `resource` | Object | Yes | Updated KVDB definition |

Fields within `resource` (all required for update):

| Field | Type | Required | Description |
|---|---|---|---|
| `title` | String | Yes | KVDB title |
| `author` | String | Yes | Author |
| `content` | Object | Yes | Key-value data |
| `description` | String | Yes | Description |
| `documentation` | String | Yes | Documentation |
| `references` | Array | Yes | Reference URLs |
| `name` | String | No | KVDB identifier name |
| `enabled` | Boolean | No | Whether the KVDB is enabled |

**Example Request**

```bash
curl -sk -u admin:admin -X PUT \
  "https://192.168.56.6:9200/_plugins/_content_manager/kvdbs/9d4ec6d5-8e30-4ea3-be05-957968c02dae" \
  -H 'Content-Type: application/json' \
  -d '{
    "resource": {
      "name": "test-UPDATED",
      "enabled": true,
      "author": "Wazuh.",
      "content": {
        "non_standard_timezones": {
          "AEST": "Australia/Sydney",
          "CEST": "Europe/Berlin",
          "CST": "America/Chicago",
          "EDT": "America/New_York",
          "EST": "America/New_York",
          "IST": "Asia/Kolkata",
          "MST": "America/Denver",
          "PKT": "Asia/Karachi",
          "SST": "Asia/Singapore",
          "WEST": "Europe/London"
        }
      },
      "description": "UPDATE",
      "documentation": "UPDATE.doc",
      "references": [
        "https://wazuh.com"
      ],
      "title": "non_standard_timezones-2"
    }
  }'
```

**Example Response**

```json
{
  "message": "9d4ec6d5-8e30-4ea3-be05-957968c02dae",
  "status": 200
}
```

**Status Codes**

| Code | Description |
|---|---|
| 200 | KVDB updated |
| 400 | Invalid request, missing required fields, or not in draft space |
| 404 | KVDB not found |
| 500 | Internal error |

---

### Delete KVDB

Deletes a KVDB from the draft space. The KVDB is also removed from any integrations that reference it.

**Request**
- Method: `DELETE`
- Path: `/_plugins/_content_manager/kvdbs/{id}`

**Parameters**

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `id` | Path | String (UUID) | Yes | KVDB document ID |

**Example Request**

```bash
curl -sk -u admin:admin -X DELETE \
  "https://192.168.56.6:9200/_plugins/_content_manager/kvdbs/9d4ec6d5-8e30-4ea3-be05-957968c02dae"
```

**Example Response**

```json
{
  "message": "9d4ec6d5-8e30-4ea3-be05-957968c02dae",
  "status": 200
}
```

**Status Codes**

| Code | Description |
|---|---|
| 200 | KVDB deleted |
| 404 | KVDB not found |
| 500 | Internal error |

---

## Promotion

### Preview Promotion Changes

Returns a preview of changes that would be applied when promoting from the specified space. This is a dry-run operation that does not modify any content.

**Request**
- Method: `GET`
- Path: `/_plugins/_content_manager/promote`

**Parameters**

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `space` | Query | String | Yes | Source space to preview: `draft` or `test` |

**Example Request**

```bash
curl -sk -u admin:admin \
  "https://192.168.56.6:9200/_plugins/_content_manager/promote?space=draft"
```

**Example Response**

```json
{
  "changes": {
    "kvdbs": [
      {
        "operation": "add",
        "id": "4441d331-847a-43ed-acc6-4e09d8d6abb9"
      }
    ],
    "rules": [],
    "decoders": [],
    "filters": [],
    "integrations": [
      {
        "operation": "add",
        "id": "f16f33ec-a5ea-4dc4-bf33-616b1562323a"
      }
    ],
    "policy": [
      {
        "operation": "update",
        "id": "f75bda3d-1926-4a8d-9c75-66382109ab04"
      }
    ]
  }
}
```

The response lists changes grouped by content type. Each change includes:
- `operation`: `add`, `update`, or `remove`
- `id`: Document ID of the affected resource

**Status Codes**

| Code | Description |
|---|---|
| 200 | Preview returned successfully |
| 400 | Invalid or missing `space` parameter |
| 500 | Internal error |

---

### Execute Promotion

Promotes content from the source space to the next space in the promotion chain (Draft → Test → Custom). The request body must include the source space and the changes to apply (typically obtained from the preview endpoint).

**Request**
- Method: `POST`
- Path: `/_plugins/_content_manager/promote`

**Request Body**

| Field | Type | Required | Description |
|---|---|---|---|
| `space` | String | Yes | Source space: `draft` or `test` |
| `changes` | Object | Yes | Changes to promote (from preview response) |

The `changes` object contains arrays for each content type (`policy`, `integrations`, `kvdbs`, `decoders`, `rules`, `filters`), each with `operation` and `id` fields.

**Example Request**

```bash
curl -sk -u admin:admin -X POST \
  "https://192.168.56.6:9200/_plugins/_content_manager/promote" \
  -H 'Content-Type: application/json' \
  -d '{
    "space": "draft",
    "changes": {
      "kvdbs": [],
      "decoders": [
        {
          "operation": "add",
          "id": "f56f3865-2827-464b-8335-30561b0f381b"
        }
      ],
      "rules": [],
      "filters": [],
      "integrations": [
        {
          "operation": "add",
          "id": "0aa4fc6f-1cfd-4a7c-b30b-643f32950f1f"
        }
      ],
      "policy": [
        {
          "operation": "update",
          "id": "baf9b03f-5872-4409-ab02-507b7f93d0c8"
        }
      ]
    }
  }'
```

**Example Response**

```json
{
  "message": "Promotion completed successfully",
  "status": 200
}
```

**Status Codes**

| Code | Description |
|---|---|
| 200 | Promotion successful |
| 400 | Invalid request body or missing `space` field |
| 500 | Engine communication error or validation failure |
