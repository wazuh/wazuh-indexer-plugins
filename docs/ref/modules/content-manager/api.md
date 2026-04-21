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

| Code | Description                 |
| ---- | --------------------------- |
| 200  | Subscription token returned |
| 404  | No subscription registered  |

---

### Register CTI Subscription

Registers a new CTI subscription using a device code obtained from the Wazuh CTI Console.

**Request**
- Method: `POST`
- Path: `/_plugins/_content_manager/subscription`

**Request Body**

| Field         | Type    | Required | Description                                |
| ------------- | ------- | -------- | ------------------------------------------ |
| `device_code` | String  | Yes      | Device authorization code from CTI Console |
| `client_id`   | String  | Yes      | OAuth client identifier                    |
| `expires_in`  | Integer | Yes      | Token expiration time in seconds           |
| `interval`    | Integer | Yes      | Polling interval in seconds                |

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

| Code | Description                                                                    |
| ---- | ------------------------------------------------------------------------------ |
| 201  | Subscription registered successfully                                           |
| 400  | Missing required fields (`device_code`, `client_id`, `expires_in`, `interval`) |
| 401  | Unauthorized — endpoint accessed by unexpected user                            |
| 500  | Internal error                                                                 |

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

| Code | Description               |
| ---- | ------------------------- |
| 200  | Subscription deleted      |
| 404  | No subscription to delete |

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

| Code | Description                             |
| ---- | --------------------------------------- |
| 200  | Sync triggered successfully             |
| 404  | No subscription token found             |
| 409  | A content update is already in progress |
| 429  | Rate limit exceeded                     |
| 500  | Internal error during sync              |

---

## Logtest

### Execute Logtest

Sends a log event to the Wazuh Engine for analysis. If an `integration` ID is provided, the integration's Sigma rules are also evaluated against the normalized event via the Security Analytics Plugin (SAP). If `integration` is omitted, only the normalization step is performed and the `detection` section is returned with `status: "skipped"`.

> **Note**: A testing policy must be loaded in the Engine for logtest to execute successfully. Load a policy via the policy promotion endpoint. When an integration is specified, it must exist in the specified space.

**Request**
- Method: `POST`
- Path: `/_plugins/_content_manager/logtest`

**Request Body**

| Field            | Type    | Required | Description                                          |
| ---------------- | ------- | -------- | ---------------------------------------------------- |
| `integration`    | String  | No       | ID of the integration to test against. If omitted, only normalization is performed. |
| `space`          | String  | Yes      | `"test"` or `"standard"`                             |
| `queue`          | Integer | Yes      | Queue number for logtest execution                   |
| `location`       | String  | Yes      | Log file path or logical source location             |
| `event`          | String  | Yes      | Raw log event to test                                |
| `metadata`       | Object  | No       | Optional metadata passed to the Engine               |
| `trace_level`    | String  | No       | Trace verbosity: `NONE`, `ASSET_ONLY`, or `ALL`      |

**Example Request**

```bash
curl -sk -u admin:admin -X POST \
  "https://192.168.56.6:9200/_plugins/_content_manager/logtest" \
  -H 'Content-Type: application/json' \
  -d '{
    "integration": "a0b448c8-3d3c-47d4-b7b9-cbc3c175f509",
    "space": "test",
    "queue": 1,
    "location": "/var/log/cassandra/system.log",
    "event": "INFO  [main] 2026-03-31 10:00:00 StorageService.java:123 - Node is ready to serve",
    "trace_level": "NONE"
  }'
```

**Example Response (success with rule match)**

```json
{
  "status": 200,
  "message": {
    "normalization": {
      "output": {
        "event": {
          "category": ["database"],
          "kind": "event",
          "original": "INFO  [main] 2026-03-31 10:00:00 StorageService.java:123 - Node is ready to serve"
        },
        "wazuh": {
          "integration": {
            "name": "test-integ",
            "category": "other",
            "decoders": ["decoder/cassandra-default/0"]
          }
        },
        "message": "Node is ready to serve"
      },
      "asset_traces": [],
      "validation": {
        "valid": true,
        "errors": []
      }
    },
    "detection": {
      "status": "success",
      "rules_evaluated": 2,
      "rules_matched": 1,
      "matches": [
        {
          "rule": {
            "id": "85bba177-a2e9-4468-9d59-26f4798906c9",
            "title": "Cassandra Database Event Detected",
            "level": "low",
            "tags": []
          },
          "matched_conditions": [
            "event.category matched 'database'",
            "event.kind matched 'event'"
          ]
        }
      ]
    }
  }
}
```

**Example Response (Engine error, SAP skipped)**

```json
{
  "status": 200,
  "message": {
    "normalization": {
      "status": "error",
      "error": {
        "message": "Failed to parse protobuff json request: invalid value",
        "code": "ENGINE_ERROR"
      }
    },
    "detection": {
      "status": "skipped",
      "reason": "Engine processing failed"
    }
  }
}
```

**Example Response (no rules in integration)**

```json
{
  "status": 200,
  "message": {
    "normalization": {
      "output": { "..." : "..." },
      "asset_traces": [],
      "validation": { "valid": true, "errors": [] }
    },
    "detection": {
      "status": "success",
      "rules_evaluated": 0,
      "rules_matched": 0,
      "matches": []
    }
  }
}
```

**Example Request (normalization only, no integration)**

```bash
curl -sk -u admin:admin -X POST \
  "https://192.168.56.6:9200/_plugins/_content_manager/logtest" \
  -H 'Content-Type: application/json' \
  -d '{
    "space": "test",
    "queue": 1,
    "location": "/var/log/syslog",
    "event": "Mar 31 10:00:00 myhost sshd[1234]: Accepted publickey for user from 192.168.1.1 port 22 ssh2",
    "trace_level": "NONE"
  }'
```

**Example Response (normalization only)**

```json
{
  "status": 200,
  "message": {
    "normalization": {
      "output": {
        "event": {
          "original": "Mar 31 10:00:00 myhost sshd[1234]: Accepted publickey for user from 192.168.1.1 port 22 ssh2"
        }
      },
      "asset_traces": [],
      "validation": { "valid": true, "errors": [] }
    },
    "detection": {
      "status": "skipped",
      "reason": "No integration provided"
    }
  }
}
```

**Response Fields**

| Field                                  | Type    | Description                                                  |
| -------------------------------------- | ------- | ------------------------------------------------------------ |
| `normalization.output`                 | Object  | Engine normalized event output                               |
| `normalization.asset_traces`           | Array   | List of decoders that processed the event                    |
| `normalization.validation`             | Object  | Validation result (`valid`, `errors`)                        |
| `normalization.status`                 | String  | Present on error: `"error"`                                  |
| `normalization.error`                  | Object  | Present on error: `message` and `code`                       |
| `detection.status`                     | String  | `"success"`, `"error"`, or `"skipped"`                       |
| `detection.reason`                     | String  | Present when status is `"skipped"`                           |
| `detection.rules_evaluated`            | Integer | Number of Sigma rules evaluated                              |
| `detection.rules_matched`              | Integer | Number of rules that matched                                 |
| `detection.matches`                    | Array   | List of matched rules with details                           |
| `detection.matches[].rule`             | Object  | Rule metadata: `id`, `title`, `level`, `tags`                |
| `detection.matches[].matched_conditions` | Array | Human-readable descriptions of conditions that matched       |

**Status Codes**

| Code | Description                                        |
| ---- | -------------------------------------------------- |
| 200  | Logtest executed (check inner status fields)       |
| 400  | Missing/invalid fields or integration not found    |
| 500  | Engine socket communication error or internal error|

---

## Policy

### Update Policy

Updates the routing policy in the specified space. The policy defines which integrations are active, the root decoder, enrichment types, and how events are routed through the Engine.

> **Note**: The `integrations` and `filters` arrays allow reordering but do not allow adding or removing entries — membership is managed via their respective CRUD endpoints.

**Space-specific behavior**

- **Draft space** (`/policy/draft`): All policy fields are accepted. The metadata fields `author`, `description`, `documentation`, and `references` are required in addition to the boolean fields.
- **Standard space** (`/policy/standard`): Only `enrichments`, `filters`, `enabled`, `index_unclassified_events`, and `index_discarded_events` can be modified. All other fields are preserved from the existing standard policy document. If the update changes the space hash, the full standard policy is automatically loaded to the local Engine.

**Request**
- Method: `PUT`
- Path: `/_plugins/_content_manager/policy/{space}`

**Path Parameters**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `space` | String | Yes | Target space (`draft` or `standard`) |

**Request Body**

| Field      | Type   | Required | Description                |
| ---------- | ------ | -------- | -------------------------- |
| `resource` | Object | Yes      | The policy resource object |

Fields within `resource`:

| Field | Type | Required | Description |
|---|---|---|---|
| `metadata` | Object | Yes (draft) | Policy metadata (see below) |
| `root_decoder` | String | No | Identifier of the root decoder for event processing |
| `integrations` | Array | No | List of integration IDs (reorder only, no add/remove) |
| `filters` | Array | No | List of filter UUIDs (reorder only, no add/remove) |
| `enrichments` | Array | No | Enrichment types (no duplicates; values depend on engine capabilities) |
| `enabled` | Boolean | Yes | Whether the policy is active and synchronized by the Engine |
| `index_unclassified_events` | Boolean | Yes | Whether uncategorized events are indexed |
| `index_discarded_events` | Boolean | Yes | Whether discarded events are indexed |

Fields within `resource.metadata`:

| Field | Type | Required | Description |
|---|---|---|---|
| `title` | String | No | Human-readable policy name |
| `author` | String | Yes (draft) | Author of the policy |
| `description` | String | Yes (draft) | Brief description |
| `documentation` | String | Yes (draft) | Documentation text or URL |
| `references` | Array | Yes (draft) | External reference URLs |

**Example Request (draft space)**

```bash
curl -sk -u admin:admin -X PUT \
  "https://192.168.56.6:9200/_plugins/_content_manager/policy/draft" \
  -H 'Content-Type: application/json' \
  -d '{
    "resource": {
      "metadata": {
        "title": "Draft policy",
        "author": "Wazuh Inc.",
        "description": "Custom policy",
        "documentation": "",
        "references": [
          "https://wazuh.com"
        ]
      },
      "root_decoder": "",
      "integrations": [
        "f16f33ec-a5ea-4dc4-bf33-616b1562323a"
      ],
      "filters": [],
      "enrichments": [],
      "enabled": true,
      "index_unclassified_events": false,
      "index_discarded_events": false
    }
  }'
```

**Example Request (standard space)**

```bash
curl -sk -u admin:admin -X PUT \
  "https://192.168.56.6:9200/_plugins/_content_manager/policy/standard" \
  -H 'Content-Type: application/json' \
  -d '{
    "resource": {
      "enrichments": ["connection"],
      "filters": [],
      "enabled": true,
      "index_unclassified_events": false,
      "index_discarded_events": false
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
| 400 | Invalid space, missing `resource` field, missing required fields, invalid enrichments, or disallowed modification of `integrations`/`filters` |
| 500 | Internal error |

---

## Rules

Rules follow the Sigma format with Wazuh extensions. See [Sigma Rules](sigma-rules.md) for the full format reference, including the `mitre`, `compliance`, and `metadata` blocks.

> **Validation notes**:
> - The `logsource.product` field must exactly match the `metadata.title` of the parent integration.
> - Detection fields are validated against the Wazuh Common Schema (WCS); rules referencing unknown fields are rejected.
> - IPv6 addresses are supported in detection conditions (standard, compressed, and CIDR notation).

### Create Rule

Creates a new detection rule in the draft space. The rule is linked to the specified parent integration and validated by the Security Analytics Plugin.

The rule is also synchronized to the SAP, where a separate document is created with its own auto-generated UUID. The SAP document stores the CTI document UUID in a `document.id` field and the space in a `source` field (e.g., "Draft") for cross-reference.

**Request**
- Method: `POST`
- Path: `/_plugins/_content_manager/rules`

**Request Body**

| Field         | Type   | Required | Description                                             |
| ------------- | ------ | -------- | ------------------------------------------------------- |
| `integration` | String | Yes      | UUID of the parent integration (must be in draft space) |
| `resource`    | Object | Yes      | The rule definition                                     |

Fields within `resource`:

| Field         | Type    | Required | Description                                                 |
| ------------- | ------- | -------- | ----------------------------------------------------------- |
| `metadata`    | Object  | Yes      | Rule metadata (see below)                                   |
| `sigma_id`    | String  | No       | Sigma rule ID                                               |
| `enabled`     | Boolean | No       | Whether the rule is enabled                                 |
| `status`      | String  | Yes      | Rule status (e.g., `experimental`, `stable`)                |
| `level`       | String  | Yes      | Alert level (e.g., `low`, `medium`, `high`, `critical`)     |
| `logsource`   | Object  | No       | Log source definition (`product`, `category`)               |
| `detection`   | Object  | Yes      | Sigma detection logic with `condition` and selection fields |
| `mitre`       | Object  | No       | MITRE ATT&CK mapping (see [Sigma Rules](sigma-rules.md#mitre-attck-block))       |
| `compliance`  | Object  | No       | Compliance framework mapping (see [Sigma Rules](sigma-rules.md#compliance-block)) |

Fields within `resource.metadata`:

| Field           | Type   | Required | Description                                        |
| --------------- | ------ | -------- | -------------------------------------------------- |
| `title`         | String | Yes      | Rule title (must be unique within the draft space) |
| `author`        | String | No       | Rule author                                        |
| `description`   | String | No       | Rule description                                   |
| `references`    | Array  | No       | Reference URLs                                     |
| `documentation` | String | No       | Documentation text or URL                          |

**Example Request**

```bash
curl -sk -u admin:admin -X POST \
  "https://192.168.56.6:9200/_plugins/_content_manager/rules" \
  -H 'Content-Type: application/json' \
  -d '{
    "integration": "6b7b7645-00da-44d0-a74b-cffa7911e89c",
    "resource": {
      "metadata": {
        "title": "Test Rule",
        "description": "A Test rule",
        "author": "Tester",
        "references": [
          "https://wazuh.com"
        ]
      },
      "sigma_id": "19aefed0-ffd4-47dc-a7fc-f8b1425e84f9",
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
      "level": "low",
      "mitre": {
        "tactic": ["TA0001"],
        "technique": ["T1190"],
        "subtechnique": []
      },
      "compliance": {
        "pci_dss": ["6.5.1"]
      }
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

| Code | Description                                                                            |
| ---- | -------------------------------------------------------------------------------------- |
| 201  | Rule created                                                                           |
| 400  | Missing fields, duplicate title, integration not in draft space, or validation failure |
| 500  | Internal error or SAP unavailable                                                      |

---

### Update Rule

Updates an existing rule in the draft space.

**Request**
- Method: `PUT`
- Path: `/_plugins/_content_manager/rules/{id}`

**Parameters**

| Name | In   | Type          | Required | Description      |
| ---- | ---- | ------------- | -------- | ---------------- |
| `id` | Path | String (UUID) | Yes      | Rule document ID |

**Request Body**

| Field      | Type   | Required | Description                                     |
| ---------- | ------ | -------- | ----------------------------------------------- |
| `resource` | Object | Yes      | Updated rule definition (same fields as create) |

> **Note**: On update, `enabled`, `metadata.title`, and `metadata.author` are required. The `detection` and `logsource` fields are also required.

**Example Request**

```bash
curl -sk -u admin:admin -X PUT \
  "https://192.168.56.6:9200/_plugins/_content_manager/rules/6e1c43f1-f09b-4cec-bb59-00e3a52b7930" \
  -H 'Content-Type: application/json' \
  -d '{
    "resource": {
      "metadata": {
        "title": "Test Hash Generation Rule",
        "description": "A rule to verify that SHA-256 hashes are calculated correctly upon creation.",
        "author": "Tester"
      },
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
  "status": 200
}
```

**Status Codes**

| Code | Description                                                |
| ---- | ---------------------------------------------------------- |
| 200  | Rule updated                                               |
| 400  | Invalid request, not in draft space, or validation failure |
| 404  | Rule not found                                             |
| 500  | Internal error                                             |

---

### Delete Rule

Deletes a rule from the draft space. The rule is also removed from any integrations that reference it.

**Request**
- Method: `DELETE`
- Path: `/_plugins/_content_manager/rules/{id}`

**Parameters**

| Name | In   | Type          | Required | Description      |
| ---- | ---- | ------------- | -------- | ---------------- |
| `id` | Path | String (UUID) | Yes      | Rule document ID |

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

| Code | Description    |
| ---- | -------------- |
| 200  | Rule deleted   |
| 404  | Rule not found |
| 500  | Internal error |

---

## Decoders

### Create Decoder

Creates a new log decoder in the draft space. The decoder is validated against the Wazuh Engine before being stored, and automatically linked to the specified integration.

> **Note**: A testing policy must be loaded in the Engine for decoder validation to succeed.

**Request**
- Method: `POST`
- Path: `/_plugins/_content_manager/decoders`

**Request Body**

| Field         | Type   | Required | Description                                             |
| ------------- | ------ | -------- | ------------------------------------------------------- |
| `integration` | String | Yes      | UUID of the parent integration (must be in draft space) |
| `resource`    | Object | Yes      | The decoder definition                                  |

Fields within `resource`:

| Field       | Type    | Description                                                    |
| ----------- | ------- | -------------------------------------------------------------- |
| `name`      | String  | Decoder name identifier (e.g., `decoder/core-wazuh-message/0`) |
| `enabled`   | Boolean | Whether the decoder is enabled                                 |
| `check`     | Array   | Decoder check logic — array of condition objects               |
| `normalize` | Array   | Normalization rules — array of mapping objects                 |
| `metadata`  | Object  | Decoder metadata (see below)                                   |

Fields within `metadata`:

| Field           | Type   | Description                          |
| --------------- | ------ | ------------------------------------ |
| `title`         | String | Human-readable decoder title         |
| `description`   | String | Decoder description                  |
| `module`        | String | Module name                          |
| `compatibility` | String | Compatibility description            |
| `author`        | Object | Author info (`name`, `email`, `url`) |
| `references`    | Array  | Reference URLs                       |
| `versions`      | Array  | Supported versions                   |

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

| Code | Description                                                                               |
| ---- | ----------------------------------------------------------------------------------------- |
| 201  | Decoder created                                                                           |
| 400  | Missing `integration` field, integration not in draft space, or Engine validation failure |
| 500  | Engine unavailable or internal error                                                      |

---

### Update Decoder

Updates an existing decoder in the draft space. The decoder is re-validated against the Wazuh Engine.

**Request**
- Method: `PUT`
- Path: `/_plugins/_content_manager/decoders/{id}`

**Parameters**

| Name | In   | Type   | Required | Description         |
| ---- | ---- | ------ | -------- | ------------------- |
| `id` | Path | String | Yes      | Decoder document ID |

**Request Body**

| Field      | Type   | Required | Description                                        |
| ---------- | ------ | -------- | -------------------------------------------------- |
| `resource` | Object | Yes      | Updated decoder definition (same fields as create) |

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

| Code | Description                                                       |
| ---- | ----------------------------------------------------------------- |
| 200  | Decoder updated                                                   |
| 400  | Invalid request, not in draft space, or Engine validation failure |
| 404  | Decoder not found                                                 |
| 500  | Internal error                                                    |

---

### Delete Decoder

Deletes a decoder from the draft space. The decoder is also removed from any integrations that reference it.
A decoder cannot be deleted if it is currently set as the root decoder in the draft policy.

**Request**
- Method: `DELETE`
- Path: `/_plugins/_content_manager/decoders/{id}`

**Parameters**

| Name | In   | Type   | Required | Description         |
| ---- | ---- | ------ | -------- | ------------------- |
| `id` | Path | String | Yes      | Decoder document ID |

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

**Example Response (set as root decoder)**
```json
{
  "message": "Cannot remove decoder [acbdba85-09c4-45a0-a487-61c8eeec58e6] as it is set as root decoder.",
  "status": 400
}
```

**Status Codes**

| Code | Description                    |
|------|--------------------------------|
| 200  | Decoder deleted                |
| 400  | Decoder is set as root decoder |
| 404  | Decoder not found              |
| 500  | Internal error                 |


---

## Filters

### Create Filter

Creates a new filter in the draft or standard space. The filter is validated against the Wazuh Engine before being stored and automatically linked to the specified space's policy.

**Request**
- Method: `POST`
- Path: `/_plugins/_content_manager/filters`

**Request Body**

| Field      | Type   | Required | Description                         |
| ---------- | ------ | -------- | ----------------------------------- |
| `space`    | String | Yes      | Target space: `draft` or `standard` |
| `resource` | Object | Yes      | The filter definition               |

Fields within `resource`:

| Field      | Type    | Description                                         |
| ---------- | ------- | --------------------------------------------------- |
| `name`     | String  | Filter name identifier (e.g., `filter/prefilter/0`) |
| `enabled`  | Boolean | Whether the filter is enabled                       |
| `check`    | String  | Filter check expression                             |
| `type`     | String  | Filter type (e.g., `pre-filter`)                    |
| `metadata` | Object  | Filter metadata (see below)                         |

Fields within `metadata`:

| Field         | Type   | Description                          |
| ------------- | ------ | ------------------------------------ |
| `description` | String | Filter description                   |
| `author`      | Object | Author info (`name`, `email`, `url`) |

**Example Request**

```bash
curl -sk -u admin:admin -X POST \
  "https://192.168.56.6:9200/_plugins/_content_manager/filters" \
  -H 'Content-Type: application/json' \
  -d '{
    "space": "draft",
    "resource": {
      "name": "filter/prefilter/0",
      "enabled": true,
      "metadata": {
        "description": "Default filter to allow all events (for default ruleset)",
        "author": {
          "email": "info@wazuh.com",
          "name": "Wazuh, Inc.",
          "url": "https://wazuh.com"
        }
      },
      "check": "$host.os.platform == '\''ubuntu'\''",
      "type": "pre-filter"
    }
  }'
```

**Example Response**

```json
{
  "message": "f_a1b2c3d4-e5f6-47a8-b9c0-d1e2f3a4b5c6",
  "status": 201
}
```

The `message` field contains the UUID of the created filter (prefixed with `f_`).

**Status Codes**

| Code | Description                                                        |
| ---- | ------------------------------------------------------------------ |
| 201  | Filter created                                                     |
| 400  | Missing `space` field, invalid space, or Engine validation failure |
| 500  | Engine unavailable or internal error                               |

---

### Update Filter

Updates an existing filter in the draft or standard space. The filter is re-validated against the Wazuh Engine.

**Request**
- Method: `PUT`
- Path: `/_plugins/_content_manager/filters/{id}`

**Parameters**

| Name | In   | Type   | Required | Description        |
| ---- | ---- | ------ | -------- | ------------------ |
| `id` | Path | String | Yes      | Filter document ID |

**Request Body**

| Field      | Type   | Required | Description                                       |
| ---------- | ------ | -------- | ------------------------------------------------- |
| `space`    | String | Yes      | Target space: `draft` or `standard`               |
| `resource` | Object | Yes      | Updated filter definition (same fields as create) |

**Example Request**

```bash
curl -sk -u admin:admin -X PUT \
  "https://192.168.56.6:9200/_plugins/_content_manager/filters/a1b2c3d4-e5f6-47a8-b9c0-d1e2f3a4b5c6" \
  -H 'Content-Type: application/json' \
  -d '{
    "space": "draft",
    "resource": {
      "name": "filter/prefilter/0",
      "enabled": true,
      "metadata": {
        "description": "Updated filter description",
        "author": {
          "email": "info@wazuh.com",
          "name": "Wazuh, Inc.",
          "url": "https://wazuh.com"
        }
      },
      "check": "$host.os.platform == '\''ubuntu'\''",
      "type": "pre-filter"
    }
  }'
```

**Example Response**

```json
{
  "message": "a1b2c3d4-e5f6-47a8-b9c0-d1e2f3a4b5c6",
  "status": 200
}
```

**Status Codes**

| Code | Description                                                  |
| ---- | ------------------------------------------------------------ |
| 200  | Filter updated                                               |
| 400  | Invalid request, invalid space, or Engine validation failure |
| 404  | Filter not found                                             |
| 500  | Internal error                                               |

---

### Delete Filter

Deletes a filter from the draft or standard space. The filter is also removed from the associated policy.

**Request**
- Method: `DELETE`
- Path: `/_plugins/_content_manager/filters/{id}`

**Parameters**

| Name | In   | Type   | Required | Description        |
| ---- | ---- | ------ | -------- | ------------------ |
| `id` | Path | String | Yes      | Filter document ID |

**Example Request**

```bash
curl -sk -u admin:admin -X DELETE \
  "https://192.168.56.6:9200/_plugins/_content_manager/filters/a1b2c3d4-e5f6-47a8-b9c0-d1e2f3a4b5c6"
```

**Example Response**

```json
{
  "message": "a1b2c3d4-e5f6-47a8-b9c0-d1e2f3a4b5c6",
  "status": 200
}
```

**Status Codes**

| Code | Description      |
| ---- | ---------------- |
| 200  | Filter deleted   |
| 404  | Filter not found |
| 500  | Internal error   |

---

## Integrations

### Create Integration

Creates a new integration in the draft space. An integration is a logical grouping of related rules, decoders, and KVDBs. The integration is validated against the Engine and registered in the Security Analytics Plugin.

The integration is also synchronized to the SAP, where a separate document is created with its own auto-generated UUID. The SAP document stores the CTI document UUID in a `document.id` field and the space in the `source` field (e.g., "Draft") for cross-reference.

**Request**
- Method: `POST`
- Path: `/_plugins/_content_manager/integrations`

**Request Body**

| Field      | Type   | Required | Description                |
| ---------- | ------ | -------- | -------------------------- |
| `resource` | Object | Yes      | The integration definition |

Fields within `resource`:

| Field      | Type    | Required | Description                                                                          |
| ---------- | ------- | -------- | ------------------------------------------------------------------------------------ |
| `metadata` | Object  | Yes      | Integration metadata (see below)                                                     |
| `category` | String  | Yes      | Category (e.g., `cloud-services`, `network-activity`, `security`, `system-activity`) |
| `enabled`  | Boolean | No       | Whether the integration is enabled                                                   |

Fields within `resource.metadata`:

| Field           | Type   | Required | Description                                       |
| --------------- | ------ | -------- | ------------------------------------------------- |
| `title`         | String | Yes      | Integration title (must be unique in draft space)  |
| `author`        | String | Yes      | Author of the integration                          |
| `description`   | String | No       | Description                                        |
| `documentation` | String | No       | Documentation text or URL                          |
| `references`    | Array  | No       | Reference URLs                                     |

> **Note**: Do not include the `id` field — it is auto-generated by the Indexer.

**Example Request**

```bash
curl -sk -u admin:admin -X POST \
  "https://192.168.56.6:9200/_plugins/_content_manager/integrations" \
  -H 'Content-Type: application/json' \
  -d '{
    "resource": {
      "metadata": {
        "title": "azure-functions",
        "author": "Wazuh Inc.",
        "description": "This integration supports Azure Functions app logs.",
        "documentation": "https://docs.wazuh.com/integrations/azure-functions",
        "references": [
          "https://wazuh.com"
        ]
      },
      "category": "cloud-services",
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

| Code | Description                                                                                     |
| ---- | ----------------------------------------------------------------------------------------------- |
| 201  | Integration created                                                                             |
| 400  | Missing required fields (`title`, `author`, `category`), duplicate title, or validation failure |
| 500  | Internal error or SAP/Engine unavailable                                                        |

---

### Update Integration

Updates an existing integration in the draft space. Only integrations in the draft space can be updated.

**Request**
- Method: `PUT`
- Path: `/_plugins/_content_manager/integrations/{id}`

**Parameters**

| Name | In   | Type          | Required | Description             |
| ---- | ---- | ------------- | -------- | ----------------------- |
| `id` | Path | String (UUID) | Yes      | Integration document ID |

**Request Body**

| Field      | Type   | Required | Description                    |
| ---------- | ------ | -------- | ------------------------------ |
| `resource` | Object | Yes      | Updated integration definition |

Fields within `resource` (all required for update):

| Field      | Type    | Required | Description                        |
| ---------- | ------- | -------- | ---------------------------------- |
| `metadata` | Object  | Yes      | Integration metadata (see below)   |
| `category` | String  | Yes      | Category                           |
| `enabled`  | Boolean | Yes      | Whether the integration is enabled |
| `rules`    | Array   | Yes      | Ordered list of rule IDs           |
| `decoders` | Array   | Yes      | Ordered list of decoder IDs        |
| `kvdbs`    | Array   | Yes      | Ordered list of KVDB IDs           |

Fields within `resource.metadata`:

| Field           | Type   | Required | Description               |
| --------------- | ------ | -------- | ------------------------- |
| `title`         | String | Yes      | Integration title         |
| `author`        | String | Yes      | Author                    |
| `description`   | String | Yes      | Description               |
| `documentation` | String | Yes      | Documentation text or URL |
| `references`    | Array  | Yes      | Reference URLs            |

> **Note**: The `rules`, `decoders`, and `kvdbs` arrays are mandatory on update to allow reordering. Pass empty arrays `[]` if the integration has none.

**Example Request**

```bash
curl -sk -u admin:admin -X PUT \
  "https://192.168.56.6:9200/_plugins/_content_manager/integrations/94e5a2af-505e-4164-ab62-576a71873308" \
  -H 'Content-Type: application/json' \
  -d '{
    "resource": {
      "metadata": {
        "title": "azure-functions-update",
        "author": "Wazuh Inc.",
        "description": "This integration supports Azure Functions app logs.",
        "documentation": "updated documentation",
        "references": []
      },
      "category": "cloud-services",
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

| Code | Description                                                                      |
| ---- | -------------------------------------------------------------------------------- |
| 200  | Integration updated                                                              |
| 400  | Invalid request, missing required fields, not in draft space, or duplicate title |
| 404  | Integration not found                                                            |
| 500  | Internal error                                                                   |

---

### Delete Integration

Deletes an integration from the draft space. The integration must have no attached decoders, rules, or KVDBs — delete those first.

**Request**
- Method: `DELETE`
- Path: `/_plugins/_content_manager/integrations/{id}`

**Parameters**

| Name | In   | Type          | Required | Description             |
| ---- | ---- | ------------- | -------- | ----------------------- |
| `id` | Path | String (UUID) | Yes      | Integration document ID |

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

| Code | Description                                                |
| ---- | ---------------------------------------------------------- |
| 200  | Integration deleted                                        |
| 400  | Integration has dependent resources (decoders/rules/kvdbs) |
| 404  | Integration not found                                      |
| 500  | Internal error                                             |

---

## KVDBs

### Create KVDB

Creates a new key-value database in the draft space, linked to the specified integration.

**Request**
- Method: `POST`
- Path: `/_plugins/_content_manager/kvdbs`

**Request Body**

| Field         | Type   | Required | Description                                             |
| ------------- | ------ | -------- | ------------------------------------------------------- |
| `integration` | String | Yes      | UUID of the parent integration (must be in draft space) |
| `resource`    | Object | Yes      | The KVDB definition                                     |

Fields within `resource`:

| Field      | Type    | Required | Description                                  |
| ---------- | ------- | -------- | -------------------------------------------- |
| `metadata` | Object  | Yes      | KVDB metadata (see below)                    |
| `content`  | Object  | Yes      | Key-value data (at least one entry required) |
| `name`     | String  | No       | KVDB identifier name                         |
| `enabled`  | Boolean | No       | Whether the KVDB is enabled                  |

Fields within `resource.metadata`:

| Field           | Type   | Required | Description               |
| --------------- | ------ | -------- | ------------------------- |
| `title`         | String | Yes      | KVDB title                |
| `author`        | String | Yes      | Author                    |
| `description`   | String | No       | Description               |
| `documentation` | String | No       | Documentation             |
| `references`    | Array  | No       | Reference URLs            |

**Example Request**

```bash
curl -sk -u admin:admin -X POST \
  "https://192.168.56.6:9200/_plugins/_content_manager/kvdbs" \
  -H 'Content-Type: application/json' \
  -d '{
    "integration": "f16f33ec-a5ea-4dc4-bf33-616b1562323a",
    "resource": {
      "metadata": {
        "title": "non_standard_timezones",
        "author": "Wazuh Inc.",
        "description": "",
        "documentation": "",
        "references": [
          "https://wazuh.com"
        ]
      },
      "name": "non_standard_timezones",
      "enabled": true,
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
      }
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

| Code | Description                                                                       |
| ---- | --------------------------------------------------------------------------------- |
| 201  | KVDB created                                                                      |
| 400  | Missing `integration` or required resource fields, integration not in draft space |
| 500  | Internal error                                                                    |

---

### Update KVDB

Updates an existing KVDB in the draft space.

**Request**
- Method: `PUT`
- Path: `/_plugins/_content_manager/kvdbs/{id}`

**Parameters**

| Name | In   | Type          | Required | Description      |
| ---- | ---- | ------------- | -------- | ---------------- |
| `id` | Path | String (UUID) | Yes      | KVDB document ID |

**Request Body**

| Field      | Type   | Required | Description             |
| ---------- | ------ | -------- | ----------------------- |
| `resource` | Object | Yes      | Updated KVDB definition |

Fields within `resource` (all required for update):

| Field      | Type    | Required | Description                 |
| ---------- | ------- | -------- | --------------------------- |
| `metadata` | Object  | Yes      | KVDB metadata (see below)   |
| `content`  | Object  | Yes      | Key-value data              |
| `name`     | String  | No       | KVDB identifier name        |
| `enabled`  | Boolean | No       | Whether the KVDB is enabled |

Fields within `resource.metadata`:

| Field           | Type   | Required | Description               |
| --------------- | ------ | -------- | ------------------------- |
| `title`         | String | Yes      | KVDB title                |
| `author`        | String | Yes      | Author                    |
| `description`   | String | Yes      | Description               |
| `documentation` | String | Yes      | Documentation             |
| `references`    | Array  | Yes      | Reference URLs            |

**Example Request**

```bash
curl -sk -u admin:admin -X PUT \
  "https://192.168.56.6:9200/_plugins/_content_manager/kvdbs/9d4ec6d5-8e30-4ea3-be05-957968c02dae" \
  -H 'Content-Type: application/json' \
  -d '{
    "resource": {
      "metadata": {
        "title": "non_standard_timezones-2",
        "author": "Wazuh.",
        "description": "UPDATE",
        "documentation": "UPDATE.doc",
        "references": [
          "https://wazuh.com"
        ]
      },
      "name": "test-UPDATED",
      "enabled": true,
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
      }
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

| Code | Description                                                     |
| ---- | --------------------------------------------------------------- |
| 200  | KVDB updated                                                    |
| 400  | Invalid request, missing required fields, or not in draft space |
| 404  | KVDB not found                                                  |
| 500  | Internal error                                                  |

---

### Delete KVDB

Deletes a KVDB from the draft space. The KVDB is also removed from any integrations that reference it.

**Request**
- Method: `DELETE`
- Path: `/_plugins/_content_manager/kvdbs/{id}`

**Parameters**

| Name | In   | Type          | Required | Description      |
| ---- | ---- | ------------- | -------- | ---------------- |
| `id` | Path | String (UUID) | Yes      | KVDB document ID |

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

| Code | Description    |
| ---- | -------------- |
| 200  | KVDB deleted   |
| 404  | KVDB not found |
| 500  | Internal error |

---

## Promotion

### Preview Promotion Changes

Returns a preview of changes that would be applied when promoting from the specified space. This is a dry-run operation that does not modify any content.

**Request**
- Method: `GET`
- Path: `/_plugins/_content_manager/promote`

**Parameters**

| Name    | In    | Type   | Required | Description                                |
| ------- | ----- | ------ | -------- | ------------------------------------------ |
| `space` | Query | String | Yes      | Source space to preview: `draft` or `test` |

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

| Code | Description                          |
| ---- | ------------------------------------ |
| 200  | Preview returned successfully        |
| 400  | Invalid or missing `space` parameter |
| 500  | Internal error                       |

---

### Execute Promotion

Promotes content from the source space to the next space in the promotion chain (Draft → Test → Custom). The request body must include the source space and the changes to apply (typically obtained from the preview endpoint).

In addition to copying documents across CTI indices, promotion also synchronizes **integrations** and **rules** with the Security Analytics Plugin (SAP). For each promoted resource, a new SAP document is created in the target space with:
- A newly generated UUID as the SAP document primary ID.
- A `document.id` field storing the original CTI document UUID for cross-reference.
- A `source` field indicating the target space (e.g., "Test", "Custom").

New resources (ADD operations) use `POST` to create SAP documents; existing resources (UPDATE operations) use `PUT` to update them in-place.

This ensures that the same CTI resource can exist in multiple spaces with independent SAP documents.

#### Rollback on Failure

If any Content Manager index mutation fails during the consolidation phase, the endpoint
automatically performs a **LIFO rollback** to restore the system to its pre-promotion state:

1. **Pre-promotion snapshots** are captured before any writes — old versions for adds/updates, full documents for deletes.
2. **CM rollback**: Each completed mutation is undone in reverse order. ADDs are deleted, UPDATEs are restored to their previous version, DELETEs are re-indexed from the snapshot.
3. **SAP reconciliation** (best-effort): Rules and integrations synced to SAP during the forward pass are reverted — new SAP documents are deleted, updated ones are restored, and deleted ones are re-created from snapshots.

Individual rollback or SAP reconciliation step failures are logged but do not prevent remaining steps from executing. On rollback, the endpoint returns a `500` status.

**Request**
- Method: `POST`
- Path: `/_plugins/_content_manager/promote`

**Request Body**

| Field     | Type   | Required | Description                                |
| --------- | ------ | -------- | ------------------------------------------ |
| `space`   | String | Yes      | Source space: `draft` or `test`            |
| `changes` | Object | Yes      | Changes to promote (from preview response) |

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

| Code | Description                                      |
| ---- | ------------------------------------------------ |
| 200  | Promotion successful                             |
| 400  | Invalid request body or missing `space` field    |
| 500  | Engine communication error or validation failure |

---

## Spaces

### Reset Space

Resets a user space (`draft`) to its initial state.

When resetting the `draft` space, this operation will:
- Remove all documents (integrations, rules, decoders, kvdbs) that belong to the given space.
- Re-generate the default policy for the given space.

The resources are removed in the Content Manager (`wazuh-threatintel-*` indices) and in the Security Analytics Plugin (`.opensearch-sap-*` indices) to ensure a complete reset of the space. 

> **Note**: Only `draft` space can be reset.

**Request**
- Method: `DELETE`
- Path: `/_plugins/_content_manager/space/{space}`

**Parameters**

| Name    | In   | Type   | Required | Description                                   |
| ------- | ---- | ------ | -------- | --------------------------------------------- |
| `space` | Path | String | Yes      | The name of the user space to reset (`draft`) |

**Example Request**

```bash
curl -sk -u admin:admin -X DELETE \
  "https://192.168.56.6:9200/_plugins/_content_manager/space/draft"
```

**Example Response**

```json
{
  "message": "Space reset successfully",
  "status": 200
}
```

**Status Codes**

| Code | Description                                                                    |
| ---- | ------------------------------------------------------------------------------ |
| 200  | Space reset successfully                                                       |
| 400  | Invalid space identifier, or attempted to reset a space different from `draft` |
| 500  | Internal error (e.g., Engine unavailable or deletion failure)                  |

## Version Check

### Check Available Updates

Returns whether there are newer versions of Wazuh available for download. The endpoint reads the current installed version from `VERSION.json` and queries the CTI API for available updates. The response includes the latest available major, minor, and patch updates when available.

**Request**
- Method: `GET`
- Path: `/_plugins/_content_manager/version/check`

**Example Request**

```bash
curl -sk -u admin:admin \
  "https://192.168.56.6:9200/_plugins/_content_manager/version/check"
```

**Example Response (updates available)**

```json
{
  "message": {
    "uuid": "bd7f0db0-d094-48ca-b883-7019484ce71f",
    "last_check_date": "2026-04-14T15:28:41.347387+00:00",
    "current_version": "v5.0.0",
    "last_available_major": {
      "tag": "v6.0.0",
      "title": "Wazuh v6.0.0",
      "description": "Major release with new features...",
      "published_date": "2026-03-01T10:00:00Z",
      "semver": { "major": 6, "minor": 0, "patch": 0 }
    },
    "last_available_minor": {
      "tag": "v5.1.0",
      "title": "Wazuh v5.1.0",
      "description": "Minor improvements and enhancements...",
      "published_date": "2026-02-15T10:00:00Z",
      "semver": { "major": 5, "minor": 1, "patch": 0 }
    },
    "last_available_patch": {
      "tag": "v5.0.1",
      "title": "Wazuh v5.0.1",
      "description": "Bug fixes and stability improvements...",
      "published_date": "2026-01-20T10:00:00Z",
      "semver": { "major": 5, "minor": 0, "patch": 1 }
    }
  },
  "status": 200
}
```

**Example Response (no updates)**

```json
{
  "message": {
    "uuid": "bd7f0db0-d094-48ca-b883-7019484ce71f",
    "last_check_date": "2026-04-14T15:28:41.347387+00:00",
    "current_version": "v5.0.0",
    "last_available_major": {},
    "last_available_minor": {},
    "last_available_patch": {}
  },
  "status": 200
}
```

**Example Response (version not found)**

```json
{
  "message": "Unable to determine current Wazuh version.",
  "status": 500
}
```

**Status Codes**

| Code | Description                                            |
| ---- | ------------------------------------------------------ |
| 200  | Version check completed (may include updates or empty) |
| 500  | Unable to determine version or internal error          |
| 502  | CTI API returned an error                              |

> **Note**: Categories with no available updates are represented as empty objects `{}`.

---

## Documentation Maintenance

To maintain technical consistency, any modification, addition or removal \
of endpoints in the REST API source code must be reflected in the `openapi.yml` \
specification and this `api.md` reference guide.
