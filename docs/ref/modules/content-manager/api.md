# API reference

The Content Manager plugin exposes a REST API under `/_plugins/_content_manager/`. All endpoints require authentication. The full machine-readable specification is available in [`openapi.yml`](https://github.com/wazuh/wazuh-indexer-plugins/blob/main/plugins/content-manager/openapi.yml).

## Sections

- [YAML content-type support](#yaml-content-type-support)
- [Subscription management](#subscription-management)
- [Content updates](#content-updates)
- [Logtest](#logtest)
- [Policy](#policy)
- [Rules](#rules)
- [Decoders](#decoders)
- [Filters](#filters)
- [Integrations](#integrations)
- [KVDBs](#kvdbs)
- [Promotion](#promotion)
- [Spaces](#spaces)
- [Version check](#version-check)

---

## YAML content-type support

The **Decoders**, **KVDBs**, and **Filters** endpoints accept requests with `Content-Type: application/yaml` in addition to the standard `Content-Type: application/json`. When using YAML, the request body uses the same envelope structure as JSON — the only difference is the serialization format.

### Envelope structure

Both JSON and YAML requests use the same envelope:

**JSON example:**

```json
{
  "integration": "<uuid>",
  "resource": {
    "metadata": { "title": "My Decoder", "author": "Wazuh" },
    "name": "decoder/my-decoder/0",
    "enabled": true
  }
}
```

**Equivalent YAML example:**

```yaml
---
integration: <uuid>
resource:
  metadata:
    title: "My Decoder"
    author: "Wazuh"
  name: decoder/my-decoder/0
  enabled: true
```

For resource types that do not require an `integration` field (e.g., Filters, which use `space` instead), the corresponding field appears at the top level of the envelope in both formats.

### YAML field in responses

When a Decoder, KVDB, or Filter is created or updated, a `yaml` field is stored alongside the `document` in the indexed record. This field contains a YAML representation of the resource content:

- **YAML requests**: the `yaml` field is generated from the `resource` subtree of the parsed envelope.
- **JSON requests**: the `yaml` field is auto-generated from the resource content.

### Type fidelity

YAML parsing preserves numeric type fidelity. Floating-point values like `5.0` are stored as `5.0` in both the `yaml` field and the `document` field — they are not coerced to integers.

### Supported endpoints

- **`/_plugins/_content_manager/decoders`** (POST, PUT) — YAML supported.
- **`/_plugins/_content_manager/kvdbs`** (POST, PUT) — YAML supported.
- **`/_plugins/_content_manager/filters`** (POST, PUT) — YAML supported.
- **`/_plugins/_content_manager/integrations`** (POST, PUT) — JSON only.
- **`/_plugins/_content_manager/rules`** (POST, PUT) — JSON only.
- **`/_plugins/_content_manager/policy/{space}`** (PUT) — JSON only.

---

## Subscription management

### Store CTI credentials

Stores the provided CTI access token in the `.wazuh-internal-state` hidden index and loads it into memory. If the index does not exist it is recreated automatically before writing.

#### Request

- Method: `POST`
- Path: `/_plugins/_content_manager/subscription`

#### Request body

- **`access_token`** (String, required) — the CTI access token used to authenticate against the CTI API.

#### Example request

```bash
curl -sk -u admin:admin -X POST \
  "https://127.0.0.1:9200/_plugins/_content_manager/subscription" \
  -H 'Content-Type: application/json' \
  -d '{
    "access_token": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS"
  }'
```

#### Example response

```json
{
  "message": "Credentials received",
  "status": 201
}
```

#### Status codes

- **201** — credentials stored successfully.
- **400** — missing or empty `access_token` field.
- **412** — a required precondition is not met (for example, the credentials index is not declared as a system index — see `plugins.security.system_indices.indices` in `opensearch.yml`).
- **500** — internal error.

---

### Get CTI subscription status

Returns the current subscription status and active plan. For registered instances the plan comes from the authenticated CTI endpoint; for unregistered instances, the public free plan is returned.

> If the stored token is rejected by the CTI API (e.g. expired or revoked), the credentials document is deleted automatically, the in-memory token is cleared, and the response falls back to the public free plan as if the instance were unregistered.

#### Request

- Method: `GET`
- Path: `/_plugins/_content_manager/subscription`

#### Example request

```bash
curl -sk -u admin:admin -X GET \
  "https://127.0.0.1:9200/_plugins/_content_manager/subscription"
```

#### Example response (registered)

```json
{
  "message": {
    "plan": {
      "name": "Premium Plan",
      "is_public": false
    },
    "is_registered": true
  },
  "status": 200
}
```

#### Example response (unregistered)

```json
{
  "message": {
    "plan": {
      "name": "Free",
      "is_public": true
    },
    "is_registered": false
  },
  "status": 200
}
```

#### Status codes

- **200** — subscription status returned successfully.
- **500** — internal error.

---

### Delete CTI credentials

Clears the stored CTI access token document from the credentials index and clears the in-memory token. The credentials index is preserved. After this operation the instance is unregistered. If the credentials index does not exist the operation succeeds without error.

#### Request

- Method: `DELETE`
- Path: `/_plugins/_content_manager/subscription`

#### Example request

```bash
curl -sk -u admin:admin -X DELETE \
  "https://127.0.0.1:9200/_plugins/_content_manager/subscription"
```

#### Example response

```json
{
  "message": "Credentials removed",
  "status": 200
}
```

#### Status codes

- **200** — credentials removed successfully.
- **500** — internal error.

---

## Content updates

### Trigger manual sync

Triggers an immediate content synchronization with the CTI API. Requires a valid subscription.

#### Request

- Method: `POST`
- Path: `/_plugins/_content_manager/update`

#### Example request

```bash
curl -sk -u admin:admin -X POST \
  "https://127.0.0.1:9200/_plugins/_content_manager/update"
```

#### Example response (accepted)

```json
{
  "message": "The update request has been accepted for processing.",
  "status": 202
}
```

#### Example response (no credentials)

```json
{
  "message": "Token not found. Please create a subscription before attempting to update.",
  "status": 404
}
```

#### Example response (update in progress)

```json
{
  "message": "A content update is already in progress.",
  "status": 409
}
```

#### Status codes

- **202** — update request accepted for processing.
- **404** — no access token registered.
- **409** — a content update is already in progress.
- **500** — internal error during sync.

---

## Logtest

### Execute logtest

Sends a log event to the Wazuh Engine for analysis. If an `integration` ID is provided, the integration's Sigma rules are also evaluated against the normalized event via the Security Analytics plugin. If `integration` is omitted, only the normalization step is performed and the `detection` section is returned with `status: "skipped"`.

> **Note**: A testing policy must be loaded in the Engine for logtest to execute successfully. Load a policy via the policy promotion endpoint. When an integration is specified, it must exist in the specified space.

#### Request

- Method: `POST`
- Path: `/_plugins/_content_manager/logtest`

#### Request body

- **`integration`** (String, optional) — ID of the integration to test against. If omitted, only normalization is performed.
- **`space`** (String, required) — `"test"`, `"standard"`, or `"custom"`.
- **`queue`** (Integer, required) — queue number for logtest execution.
- **`location`** (String, required) — log file path or logical source location.
- **`event`** (String, required) — raw log event to test.
- **`metadata`** (Object, optional) — optional metadata passed to the Engine.
- **`trace_level`** (String, optional) — trace verbosity: `NONE`, `ASSET_ONLY`, or `ALL`.

#### Example request

```bash
curl -sk -u admin:admin -X POST \
  "https://127.0.0.1:9200/_plugins/_content_manager/logtest" \
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

#### Example response (success with rule match)

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

#### Example response (Engine error, detection skipped)

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

#### Example response (no rules in integration)

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

#### Example request (normalization only, no integration)

```bash
curl -sk -u admin:admin -X POST \
  "https://127.0.0.1:9200/_plugins/_content_manager/logtest" \
  -H 'Content-Type: application/json' \
  -d '{
    "space": "test",
    "queue": 1,
    "location": "/var/log/syslog",
    "event": "Mar 31 10:00:00 myhost sshd[1234]: Accepted publickey for user from 192.168.1.1 port 22 ssh2",
    "trace_level": "NONE"
  }'
```

#### Example response (normalization only)

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

#### Response fields

- **`normalization.output`** (Object) — Engine normalized event output.
- **`normalization.asset_traces`** (Array) — list of decoders that processed the event.
- **`normalization.validation`** (Object) — validation result (`valid`, `errors`).
- **`normalization.status`** (String) — present on error: `"error"`.
- **`normalization.error`** (Object) — present on error: `message` and `code`.
- **`detection.status`** (String) — `"success"`, `"error"`, or `"skipped"`.
- **`detection.reason`** (String) — present when status is `"skipped"`.
- **`detection.rules_evaluated`** (Integer) — number of Sigma rules evaluated.
- **`detection.rules_matched`** (Integer) — number of rules that matched.
- **`detection.matches`** (Array) — list of matched rules with details.
- **`detection.matches[].rule`** (Object) — rule metadata: `id`, `title`, `level`, `tags`.
- **`detection.matches[].matched_conditions`** (Array) — human-readable descriptions of conditions that matched.

#### Status codes

- **200** — logtest executed (check inner status fields).
- **400** — missing/invalid fields or integration not found.
- **500** — Engine socket communication error or internal error.

---

### Normalization only

Sends a log event to the Wazuh Engine for decoding and normalization without performing Sigma rule detection. Use this to validate that decoders correctly parse events before testing detection rules.

> **Note**: A testing policy must be loaded in the Engine for normalization to execute successfully.

#### Request

- Method: `POST`
- Path: `/_plugins/_content_manager/logtest/normalization`

#### Request body

- **`space`** (String, required) — `"test"` or `"standard"`.
- **`queue`** (Integer, optional) — queue number for logtest execution.
- **`location`** (String, optional) — log file path or logical source location.
- **`event`** (String, optional) — raw log event to normalize.
- **`metadata`** (Object, optional) — optional metadata passed to the Engine.
- **`trace_level`** (String, optional) — trace verbosity: `NONE`, `ASSET_ONLY`, or `ALL`.

#### Example request

```bash
curl -sk -u admin:admin -X POST \
  "https://127.0.0.1:9200/_plugins/_content_manager/logtest/normalization" \
  -H 'Content-Type: application/json' \
  -d '{
    "space": "test",
    "queue": 1,
    "location": "/var/log/cassandra/system.log",
    "metadata": {},
    "trace_level": "NONE",
    "event": "INFO  [CompactionExecutor-3] 2025-11-30 14:23:45 CassandraDaemon.java:250 - Some message - 7500 - 4"
  }'
```

#### Example response

```json
{
  "status": 200,
  "message": {
    "output": {
      "log": {
        "level": "INFO",
        "origin": {
          "file": {
            "name": "CassandraDaemon.java",
            "line": 250
          }
        }
      },
      "wazuh": {
        "space": { "name": "test" },
        "protocol": { "location": "/var/log/cassandra/system.log", "queue": 1 },
        "integration": {
          "decoders": ["decoder/cassandra-default/0"],
          "name": "my-integration",
          "category": "other"
        }
      },
      "message": "Some message",
      "event": {
        "duration": 7500,
        "category": ["database"],
        "kind": "event",
        "severity": 4
      },
      "source": { "ip": "10.42.3.15" },
      "process": {
        "thread": { "name": "CompactionExecutor-3" }
      }
    },
    "asset_traces": [],
    "validation": {
      "valid": true,
      "errors": []
    }
  }
}
```

#### Response fields

- **`message.output`** (Object) — Engine normalized event output.
- **`message.asset_traces`** (Array) — list of decoders that processed the event.
- **`message.validation`** (Object) — validation result (`valid`, `errors`).

#### Status codes

- **200** — normalization executed successfully.
- **400** — missing/invalid fields.
- **500** — Engine socket communication error or internal error.

---

### Detection only

Evaluates an already-normalized event against the Sigma rules of a given integration via the Security Analytics plugin. This endpoint does **not** call the Wazuh Engine — the normalized event must be provided directly in the `input` field.

Use this after obtaining a normalized event from the `/logtest/normalization` endpoint, or when you already have a normalized event and want to test different integrations' rules against it.

> **Note**: The integration must exist in the specified space. The `input` field must be a JSON object (the normalized event), not a raw log string.

#### Request

- Method: `POST`
- Path: `/_plugins/_content_manager/logtest/detection`

#### Request body

- **`space`** (String, required) — `"test"` or `"standard"`.
- **`integration`** (String, required) — UUID of the integration whose rules to evaluate.
- **`input`** (Object, required) — normalized event object to evaluate rules against.

#### Example request

```bash
curl -sk -u admin:admin -X POST \
  "https://127.0.0.1:9200/_plugins/_content_manager/logtest/detection" \
  -H 'Content-Type: application/json' \
  -d '{
    "space": "test",
    "integration": "d3f3b0b8-4e25-4273-83ef-56a62003bcf7",
    "input": {
      "event": {
        "duration": 7500,
        "category": ["database"],
        "kind": "event",
        "severity": 4,
        "type": ["info"]
      },
      "source": { "ip": "10.42.3.15" },
      "process": {
        "thread": { "name": "CompactionExecutor-3" },
        "command_line": "/query tables"
      },
      "log": {
        "origin": {
          "file": { "name": "CassandraDaemon.java", "line": 250 }
        }
      }
    }
  }'
```

#### Example response (matches found)

```json
{
  "status": 200,
  "message": {
    "status": "success",
    "rules_evaluated": 12,
    "rules_matched": 6,
    "matches": [
      {
        "rule": {
          "id": "4e52f215-bccc-4c0f-a37c-70606022be8e",
          "title": "TEST: Numeric gte+lt only",
          "level": "high",
          "tags": ["attack.execution", "attack.t1059"]
        },
        "matched_conditions": [
          "event.duration matched '>= 5000'",
          "event.severity matched '< 10'"
        ]
      },
      {
        "rule": {
          "id": "1d489ded-7523-4329-8cd0-ebb21865a318",
          "title": "TEST: Exact match event.kind=event",
          "level": "low",
          "tags": ["attack.execution", "attack.t1059"]
        },
        "matched_conditions": [
          "event.kind matched 'event'"
        ]
      }
    ]
  }
}
```

#### Example response (no rules in integration)

```json
{
  "status": 200,
  "message": {
    "status": "success",
    "rules_evaluated": 0,
    "rules_matched": 0,
    "matches": []
  }
}
```

#### Response fields

- **`message.status`** (String) — `"success"` or `"error"`.
- **`message.rules_evaluated`** (Integer) — number of Sigma rules evaluated.
- **`message.rules_matched`** (Integer) — number of rules that matched.
- **`message.matches`** (Array) — list of matched rules with details.
- **`message.matches[].rule`** (Object) — rule metadata: `id`, `title`, `level`, `tags`.
- **`message.matches[].matched_conditions`** (Array) — human-readable descriptions of matched conditions.

#### Status codes

- **200** — detection executed (check `message.status`).
- **400** — missing/invalid fields or integration not found.
- **500** — internal error.

---

## Policy

### Update policy

Updates the routing policy in the specified space. The policy defines which integrations are active, the root decoder, enrichment types, and how events are routed through the Engine.

> **Note**: The `integrations` and `filters` arrays allow reordering but do not allow adding or removing entries — membership is managed via their respective CRUD endpoints.

**Space-specific behavior**

- **Draft space** (`/policy/draft`): all policy fields are accepted. The metadata fields `author`, `description`, `documentation`, and `references` are required in addition to the boolean fields.
- **Standard space** (`/policy/standard`): only `enrichments`, `filters`, `enabled`, `index_unclassified_events`, and `index_discarded_events` can be modified. All other fields are preserved from the existing standard policy document. If the update changes the space hash, the full standard policy is automatically loaded to the local Engine.

#### Request

- Method: `PUT`
- Path: `/_plugins/_content_manager/policy/{space}`

#### Path parameters

- **`space`** (String, required) — target space (`draft` or `standard`).

#### Request body

- **`resource`** (Object, required) — the policy resource object.

Fields within `resource`:

- **`metadata`** (Object, required in draft) — policy metadata (see below).
- **`root_decoder`** (String, optional) — identifier of the root decoder for event processing.
- **`integrations`** (Array, optional) — list of integration IDs (reorder only, no add/remove).
- **`filters`** (Array, optional) — list of filter UUIDs (reorder only, no add/remove).
- **`enrichments`** (Array, optional) — enrichment types (no duplicates; values depend on engine capabilities).
- **`enabled`** (Boolean, required) — whether the policy is active and synchronized by the Engine.
- **`index_unclassified_events`** (Boolean, required) — whether uncategorized events are indexed.
- **`index_discarded_events`** (Boolean, required) — whether discarded events are indexed.

Fields within `resource.metadata`:

- **`title`** (String, optional) — human-readable policy name.
- **`author`** (String, required in draft) — author of the policy.
- **`description`** (String, required in draft) — brief description.
- **`documentation`** (String, required in draft) — documentation text or URL.
- **`references`** (Array, required in draft) — external reference URLs.

#### Example request (draft space)

```bash
curl -sk -u admin:admin -X PUT \
  "https://127.0.0.1:9200/_plugins/_content_manager/policy/draft" \
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

#### Example request (standard space)

```bash
curl -sk -u admin:admin -X PUT \
  "https://127.0.0.1:9200/_plugins/_content_manager/policy/standard" \
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

#### Example response

```json
{
  "message": "kQPmV5wBi_TgruUn97RT",
  "status": 200
}
```

The `message` field contains the OpenSearch document ID of the updated policy.

#### Status codes

- **200** — policy updated.
- **400** — invalid space, missing `resource` field, missing required fields, invalid enrichments, or disallowed modification of `integrations`/`filters`.
- **500** — internal error.

---

## Rules

Rules follow the Sigma format with Wazuh extensions. See [Sigma Rules](../security-analytics/rules.md) for the full format reference, including the `mitre`, `compliance`, and `metadata` blocks.

> **Validation notes**:
> - The `logsource.product` field must exactly match the `metadata.title` of the parent integration.
> - Detection fields are validated against the Wazuh Common Schema (WCS); rules referencing unknown fields are rejected. A field used in a check or detection expression that is *not* part of WCS must be prefixed with an underscore to mark it as temporary (see [Troubleshooting](troubleshooting.md#engine-validation-rejects-a-temporary-field)) — otherwise the Engine rejects the resource.
> - IPv6 addresses are supported in detection conditions (standard, compressed, and CIDR notation).

### Create rule

Creates a new detection rule in the draft space. The rule is linked to the specified parent integration and validated by the Security Analytics plugin.

The rule is also synchronized to Security Analytics, where a separate document is created with its own auto-generated UUID. That document stores the CTI document UUID in a `document.id` field and the space in a `source` field (e.g., "Draft") for cross-reference.

#### Request

- Method: `POST`
- Path: `/_plugins/_content_manager/rules`

#### Request body

- **`integration`** (String, required) — UUID of the parent integration (must be in draft space).
- **`resource`** (Object, required) — the rule definition.

Fields within `resource`:

- **`metadata`** (Object, required) — rule metadata (see below).
- **`sigma_id`** (String, optional) — Sigma rule ID.
- **`enabled`** (Boolean, optional) — whether the rule is enabled.
- **`status`** (String, optional) — rule status (e.g., `experimental`, `stable`).
- **`level`** (String, optional) — alert level (e.g., `low`, `medium`, `high`, `critical`).
- **`logsource`** (Object, optional) — log source definition (`product`, `category`).
- **`detection`** (Object, optional) — Sigma detection logic with `condition` and selection fields.
- **`mitre`** (Object, optional) — MITRE ATT&CK mapping (see [Sigma Rules](../security-analytics/rules.md#mitre-attck)).
- **`compliance`** (Object, optional) — compliance framework mapping (see [Sigma Rules](../security-analytics/rules.md#compliance)).

Fields within `resource.metadata`:

- **`title`** (String, required) — rule title (must be unique within the draft space).
- **`author`** (String, optional) — rule author.
- **`description`** (String, optional) — rule description.
- **`references`** (Array, optional) — reference URLs.
- **`documentation`** (String, optional) — documentation text or URL.

#### Example request

```bash
curl -sk -u admin:admin -X POST \
  "https://127.0.0.1:9200/_plugins/_content_manager/rules" \
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

#### Example response

```json
{
  "message": "6e1c43f1-f09b-4cec-bb59-00e3a52b7930",
  "status": 201
}
```

The `message` field contains the UUID of the created rule.

#### Status codes

- **201** — rule created.
- **400** — missing fields, duplicate title, integration not in draft space, or validation failure.
- **500** — internal error or Security Analytics unavailable.

---

### Update rule

Updates an existing rule in the draft space. Unlike on create, `detection` and `logsource` are required on update, in addition to `metadata`.

#### Request

- Method: `PUT`
- Path: `/_plugins/_content_manager/rules/{id}`

#### Parameters

- **`id`** (Path, String/UUID, required) — rule document ID.

#### Request body

- **`resource`** (Object, required) — updated rule definition (same fields as create).

#### Example request

```bash
curl -sk -u admin:admin -X PUT \
  "https://127.0.0.1:9200/_plugins/_content_manager/rules/6e1c43f1-f09b-4cec-bb59-00e3a52b7930" \
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

#### Example response

```json
{
  "message": "6e1c43f1-f09b-4cec-bb59-00e3a52b7930",
  "status": 200
}
```

#### Status codes

- **200** — rule updated.
- **400** — invalid request, not in draft space, or validation failure.
- **404** — rule not found.
- **500** — internal error.

---

### Delete rule

Deletes a rule from the draft space. The rule is also removed from any integrations that reference it.

#### Request

- Method: `DELETE`
- Path: `/_plugins/_content_manager/rules/{id}`

#### Parameters

- **`id`** (Path, String/UUID, required) — rule document ID.

#### Example request

```bash
curl -sk -u admin:admin -X DELETE \
  "https://127.0.0.1:9200/_plugins/_content_manager/rules/6e1c43f1-f09b-4cec-bb59-00e3a52b7930"
```

#### Example response

```json
{
  "message": "6e1c43f1-f09b-4cec-bb59-00e3a52b7930",
  "status": 200
}
```

#### Status codes

- **200** — rule deleted.
- **404** — rule not found.
- **500** — internal error.

---

## Decoders

### Create decoder

Creates a new log decoder in the draft space. The decoder is validated against the Wazuh Engine before being stored, and automatically linked to the specified integration.

> **Note**: A testing policy must be loaded in the Engine for decoder validation to succeed.

#### Request

- Method: `POST`
- Path: `/_plugins/_content_manager/decoders`

#### Request body

- **`integration`** (String, required) — UUID of the parent integration (must be in draft space).
- **`resource`** (Object, required) — the decoder definition.

Fields within `resource`:

- **`name`** (String) — decoder name identifier (e.g., `decoder/core-wazuh-message/0`).
- **`enabled`** (Boolean) — whether the decoder is enabled.
- **`check`** (Array) — decoder check logic — array of condition objects. Fields referenced here that aren't part of WCS must be prefixed with an underscore (see the validation note under [Rules](#rules)).
- **`normalize`** (Array) — normalization rules — array of mapping objects.
- **`metadata`** (Object) — decoder metadata (see below).

Fields within `metadata`:

- **`title`** (String) — human-readable decoder title.
- **`description`** (String) — decoder description.
- **`module`** (String) — module name.
- **`compatibility`** (String) — compatibility description.
- **`author`** (String) — author name, stored as a keyword.
- **`references`** (Array) — reference URLs.
- **`versions`** (Array) — supported versions.

#### Example request

```bash
curl -sk -u admin:admin -X POST \
  "https://127.0.0.1:9200/_plugins/_content_manager/decoders" \
  -H 'Content-Type: application/json' \
  -d '{
    "integration": "0aa4fc6f-1cfd-4a7c-b30b-643f32950f1f",
    "resource": {
      "enabled": true,
      "metadata": {
        "author": "Wazuh, Inc.",
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
          "_tmp_json.event.action": "string_equal(\"netflow_flow\")"
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

#### Example response

```json
{
  "message": "d_0a6aaebe-dd0b-44cc-a787-ffefd4aac175",
  "status": 201
}
```

The `message` field contains the UUID of the created decoder (prefixed with `d_`).

#### Example request (YAML)

```bash
curl -sk -u admin:admin -X POST \
  "https://127.0.0.1:9200/_plugins/_content_manager/decoders" \
  -H 'Content-Type: application/yaml' \
  --data-binary '---
integration: 0aa4fc6f-1cfd-4a7c-b30b-643f32950f1f
resource:
  enabled: true
  metadata:
    author: "Wazuh, Inc."
    compatibility: "All wazuh events."
    description: "Base decoder to process Wazuh message format."
    module: wazuh
    references:
      - "https://documentation.wazuh.com/"
    title: "Wazuh message decoder"
    versions:
      - "Wazuh 5.*"
  name: decoder/core-wazuh-message/0
  check:
    - _tmp_json.event.action: "string_equal(\"netflow_flow\")"
  normalize:
    - map:
        - "@timestamp": "get_date()"
'
```

> **Note**: See [YAML content-type support](#yaml-content-type-support) for details on the YAML envelope format and type fidelity.

#### Status codes

- **201** — decoder created.
- **400** — missing `integration` field, integration not in draft space, or Engine validation failure (see [Troubleshooting](troubleshooting.md#engine-validation-rejects-a-temporary-field) if the failure mentions an unrecognized WCS field).
- **500** — Engine unavailable or internal error.

---

### Update decoder

Updates an existing decoder in the draft space. The decoder is re-validated against the Wazuh Engine.

#### Request

- Method: `PUT`
- Path: `/_plugins/_content_manager/decoders/{id}`

#### Parameters

- **`id`** (Path, String, required) — decoder document ID.

#### Request body

- **`resource`** (Object, required) — updated decoder definition (same fields as create).

#### Example request

```bash
curl -sk -u admin:admin -X PUT \
  "https://127.0.0.1:9200/_plugins/_content_manager/decoders/bb6d0245-8c1d-42d1-8edb-4e0907cf45e0" \
  -H 'Content-Type: application/json' \
  -d '{
    "resource": {
      "name": "decoder/test-decoder/0",
      "enabled": false,
      "metadata": {
        "title": "Test Decoder UPDATED",
        "description": "Updated description",
        "author": "Hello there"
      },
      "check": [],
      "normalize": []
    }
  }'
```

#### Example response

```json
{
  "message": "bb6d0245-8c1d-42d1-8edb-4e0907cf45e0",
  "status": 200
}
```

#### Status codes

- **200** — decoder updated.
- **400** — invalid request, not in draft space, or Engine validation failure.
- **404** — decoder not found.
- **500** — internal error.

---

### Delete decoder

Deletes a decoder from the draft space. The decoder is also removed from any integrations that reference it. A decoder cannot be deleted if it is currently set as the root decoder in the draft policy.

#### Request

- Method: `DELETE`
- Path: `/_plugins/_content_manager/decoders/{id}`

#### Parameters

- **`id`** (Path, String/UUID, required) — decoder document ID.

#### Example request

```bash
curl -sk -u admin:admin -X DELETE \
  "https://127.0.0.1:9200/_plugins/_content_manager/decoders/acbdba85-09c4-45a0-a487-61c8eeec58e6"
```

#### Example response

```json
{
  "message": "acbdba85-09c4-45a0-a487-61c8eeec58e6",
  "status": 200
}
```

#### Example response (set as root decoder)

```json
{
  "message": "Cannot remove decoder [acbdba85-09c4-45a0-a487-61c8eeec58e6] as it is set as root decoder.",
  "status": 400
}
```

#### Status codes

- **200** — decoder deleted.
- **400** — decoder is set as root decoder.
- **404** — decoder not found.
- **500** — internal error.

---

## Filters

### Create filter

Creates a new filter in the draft or standard space. The filter is validated against the Wazuh Engine before being stored and automatically linked to the specified space's policy.

#### Request

- Method: `POST`
- Path: `/_plugins/_content_manager/filters`

#### Request body

- **`space`** (String, required) — target space: `draft` or `standard`.
- **`resource`** (Object, required) — the filter definition.

Fields within `resource`:

- **`name`** (String) — filter name identifier (e.g., `filter/prefilter/0`).
- **`enabled`** (Boolean) — whether the filter is enabled.
- **`check`** (String) — filter check expression.
- **`type`** (String) — filter type (e.g., `pre-filter`).
- **`metadata`** (Object) — filter metadata (see below).

Fields within `metadata`:

- **`description`** (String) — filter description.
- **`author`** (String) — author name, stored as a keyword.

#### Example request

```bash
curl -sk -u admin:admin -X POST \
  "https://127.0.0.1:9200/_plugins/_content_manager/filters" \
  -H 'Content-Type: application/json' \
  -d '{
    "space": "draft",
    "resource": {
      "name": "filter/prefilter/0",
      "enabled": true,
      "metadata": {
        "description": "Default filter to allow all events (for default ruleset)",
        "author": "Wazuh, Inc."
      },
      "check": "$host.os.platform == '\''ubuntu'\''",
      "type": "pre-filter"
    }
  }'
```

#### Example response

```json
{
  "message": "f_a1b2c3d4-e5f6-47a8-b9c0-d1e2f3a4b5c6",
  "status": 201
}
```

The `message` field contains the UUID of the created filter (prefixed with `f_`).

#### Example request (YAML)

```bash
curl -sk -u admin:admin -X POST \
  "https://127.0.0.1:9200/_plugins/_content_manager/filters" \
  -H 'Content-Type: application/yaml' \
  --data-binary '---
space: draft
resource:
  name: filter/prefilter/0
  enabled: true
  metadata:
    description: "Default filter to allow all events (for default ruleset)"
    author: "Wazuh, Inc."
  check: "$host.os.platform == '\''ubuntu'\''"
  type: pre-filter
'
```

> **Note**: See [YAML content-type support](#yaml-content-type-support) for details on the YAML envelope format and type fidelity.

#### Status codes

- **201** — filter created.
- **400** — missing `space` field, invalid space, or Engine validation failure.
- **500** — Engine unavailable or internal error.

---

### Update filter

Updates an existing filter in the draft or standard space. The filter is re-validated against the Wazuh Engine.

#### Request

- Method: `PUT`
- Path: `/_plugins/_content_manager/filters/{id}`

#### Parameters

- **`id`** (Path, String/UUID, required) — filter document ID.

#### Request body

- **`space`** (String, required) — target space: `draft` or `standard`.
- **`resource`** (Object, required) — updated filter definition (same fields as create).

#### Example request

```bash
curl -sk -u admin:admin -X PUT \
  "https://127.0.0.1:9200/_plugins/_content_manager/filters/a1b2c3d4-e5f6-47a8-b9c0-d1e2f3a4b5c6" \
  -H 'Content-Type: application/json' \
  -d '{
    "space": "draft",
    "resource": {
      "name": "filter/prefilter/0",
      "enabled": true,
      "metadata": {
        "description": "Updated filter description",
        "author": "Wazuh, Inc."
      },
      "check": "$host.os.platform == '\''ubuntu'\''",
      "type": "pre-filter"
    }
  }'
```

#### Example response

```json
{
  "message": "a1b2c3d4-e5f6-47a8-b9c0-d1e2f3a4b5c6",
  "status": 200
}
```

#### Status codes

- **200** — filter updated.
- **400** — invalid request, invalid space, or Engine validation failure.
- **404** — filter not found.
- **500** — internal error.

---

### Delete filter

Deletes a filter from the draft or standard space. The filter is also removed from the associated policy.

#### Request

- Method: `DELETE`
- Path: `/_plugins/_content_manager/filters/{id}`

#### Parameters

- **`id`** (Path, String/UUID, required) — filter document ID.

#### Example request

```bash
curl -sk -u admin:admin -X DELETE \
  "https://127.0.0.1:9200/_plugins/_content_manager/filters/a1b2c3d4-e5f6-47a8-b9c0-d1e2f3a4b5c6"
```

#### Example response

```json
{
  "message": "a1b2c3d4-e5f6-47a8-b9c0-d1e2f3a4b5c6",
  "status": 200
}
```

#### Status codes

- **200** — filter deleted.
- **404** — filter not found.
- **500** — internal error.

---

## Integrations

### Create integration

Creates a new integration in the draft space. An integration is a logical grouping of related rules, decoders, and KVDBs. The integration is validated against the Engine and registered with the Security Analytics plugin.

The integration is also synchronized to Security Analytics, where a separate document is created with its own auto-generated UUID. That document stores the CTI document UUID in a `document.id` field and the space in a `source` field (e.g., "Draft") for cross-reference.

#### Request

- Method: `POST`
- Path: `/_plugins/_content_manager/integrations`

#### Request body

- **`resource`** (Object, required) — the integration definition.

Fields within `resource`:

- **`metadata`** (Object, required) — integration metadata (see below).
- **`category`** (String, required) — category (e.g., `cloud-services`, `network-activity`, `security`, `system-activity`).
- **`enabled`** (Boolean, optional) — whether the integration is enabled.

Fields within `resource.metadata`:

- **`title`** (String, required) — integration title (must be unique in draft space).
- **`author`** (String, required) — author of the integration.
- **`description`** (String, optional) — description.
- **`documentation`** (String, optional) — documentation text or URL.
- **`references`** (Array, optional) — reference URLs.

> **Note**: Do not include the `id` field — it is auto-generated by the Indexer.

#### Example request

```bash
curl -sk -u admin:admin -X POST \
  "https://127.0.0.1:9200/_plugins/_content_manager/integrations" \
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

#### Example response

```json
{
  "message": "94e5a2af-505e-4164-ab62-576a71873308",
  "status": 201
}
```

The `message` field contains the UUID of the created integration.

#### Status codes

- **201** — integration created.
- **400** — missing required fields (`title`, `author`, `category`), duplicate title, or validation failure.
- **500** — internal error or Security Analytics/Engine unavailable.

---

### Update integration

Updates an existing integration in the draft space. Only integrations in the draft space can be updated. All fields within `resource` are required on update, including `rules`, `decoders`, and `kvdbs`, to allow reordering — pass empty arrays `[]` if the integration has none.

#### Request

- Method: `PUT`
- Path: `/_plugins/_content_manager/integrations/{id}`

#### Parameters

- **`id`** (Path, String/UUID, required) — integration document ID.

#### Request body

- **`resource`** (Object, required) — updated integration definition.

Fields within `resource` (all required for update):

- **`metadata`** (Object) — integration metadata (see below).
- **`category`** (String) — category.
- **`enabled`** (Boolean) — whether the integration is enabled.
- **`rules`** (Array) — ordered list of rule IDs.
- **`decoders`** (Array) — ordered list of decoder IDs.
- **`kvdbs`** (Array) — ordered list of KVDB IDs.

Fields within `resource.metadata` (all required for update):

- **`title`** (String) — integration title.
- **`author`** (String) — author.
- **`description`** (String) — description.
- **`documentation`** (String) — documentation text or URL.
- **`references`** (Array) — reference URLs.

#### Example request

```bash
curl -sk -u admin:admin -X PUT \
  "https://127.0.0.1:9200/_plugins/_content_manager/integrations/94e5a2af-505e-4164-ab62-576a71873308" \
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

#### Example response

```json
{
  "message": "94e5a2af-505e-4164-ab62-576a71873308",
  "status": 200
}
```

#### Status codes

- **200** — integration updated.
- **400** — invalid request, missing required fields, not in draft space, or duplicate title.
- **404** — integration not found.
- **500** — internal error.

---

### Delete integration

Deletes an integration from the draft space. The integration must have no attached decoders, rules, or KVDBs — delete those first.

#### Request

- Method: `DELETE`
- Path: `/_plugins/_content_manager/integrations/{id}`

#### Parameters

- **`id`** (Path, String/UUID, required) — integration document ID.

#### Example request

```bash
curl -sk -u admin:admin -X DELETE \
  "https://127.0.0.1:9200/_plugins/_content_manager/integrations/94e5a2af-505e-4164-ab62-576a71873308"
```

#### Example response

```json
{
  "message": "94e5a2af-505e-4164-ab62-576a71873308",
  "status": 200
}
```

#### Example response (has dependencies)

```json
{
  "message": "Cannot delete integration because it has decoders attached",
  "status": 400
}
```

#### Status codes

- **200** — integration deleted.
- **400** — integration has dependent resources (decoders/rules/kvdbs).
- **404** — integration not found.
- **500** — internal error.

---

## KVDBs

### Create KVDB

Creates a new key-value database in the draft space, linked to the specified integration.

#### Request

- Method: `POST`
- Path: `/_plugins/_content_manager/kvdbs`

#### Request body

- **`integration`** (String, required) — UUID of the parent integration (must be in draft space).
- **`resource`** (Object, required) — the KVDB definition.

Fields within `resource`:

- **`metadata`** (Object, required) — KVDB metadata (see below).
- **`content`** (Object, required) — key-value data (at least one entry required).
- **`name`** (String, optional) — KVDB identifier name.
- **`enabled`** (Boolean, optional) — whether the KVDB is enabled.

Fields within `resource.metadata`:

- **`title`** (String, required) — KVDB title.
- **`author`** (String, required) — author.
- **`description`** (String, optional) — description.
- **`documentation`** (String, optional) — documentation.
- **`references`** (Array, optional) — reference URLs.

#### Example request

```bash
curl -sk -u admin:admin -X POST \
  "https://127.0.0.1:9200/_plugins/_content_manager/kvdbs" \
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

#### Example response

```json
{
  "message": "9d4ec6d5-8e30-4ea3-be05-957968c02dae",
  "status": 201
}
```

The `message` field contains the UUID of the created KVDB.

#### Example request (YAML)

```bash
curl -sk -u admin:admin -X POST \
  "https://127.0.0.1:9200/_plugins/_content_manager/kvdbs" \
  -H 'Content-Type: application/yaml' \
  --data-binary '---
integration: f16f33ec-a5ea-4dc4-bf33-616b1562323a
resource:
  metadata:
    title: non_standard_timezones
    author: "Wazuh Inc."
    description: ""
    documentation: ""
    references:
      - "https://wazuh.com"
  name: non_standard_timezones
  enabled: true
  content:
    non_standard_timezones:
      AEST: Australia/Sydney
      CEST: Europe/Berlin
      CST: America/Chicago
      EDT: America/New_York
      EST: America/New_York
      IST: Asia/Kolkata
      MST: America/Denver
      PKT: Asia/Karachi
      SST: Asia/Singapore
      WEST: Europe/London
'
```

> **Note**: See [YAML content-type support](#yaml-content-type-support) for details on the YAML envelope format and type fidelity.

#### Status codes

- **201** — KVDB created.
- **400** — missing `integration` or required resource fields, integration not in draft space.
- **500** — internal error.

---

### Update KVDB

Updates an existing KVDB in the draft space. All fields within `resource` are required on update.

#### Request

- Method: `PUT`
- Path: `/_plugins/_content_manager/kvdbs/{id}`

#### Parameters

- **`id`** (Path, String/UUID, required) — KVDB document ID.

#### Request body

- **`resource`** (Object, required) — updated KVDB definition.

Fields within `resource` (all required for update):

- **`metadata`** (Object) — KVDB metadata (see below).
- **`content`** (Object) — key-value data.
- **`name`** (String) — KVDB identifier name.
- **`enabled`** (Boolean) — whether the KVDB is enabled.

Fields within `resource.metadata` (all required for update):

- **`title`** (String) — KVDB title.
- **`author`** (String) — author.
- **`description`** (String) — description.
- **`documentation`** (String) — documentation.
- **`references`** (Array) — reference URLs.

#### Example request

```bash
curl -sk -u admin:admin -X PUT \
  "https://127.0.0.1:9200/_plugins/_content_manager/kvdbs/9d4ec6d5-8e30-4ea3-be05-957968c02dae" \
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

#### Example response

```json
{
  "message": "9d4ec6d5-8e30-4ea3-be05-957968c02dae",
  "status": 200
}
```

#### Status codes

- **200** — KVDB updated.
- **400** — invalid request, missing required fields, or not in draft space.
- **404** — KVDB not found.
- **500** — internal error.

---

### Delete KVDB

Deletes a KVDB from the draft space. The KVDB is also removed from any integrations that reference it.

#### Request

- Method: `DELETE`
- Path: `/_plugins/_content_manager/kvdbs/{id}`

#### Parameters

- **`id`** (Path, String/UUID, required) — KVDB document ID.

#### Example request

```bash
curl -sk -u admin:admin -X DELETE \
  "https://127.0.0.1:9200/_plugins/_content_manager/kvdbs/9d4ec6d5-8e30-4ea3-be05-957968c02dae"
```

#### Example response

```json
{
  "message": "9d4ec6d5-8e30-4ea3-be05-957968c02dae",
  "status": 200
}
```

#### Status codes

- **200** — KVDB deleted.
- **404** — KVDB not found.
- **500** — internal error.

---

## Promotion

### Preview promotion changes

Returns a preview of changes that would be applied when promoting from the specified space. This is a dry-run operation that does not modify any content.

#### Request

- Method: `GET`
- Path: `/_plugins/_content_manager/promote`

#### Parameters

- **`space`** (Query, String, required) — source space to preview: `draft` or `test`.

#### Example request

```bash
curl -sk -u admin:admin \
  "https://127.0.0.1:9200/_plugins/_content_manager/promote?space=draft"
```

#### Example response

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
- `operation`: `add`, `update`, or `remove`.
- `id`: document ID of the affected resource.

#### Status codes

- **200** — preview returned successfully.
- **400** — invalid or missing `space` parameter.
- **500** — internal error.

---

### Execute promotion

Promotes content from the source space to the next space in the promotion chain (Draft → Test → Custom). The request body must include the source space and the changes to apply (typically obtained from the preview endpoint).

For Draft → Test promotions, the changeset is forwarded to the local Wazuh Engine for validation only when it includes decoders, kvdbs, or filters. Promotions limited to integrations, rules, or the policy skip the engine call entirely. Test → Custom promotions never invoke the engine.

In addition to copying documents across CTI indices, promotion also synchronizes **integrations** and **rules** with the Security Analytics plugin. For each promoted resource, a new document is created in the target space with:
- A newly generated UUID as the primary ID.
- A `document.id` field storing the original CTI document UUID for cross-reference.
- A `source` field indicating the target space (e.g., "Test", "Custom").

New resources (add operations) use `POST` to create these documents; existing resources (update operations) use `PUT` to update them in-place.

This ensures that the same CTI resource can exist in multiple spaces with independent Security Analytics documents.

#### Rollback on failure

If any Content Manager index mutation fails during the consolidation phase, the endpoint automatically performs a **LIFO rollback** to restore the system to its pre-promotion state:

1. **Pre-promotion snapshots** are captured before any writes — old versions for adds/updates, full documents for deletes.
2. **Content Manager rollback**: each completed mutation is undone in reverse order. Adds are deleted, updates are restored to their previous version, deletes are re-indexed from the snapshot.
3. **Security Analytics reconciliation** (best-effort): rules and integrations synced during the forward pass are reverted — new documents are deleted, updated ones are restored, and deleted ones are re-created from snapshots.

Individual rollback or reconciliation step failures are logged but do not prevent remaining steps from executing. On rollback, the endpoint returns a `500` status.

#### Request

- Method: `POST`
- Path: `/_plugins/_content_manager/promote`

#### Request body

- **`space`** (String, required) — source space: `draft` or `test`.
- **`changes`** (Object, required) — changes to promote (from the preview response).

The `changes` object contains arrays for each content type (`policy`, `integrations`, `kvdbs`, `decoders`, `rules`, `filters`), each with `operation` and `id` fields.

#### Example request

```bash
curl -sk -u admin:admin -X POST \
  "https://127.0.0.1:9200/_plugins/_content_manager/promote" \
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

#### Example response

```json
{
  "message": "Promotion completed successfully",
  "status": 200
}
```

#### Status codes

- **200** — promotion successful.
- **400** — invalid request body or missing `space` field.
- **500** — Engine communication error or validation failure.

---

## Spaces

### Reset space

Resets a user space (`draft`) to its initial state.

When resetting the `draft` space, this operation will:
- Remove all documents (integrations, rules, decoders, kvdbs) that belong to the given space.
- Re-generate the default policy for the given space.

> **Note**: Only the `draft` space can be reset.

#### Request

- Method: `DELETE`
- Path: `/_plugins/_content_manager/space/{space}`

#### Parameters

- **`space`** (Path, String, required) — the name of the user space to reset (`draft`).

#### Example request

```bash
curl -sk -u admin:admin -X DELETE \
  "https://127.0.0.1:9200/_plugins/_content_manager/space/draft"
```

#### Example response

```json
{
  "message": "Space reset successfully",
  "status": 200
}
```

#### Status codes

- **200** — space reset successfully.
- **400** — invalid space identifier, or attempted to reset a space different from `draft`.
- **500** — internal error (e.g., Engine unavailable or deletion failure).

---

## Version check

### Check available updates

Returns whether there are newer versions of Wazuh available for download. The endpoint reads the current installed version from `VERSION.json` and queries the CTI API for available updates. The response includes the latest available major, minor, and patch updates when available.

#### Request

- Method: `GET`
- Path: `/_plugins/_content_manager/version/check`

#### Example request

```bash
curl -sk -u admin:admin \
  "https://127.0.0.1:9200/_plugins/_content_manager/version/check"
```

#### Example response (updates available)

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

#### Example response (no updates)

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

#### Example response (version not found)

```json
{
  "message": "Unable to determine current Wazuh version.",
  "status": 500
}
```

#### Status codes

- **200** — version check completed (may include updates or empty).
- **500** — unable to determine version or internal error.
- **502** — CTI API returned an error.

> **Note**: Categories with no available updates are represented as empty objects `{}`.

---

## Documentation maintenance

To maintain technical consistency, any modification, addition or removal of endpoints in the REST API source code must be reflected in the `openapi.yml` specification and this `api.md` reference guide.
