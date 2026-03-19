# API Reference

The Setup plugin exposes a REST API under `/_plugins/_setup/`. All endpoints require authentication.

---

## Settings

### Update Settings

Persists configuration settings to the `.wazuh-settings` index. Currently supports the `engine.index_raw_events` boolean flag, which controls whether the Engine writes incoming events to the raw data stream before enrichment.

**Request**
- Method: `PUT`
- Path: `/_plugins/_setup/settings`

**Request Body**

| Field                      | Type    | Required | Description                                                                    |
| -------------------------- | ------- | -------- | ------------------------------------------------------------------------------ |
| `engine`                   | Object  | Yes      | Engine settings object                                                         |
| `engine.index_raw_events`  | Boolean | Yes      | Whether the Engine writes incoming events to the raw data stream before enrichment |

**Example Request**

```bash
curl -sk -u admin:admin -X PUT \
  "https://192.168.56.6:9200/_plugins/_setup/settings" \
  -H 'Content-Type: application/json' \
  -d '{
    "engine": {
      "index_raw_events": true
    }
  }'
```

**Example Response (success)**

```json
{
  "message": "Settings updated successfully.",
  "status": 200
}
```

**Example Response (missing field)**

```json
{
  "message": "Missing required field: 'engine.index_raw_events'.",
  "status": 400
}
```

**Example Response (invalid type)**

```json
{
  "message": "Field 'engine.index_raw_events' must be of type boolean.",
  "status": 400
}
```

**Status Codes**

| Code | Description                                                                 |
| ---- | --------------------------------------------------------------------------- |
| 200  | Settings updated successfully                                               |
| 400  | Invalid request body, missing required fields, or wrong field type          |
| 500  | Internal server error (e.g., failed to persist settings to the index)       |

---

> **Documentation Maintenance** — modifications to the REST API must be reflected in both `openapi.yml` and this file.
