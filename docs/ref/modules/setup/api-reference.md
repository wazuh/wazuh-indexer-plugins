# API reference

The Setup plugin exposes a REST API under `/_plugins/_setup/`. All endpoints require authentication.

---

## Settings

### Update settings

Persists configuration settings to the `.wazuh-settings` index. Currently, it supports the `engine.index_raw_events` boolean flag, which controls whether the Engine indexes raw events into the `wazuh-events-raw-v5` data stream.

#### Request

- Method: `PUT`
- Path: `/_plugins/_setup/settings`

#### Request body

- **`engine`** (Object, required) — Engine settings object.
- **`engine.index_raw_events`** (Boolean, required) — whether the Engine indexes raw events into the `wazuh-events-raw-v5` data stream.

#### Example request

```bash
curl -sk -u admin:admin -X PUT \
  "https://127.0.0.1:9200/_plugins/_setup/settings" \
  -H 'Content-Type: application/json' \
  -d '{
    "engine": {
      "index_raw_events": true
    }
  }'
```

#### Example response (success)

```json
{
  "message": "Settings updated successfully.",
  "status": 200
}
```

#### Example response (missing field)

```json
{
  "message": "Missing required field: 'engine.index_raw_events'.",
  "status": 400
}
```

#### Example response (invalid type)

```json
{
  "message": "Field 'engine.index_raw_events' must be of type boolean.",
  "status": 400
}
```

#### Status codes

- **200** — settings updated successfully.
- **400** — invalid request body, missing required fields, or wrong field type.
- **500** — internal server error (e.g., failed to persist settings to the index).

---

> **Documentation maintenance** — modifications to the REST API must be reflected in both `openapi.yml` and this file.
