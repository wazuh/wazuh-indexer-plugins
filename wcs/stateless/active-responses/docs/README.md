## `wazuh-active-responses` index data model

### Fields summary

Stateless index recording the active responses triggered by matched alerts. Each document links back to the alert that fired it (`event.index`, `event.doc_id`), the active-response channel configuration (`wazuh.active_response.*`) and the full agent/cluster metadata carried under `wazuh.*` (mirrored from the base stateless template).

The detail of the fields can be found in the csv file [Fields](fields.csv).

### WCS fields — `wazuh.active_response`

| Field | Type | Description |
|-------|------|-------------|
| `wazuh.active_response.name` | keyword | Name of the active response configured in the channel. |
| `wazuh.active_response.type` | keyword | Response type. One of: `stateless`, `stateful`. |
| `wazuh.active_response.executable` | keyword | Executable configured in the active response channel. |
| `wazuh.active_response.extra_arguments` | keyword | Arguments configured in the active response channel. |
| `wazuh.active_response.location` | keyword | Where to execute. One of: `local`, `defined-agent`, `all`. |
| `wazuh.active_response.agent_id` | keyword | Agent configured in the active response channel. |
| `wazuh.active_response.stateful_timeout` | integer | Seconds configured in the channel (for stateful type). |

### Data stream

- **Index pattern:** `wazuh-active-responses*`
- **ISM policy:** `stream-active-responses-policy` — rolls over on size/doc count and deletes indices older than 3 days.
