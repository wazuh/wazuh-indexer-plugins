## `wazuh-active-responses` index data model

### Fields summary

Stateless index recording the active responses triggered by matched alerts. Each document links back to the alert that fired it (`event.index`, `event.doc_id`), the active-response channel configuration (`wazuh.active_response.*`) and the full agent/cluster metadata carried under `wazuh.*` (mirrored from the base stateless template).

> **Note:** This index is part of the active response feature and is shared by two components: the notifications plugin writes the active response execution requests into it, and the Wazuh manager reads them to dispatch the orders to the agents. Documents must therefore satisfy the requirements listed below for the manager to be able to process them.
> - https://github.com/wazuh/wazuh/tree/main/docs/ref/modules/active-response
> - https://github.com/wazuh/wazuh-dashboard-plugins/tree/main/docs/ref/modules/active-response

The detail of the fields can be found in the csv file [Fields](fields.csv).

### Fields and requirements

| Field | Type | Description | Requirement |
|-------|------|-------------|-------------|
| `@timestamp` | date | Date and time when the document was inserted into the `wazuh-active-responses` data stream. | Required, ISO 8601. The manager uses it for the cursor and for the deterministic task id. |
| `event.index` | keyword | Source index of the matched alert that triggered the active response. | Required, non-empty string. The manager `mget`s that document and merges it into the agent payload. |
| `event.doc_id` | keyword | Document ID of the matched alert that triggered the active response. | Required, non-empty string. The manager `mget`s that document and merges it into the agent payload. |
| `wazuh.active_response.name` | keyword | Name of the active response configured in the channel. | Required. |
| `wazuh.active_response.type` | keyword | Response type. | Required. One of `stateless`, `stateful`. |
| `wazuh.active_response.executable` | keyword | Executable configured in the active response channel. | Required. |
| `wazuh.active_response.extra_arguments` | keyword | Arguments configured in the active response channel. | Required. |
| `wazuh.active_response.location` | keyword | Where to execute. | Required. One of `local`, `defined-agent`, `all`. |
| `wazuh.active_response.agent_id` | keyword | Agent configured in the active response channel. | Required, non-empty when `location = defined-agent`. |
| `wazuh.active_response.stateful_timeout` | integer | Seconds configured in the channel (for stateful type). | Required when `type = stateful`, integer >= 0. |
| `wazuh.agent.id` | keyword | Unique identifier of the agent that must run the active response. | Required, non-empty when `location = local`. |

### Data stream

- **Index pattern:** `wazuh-active-responses*`
- **ISM policy:** `stream-active-responses-policy` — rolls over on size/doc count and deletes indices older than 3 days.
