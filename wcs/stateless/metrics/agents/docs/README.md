## `wazuh-metrics-agents` index data model

### Fields summary

The fields are based on:
- https://github.com/wazuh/wazuh/issues/34711

Based on ECS:
- [Base Fields](https://www.elastic.co/guide/en/ecs/current/ecs-base.html) — `@timestamp`
- [Agent Fields](https://www.elastic.co/guide/en/ecs/current/ecs-agent.html) — agent identity and host metadata (via `wazuh.agent`)

The detail of the fields can be found in the csv file [Fields](fields.csv).

### Data stream

- **Index pattern:** `wazuh-metrics-agents*`
- **ISM policy:** `stream-metrics-policy` — deletes backing indices older than 30 days.

### Field table

| Field | Type | Level | Description |
|-------|------|-------|-------------|
| `@timestamp` | date | core | Date/time when the event originated. |
| `wazuh.agent.id` | keyword | core | Unique identifier of this agent. |
| `wazuh.agent.name` | keyword | core | Custom name of the agent. |
| `wazuh.agent.version` | keyword | core | Version of the agent. |
| `wazuh.agent.groups` | keyword | custom | List of groups the agent belongs to. |
| `wazuh.agent.host.ip` | ip | core | Host IP addresses. |
| `wazuh.agent.host.architecture` | keyword | core | Operating system architecture. |
| `wazuh.agent.host.os.name` | keyword | extended | Operating system name, without the version. |
| `wazuh.agent.host.os.version` | keyword | extended | Operating system version as a raw string. |
| `wazuh.agent.host.os.platform` | keyword | extended | Operating system platform. |
| `wazuh.agent.host.os.full` | keyword | extended | Operating system name, including the version or code name. |
| `wazuh.agent.register.ip` | ip | custom | Registration IP value from `client.keys`. |
| `wazuh.agent.status` | keyword | custom | Current connection status of the agent. |
| `wazuh.agent.status_code` | integer | custom | Internal numeric status code for the connection state. |
| `wazuh.agent.registered_at` | date | custom | Date/time when the agent was registered. |
| `wazuh.agent.last_seen` | date | custom | Date/time of the last keepalive received. |
| `wazuh.agent.disconnected_at` | date | custom | Date/time when the agent was considered disconnected. |
| `wazuh.agent.config.hash.md5` | keyword | custom | MD5 hash of the agent configuration. |
| `wazuh.agent.config.group.synced` | boolean | custom | Status of the group configuration assigned to the agent. |
| `wazuh.agent.config.group.hash.md5` | keyword | custom | MD5 hash of the merged group configuration. |
| `wazuh.cluster.name` | keyword | custom | Wazuh cluster name. |
| `wazuh.cluster.node` | keyword | custom | Wazuh cluster node name. |
| `wazuh.schema.version` | keyword | custom | Wazuh schema version. |
