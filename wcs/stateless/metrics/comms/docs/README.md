## `wazuh-metrics-comms` index data model

### Fields summary

The fields are based on:
- https://github.com/wazuh/wazuh/issues/35053

Based on ECS:
- [Base Fields](https://www.elastic.co/guide/en/ecs/current/ecs-base.html) — `@timestamp`
- [Event Fields](https://www.elastic.co/guide/en/ecs/current/ecs-event.html) — `event.module`
- [Network Fields](https://www.elastic.co/guide/en/ecs/current/ecs-network.html) — `network.egress.bytes`, `network.ingress.bytes`

The detail of the fields can be found in the csv file [Fields](fields.csv).

### Data stream

- **Index pattern:** `wazuh-metrics-comms*`
- **ISM policy:** `stream-metrics-policy` — deletes backing indices older than 30 days.

### Field table

| Field | Type | Level | Description |
|-------|------|-------|-------------|
| `@timestamp` | date | core | Date/time when the event originated. |
| `event.module` | keyword | core | Name of the module this data is coming from. |
| `queue.size` | integer | custom | Current number of messages queued (gauge). |
| `queue.capacity` | integer | custom | Maximum configured capacity of the message queue. |
| `tcp.sessions` | integer | custom | Current number of active TCP sessions. |
| `discarded.total` | long | custom | Cumulative number of discarded messages. |
| `events.total` | long | custom | Cumulative number of events forwarded to downstream components. |
| `messages.total` | long | custom | Cumulative number of control messages received. |
| `messages.control.dropped_on_close.total` | long | custom | Cumulative number of messages dropped when the agent connection closed. |
| `messages.control.usage` | float | custom | Current utilization ratio of the control message queue (0.0–1.0). |
| `messages.control.received.total` | long | custom | Cumulative number of control messages inserted into the control queue. |
| `messages.control.replaced.total` | long | custom | Cumulative number of control messages replaced in the queue. |
| `messages.control.processed.total` | long | custom | Cumulative number of control messages processed from the queue. |
| `network.egress.bytes` | long | core | Cumulative number of bytes sent. |
| `network.ingress.bytes` | long | core | Cumulative number of bytes received. |
| `wazuh.cluster.name` | keyword | custom | Wazuh cluster name. |
| `wazuh.cluster.node` | keyword | custom | Wazuh cluster node name. |
| `wazuh.schema.version` | keyword | custom | Wazuh schema version. |
