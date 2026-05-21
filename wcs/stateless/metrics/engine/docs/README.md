## `wazuh-metrics-normalization` index data model

### Fields summary

The fields are based on:
- https://github.com/wazuh/wazuh/issues/35470

Based on ECS:
- [Base Fields](https://www.elastic.co/guide/en/ecs/current/ecs-base.html) — `@timestamp`
- [Event Fields](https://www.elastic.co/guide/en/ecs/current/ecs-event.html) — `event.module`, `event.kind`

The detail of the fields can be found in the csv file [Fields](fields.csv).

### Data stream

- **Index pattern:** `wazuh-metrics-normalization*`
- **ISM policy:** `stream-metrics-policy` — deletes backing indices older than 30 days.

### Document structure

Unlike other metrics indices, this index stores **one document per individual metric entry** rather than one document per snapshot.

### Field table

| Field | Type | Level | Description |
|-------|------|-------|-------------|
| `@timestamp` | date | core | Date/time when the event originated. |
| `event.kind` | keyword | core | The kind of event (e.g. `metrics`). |
| `event.module` | keyword | core | Name of the module this data is coming from (e.g. `wazuh-manager-analysisd`). |
| `metric.name` | keyword | custom | Name of the metric (e.g. `router.queue.size`). |
| `metric.type` | keyword | custom | Collection type of the metric (e.g. `pull`, `counter`). |
| `metric.enabled` | boolean | custom | Whether the metric is currently enabled. |
| `metric.value` | float | custom | Numeric value of the metric. |
| `wazuh.cluster.name` | keyword | custom | Wazuh cluster name. |
| `wazuh.cluster.node` | keyword | custom | Wazuh cluster node name. |
| `wazuh.space.name` | keyword | custom | Wazuh space name. `null` for global metrics, a string for space-scoped metrics. |
| `wazuh.schema.version` | keyword | custom | Wazuh schema version. |
