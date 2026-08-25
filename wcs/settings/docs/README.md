## `.wazuh-settings` index data model

### Fields summary

Wazuh Common Schema (WCS) field set holding cluster-wide Wazuh settings toggled by the engine.

The detail of the fields can be found in the csv file [Fields](fields.csv).

### Index

- **Index pattern:** `.wazuh-settings*`
- Hidden index.

### Field table

| Field | Type | Level | Description |
|-------|------|-------|-------------|
| `engine.index_raw_events` | boolean | custom | When set to `true`, the engine will index raw events. |
