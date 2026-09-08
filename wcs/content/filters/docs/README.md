## `wazuh-threatintel-filters` index data model

### Fields summary

Wazuh Common Schema (WCS) field set describing the threat-intelligence filter documents managed by the engine. Each document holds a filter's configuration, metadata and the SHA-256 hash of its content.

The detail of the fields can be found in the csv file [Fields](fields.csv).

### Index

- **Index pattern:** `wazuh-threatintel-filters`
- No ISM policy

### Field table

| Field | Type | Level | Description |
|-------|------|-------|-------------|
| `@timestamp` | date | core | Date/time when the event originated. |
| `yaml` | text | custom | The YAML representation of the filter configuration. |
| `document.id` | keyword | custom | Unique identifier of the filter document. |
| `document.name` | keyword | custom | Human-readable name of the filter. |
| `document.type` | keyword | custom | Filter type or category. |
| `document.check` | object | custom | Check expression or identifier used by the filter. |
| `document.enabled` | boolean | custom | Whether the filter is enabled. |
| `document.metadata.title` | keyword | custom | Title of the filter. |
| `document.metadata.description` | text | custom | Description of the filter purpose or behavior. |
| `document.metadata.author` | keyword | custom | Author of the filter. |
| `document.metadata.date` | date | custom | Creation date of the filter. |
| `document.metadata.modified` | date | custom | Last modification date of the filter. |
| `document.metadata.references` | keyword | custom | References or links related to the filter. |
| `document.metadata.documentation` | keyword | custom | Documentation link for the filter. |
| `document.metadata.supports` | keyword | custom | Supported platforms or components for the filter. |
| `hash.sha256` | keyword | custom | The SHA-256 hash of the filter document. |
| `space.name` | keyword | custom | The name of the space where the filter is defined. |
