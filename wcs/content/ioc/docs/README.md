## `wazuh-threatintel-enrichments` (IoC) index data model

### Fields summary

Wazuh Common Schema (WCS) field set describing Indicators of Compromise (IoC) ingested from threat-intelligence feeds. Each document holds the indicator, its provider/feed metadata, confidence, first/last seen dates and the SHA-256 hash of its content.

The detail of the fields can be found in the csv file [Fields](fields.csv).

### Index

- **Alias:** `wazuh-threatintel-enrichments`

### Field table

| Field | Type | Level | Description |
|-------|------|-------|-------------|
| `type_hashes` | object | custom | Dynamic object containing the hash values for each IoC type. |
| `document.id` | keyword | custom | Unique identifier for the IoC document. |
| `document.name` | keyword | custom | Name or label assigned to the IoC. |
| `document.type` | keyword | custom | Type or category of the IoC (IP address, domain, file hash, URL...). |
| `document.confidence` | short | custom | Confidence level or score for the IoC. |
| `document.tags` | keyword | custom | Tags or labels associated with the IoC. |
| `document.first_seen` | date | custom | When the IoC was first observed or reported. |
| `document.last_seen` | date | custom | When the IoC was most recently observed or reported. |
| `document.provider` | keyword | custom | Provider or organization that published the data. |
| `document.reference` | keyword | custom | Reference URL or identifier for additional information. |
| `document.feed.name` | keyword | custom | Name of the threat-intelligence feed that provided this IoC. |
| `document.software.name` | keyword | custom | Name of the software or malware associated with the IoC. |
| `document.software.alias` | keyword | custom | Alias or alternative names for the associated software. |
| `document.software.type` | keyword | custom | Type or classification of the software. |
| `hash.sha256` | keyword | custom | The SHA-256 hash of the IoC document. |
