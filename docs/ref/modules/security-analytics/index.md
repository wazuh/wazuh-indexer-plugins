# Security Analytics

The Security Analytics Plugin (SAP) is a fork of the [OpenSearch Security Analytics plugin](https://opensearch.org/docs/latest/security-analytics/) adapted for Wazuh. It evaluates incoming events against Sigma detection rules, creates findings when rules match, and correlates related findings across detectors.

SAP runs inside the Wazuh Indexer and operates as an OpenSearch plugin, using the standard OpenSearch transport layer for all internal communication.

## Wazuh enriched findings

### What is a finding?

A **finding** is a record that a monitored event matched a Sigma detection rule. SAP creates one finding per matching event and stores it in the `.opensearch-sap-{category}-findings-*` data stream. Each finding contains:

| Field             | Description                                          |
| ----------------- | ---------------------------------------------------- |
| `id`              | Unique finding identifier                            |
| `detector_id`     | The detector that produced the finding               |
| `related_doc_ids` | IDs of the source documents that triggered the match |
| `queries`         | The Sigma rule(s) that matched                       |
| `index`           | The source index where the triggering event lives    |
| `timestamp`       | When the finding was created                         |

Raw findings contain only identifiers — they do not embed the triggering event payload or rule metadata.

### What is an enriched finding?

An **enriched finding** is an augmented version of a raw SAP finding. Because the Wazuh Dashboard needs the full event payload and rule context to render alert details, `WazuhEnrichedFindingService` enriches each finding with:

- The **full triggering event source** (fetched from the source index by document ID)
- **Rule metadata**: name, severity level, compliance mappings, MITRE ATT&CK tags

Enriched findings are written to `wazuh-findings-v5-{category}*`, where `{category}` is derived from the `wazuh.integration.category` field in the triggering event.

### How findings are generated (high level)

The following steps happen for every event that matches a detection rule:

1. A Wazuh Manager sends an event to the Wazuh Indexer. The event is indexed in the monitored data stream.
2. SAP's Alerting monitor evaluates the event against all active Sigma rules for the configured log category.
3. On a match, SAP creates a raw finding and fires the `SUBSCRIBE_FINDINGS_ACTION` transport action.
4. `TransportCorrelateFindingAction` receives the action, runs the correlation engine, and calls `WazuhEnrichedFindingService.enrich(finding)`.
5. The service asynchronously fetches the triggering event source and the matching rule's metadata, assembles the enriched document, and bulk-indexes it into `wazuh-findings-v5-{category}*`.

The enrichment step is **fire-and-forget**: it never blocks the SAP write path and failures are logged at `WARN` level without propagating to the caller.

See [Architecture](architecture.md) for the low-level implementation details.
