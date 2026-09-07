# Ruleset Management

The Ruleset Management plugin is a fork of the [OpenSearch Security Analytics plugin](https://opensearch.org/docs/3.6/security-analytics/) adapted for Wazuh. It evaluates incoming events against Sigma detection rules, creates findings when rules match, and correlates related findings across detectors.

The Ruleset Management plugin runs inside the Wazuh Indexer and operates as an OpenSearch plugin, using the standard OpenSearch transport layer for all internal communication.

> **A note on naming:** Ruleset Management is the user-facing name of the plugin. Internally the plugin is still called Security Analytics, and that name remains visible in the identifiers it exposes — the `plugins.security_analytics.*` settings prefix, the `/_plugins/_security_analytics/` API base path, the `.opensearch-sap-*` index patterns, and the `cluster:admin/*/securityanalytics/*` action namespaces. The [Development Guide](../../../dev/plugins/security-analytics.md) also refers to it as Security Analytics throughout. Both names describe the same plugin.

## Detector rule space restriction

A detector can only reference rules from a single space type — either **Standard** (pre-packaged Sigma rules) or **Custom** (user-promoted rules) — never both simultaneously. This applies to both detector creation and update operations.

When the restriction is violated, the API returns `400 Bad Request`.

## Detector constraints

- **Max rules per detector** — each detector input can reference at most `plugins.security_analytics.max_rules_per_detector` rules (custom or pre-packaged), default `50`. Requests that exceed this limit are rejected with HTTP 400.
- **Max detectors** — at most `plugins.security_analytics.max_detectors` user-created detectors are allowed, default `10`. Detectors created by the Content Manager plugin do not count towards this limit.

Both limits are dynamic and enforced at the transport layer, applying to all detector creation and update paths, including inter-plugin calls from the Content Manager. Both accept any value from `0` upwards; there is no hard-coded ceiling. See [Configuration](configuration.md) for details.

## Wazuh enriched findings

### What is a finding?

A **finding** is a record that a monitored event matched a Sigma detection rule. Ruleset Management creates one finding per matching event and stores it in the `.opensearch-sap-{category}-findings-*` data stream. Each finding contains:

- **`id`** — unique finding identifier.
- **`detector_id`** — the detector that produced the finding.
- **`related_doc_ids`** — IDs of the source documents that triggered the match.
- **`queries`** — the Sigma rule(s) that matched.
- **`index`** — the source index where the triggering event lives.
- **`timestamp`** — when the finding was created.

Raw findings contain only identifiers — they do not embed the triggering event payload or rule metadata.

### What is an enriched finding?

An **enriched finding** is an augmented version of a raw Ruleset Management finding. Because the Wazuh Dashboard needs the full event payload and rule context to render alert details, each finding is enriched with:

- The **full triggering event source** (fetched from the source index by document ID)
- **Rule metadata** under `wazuh.rule`: name, severity level, compliance mappings, MITRE ATT&CK tags

Rule metadata is merged into the event's existing `wazuh` object, so `wazuh.integration.*` from the triggering event sits alongside `wazuh.rule.*` in the enriched document.

Enriched findings are written to `wazuh-findings-v5-{category}*`, where `{category}` is derived from the `wazuh.integration.category` field in the triggering event.

### How findings are generated (high level)

The following steps happen for every event that matches a detection rule:

1. A Wazuh Manager sends an event to the Wazuh Indexer. The event is indexed in the monitored data stream.
2. The Ruleset Management plugin's Alerting monitor evaluates the event against all active Sigma rules for the configured log category.
3. On a match, Ruleset Management creates a raw finding and queues it for enrichment.
4. The enrichment step asynchronously fetches the triggering event source and the matching rule's metadata, assembles the enriched document, and bulk-indexes it into `wazuh-findings-v5-{category}*`.

Enrichment is **fire-and-forget**: it never blocks the Ruleset Management write path and failures are logged without propagating to the caller.

See [Architecture](architecture.md) for the data flow, and the development guide for implementation details.

## API

Most endpoints (detectors, alerts, findings, correlations, log types) are inherited from the upstream OpenSearch Security Analytics plugin — see the [OpenSearch API reference](https://opensearch.org/docs/3.6/security-analytics/api-tools/) for those. Wazuh-specific additions and modifications:

- **Case management update** (`PUT /_plugins/_security_analytics/findings/_update`) — see [Case management](case-management.md).
- **Detector rule-space restriction** and the **100-rule-per-detector limit** — see [Detector rule space restriction](#detector-rule-space-restriction) and [Detector constraints](#detector-constraints) above.
