# Architecture

## Enrichment pipeline

When a Sigma rule matches an event, Ruleset Management writes a raw finding, and an asynchronous enrichment step fetches the triggering event and the matching rule's metadata, assembles an enriched document, and bulk-indexes it into `wazuh-findings-v5-{category}*`.

The complete flow is shown in the sequence diagram below:

```mermaid
sequenceDiagram
    participant A as Wazuh Manager
    participant I as Wazuh Indexer
    participant RM as Ruleset Management
    participant SI as Source index
    participant RI as Rules index
    participant WF as wazuh-findings-v5-{category}*

    A->>I: Ingest event
    I->>RM: Monitor evaluates event against Sigma rules
    RM->>RM: Rule matches → create raw finding
    RM->>RM: Queue finding for enrichment
    RM->>SI: Fetch triggering event by document ID
    SI-->>RM: Event source
    RM->>RM: Resolve log category from the event
    alt Rule metadata cached
        RM->>RM: Read from in-memory cache
    else Cache miss
        RM->>RI: Fetch rule metadata (pre-packaged + custom rules indices)
        RI-->>RM: Rule metadata
        RM->>RM: Cache the result
    end
    RM->>RM: Assemble enriched document
    alt Batch full
        RM->>WF: Bulk-index accumulated findings
    else Periodic flush
        RM->>WF: Bulk-index accumulated findings
    end
```

Enrichment is fire-and-forget: it never blocks the write path for the raw finding, and failures are logged without propagating to the caller. Concurrency is bounded so that heavy finding volume can't overload the transport layer; findings that arrive while the concurrency limit is reached are queued and processed as capacity frees up.

## Detector provisioning

Threat detectors for Wazuh integrations are created dynamically based on CTI content rather than fixed configuration:

- **Enabled status**: controlled by CTI to activate or deactivate detectors globally.
- **Scan interval**: customizable per integration (e.g., critical integrations can have shorter intervals).
- **Source indices**: defines the target indices or index patterns the detector monitors. If no source indices are provided, the detector falls back to the legacy per-category events pattern.

Any change in the CTI catalog is reflected in detector configuration without requiring code changes or restarts.

## Behavior notes

- **Rule metadata caching**: rule metadata (severity level, compliance mappings, MITRE ATT&CK tags) is cached in memory, keyed by rule ID, so repeated findings from the same detector don't repeatedly query the rules indices. The cache size is bounded by `enriched_findings_rule_cache_max_size` (see [Configuration](configuration.md)); least-recently-used entries are evicted and re-fetched on demand.
- **Category resolution**: if the triggering event doesn't carry a recognized log category, enrichment is skipped for that finding and a warning is logged.
- **Document layout**: the enriched document is a copy of the triggering event's source, with rule metadata nested under `wazuh.rule` (id, title, tags, and any of level, status, compliance, MITRE present in the rule). The original event source is never mutated.
- **Write semantics**: enriched findings are indexed as new documents, never overwriting an existing enriched finding for the same event.

## Technical parameters

See [Configuration](configuration.md) for the settings that control batch size, flush interval, concurrency, and cache size.

## System indices

| Index                                       | Description                                                  |
| -------------------------------------------- | ------------------------------------------------------------ |
| `.opensearch-sap-{category}-findings-*`     | Raw findings written by the Ruleset Management plugin        |
| `.opensearch-sap-pre-packaged-rules-config` | Wazuh-provided Sigma rules; source for rule metadata         |
| `.opensearch-sap-custom-rules-config`       | User-created custom rules; fallback source for rule metadata |
| `.opensearch-sap-log-types-config`          | Integrations                                                 |
| `.opensearch-sap-detectors-config`          | Threat detector configurations                               |
| `wazuh-findings-v5-{category}*`             | Enriched findings                                             |

## Access control

Access to Ruleset Management is governed by the [default Wazuh roles](../../security/access-control.md). The plugin authorizes requests against two action namespaces: the Wazuh custom actions `cluster:admin/wazuh/securityanalytics/*` and the upstream OpenSearch actions `cluster:admin/opensearch/securityanalytics/*` (see [Permissions](../../security/permissions.md)).

- **`wazuh_admin`** — full access: create/update/delete detectors, rules, log types, and correlations; read findings and alerts.
- **`wazuh_demo`** — full access, same endpoints as `wazuh_admin`.
- **`wazuh_readonly`** — read-only: get/search detectors, rules, findings, alerts, mappings, correlations, and threat intel; `rules/evaluate`.
- **`wazuh_manager`** — no access.
