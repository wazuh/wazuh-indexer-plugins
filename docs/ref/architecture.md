# Architecture

The Wazuh Indexer is built on top of [OpenSearch](https://opensearch.org/) and extends it with a set of purpose-built plugins that provide security event indexing, threat detection, content management, notifications, access control, and reporting capabilities. It also bundles the Wazuh Engine. See [Description](description.md) for an overview of each component.

## Component overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Wazuh Indexer                                │
│                                                                     │
│  ┌──────────────┐  ┌──────────────────┐  ┌──────────┐  ┌─────────┐  │
│  │ Setup Plugin │  │ Content Manager  │  │ Security │  │Reporting│  │
│  │              │  │     Plugin       │  │  Plugin  │  │ Plugin  │  │
│  └──────┬───────┘  └────────┬─────────┘  └────┬─────┘  └───┬─────┘  │
│         │                   │                 │            │        │
│  ┌──────┴────────┐   ┌──────┴───────────┐  ┌──┴───────┐    │        │
│  │Index Templates│   │  CTI API Client  │  │  RBAC &  │    │        │
│  │ISM Policies   │   │  Engine Client   │  │  Access  │    │        │
│  │Stream Indices │   │  Job Scheduler   │  │  Control │    │        │
│  │State Indices  │   │  Space Service   │  └──────────┘    │        │
│  └───────────────┘   └───────┬──────────┘                  │        │
│                              │                             │        │
│                    ┌─────────┴───────────────────────┐     │        │
│                    │  System Indices                 │     │        │
│                    │  .wazuh-cti-consumers           │     │        │
│                    │  wazuh-threatintel-rules        │     │        │
│                    │  wazuh-threatintel-decoders     │     │        │
│                    │  wazuh-threatintel-integrations │     │        │
│                    │  wazuh-threatintel-kvdbs        │     │        │
│                    │  wazuh-threatintel-policies     │     │        │
│                    │  wazuh-threatintel-enrichments  │     │        │
│                    └─────────────────────────────────┘     │        │
└─────────────────────────────────┬──────────────────────────┼────────┘
                                  │ Unix Socket              │
                          ┌───────┴────────┐          ┌──────┴───────┐
                          │  Wazuh Engine  │          │  Wazuh       │
                          │  (Analysis &   │          │  Dashboard   │
                          │   Detection)   │          │  (UI)        │
                          └────────────────┘          └──────────────┘
```

For brevity, the diagram leaves out the Ruleset Management, Alerting and Notifications plugins and the Common Utils library, which are described below.

## Plugins

### Setup plugin

The Setup plugin initializes the Wazuh Indexer environment when the cluster starts. It is responsible for:

- **Index templates**: Defines the mappings and settings for all Wazuh indices (events, findings, inventory states, metrics, etc.).
- **ISM (Index State Management) policies**: Configures lifecycle policies for automatic rollover, deletion, and retention of time-series indices.
- **Data streams**: Creates the initial data stream indices that receive incoming event data.
- **State indices**: Sets up internal indices used by other Wazuh components to track operational state.

The Setup plugin runs once during cluster initialization and ensures the required infrastructure is in place before other plugins begin operating. It also exposes a Settings API for the Wazuh-level settings that reside in the Indexer, including Engine settings.

See [Setup](modules/setup/index.md) for full details.

### Content Manager plugin

The Content Manager is the most feature-rich plugin. It handles:

- **CTI synchronization**: Periodically fetches threat intelligence content (rules, decoders, integrations, KVDBs, IoCs) from the Wazuh CTI API. On first run, it downloads a full snapshot; subsequent runs apply incremental patches.
- **User-generated content**: Provides a REST API for creating, updating, and deleting custom decoders, rules, integrations, and KVDBs in a draft space.
- **Promotion workflow**: Changes made in the draft space can be previewed and promoted to the Wazuh Engine for activation.
- **Engine communication**: Communicates with the Wazuh Engine via a Unix socket for logtest execution, content validation, and configuration reload.
- **Policy management**: Manages the Engine routing policy that controls how events are processed.

See [Content Manager](modules/content-manager/index.md) for full details.

### Ruleset Management plugin

A Wazuh fork of the OpenSearch Security Analytics plugin, and the home of threat detection:

- **Detection content**: Holds per-space log types, rules and threat detectors, with an extended Sigma rules syntax.
- **Findings**: Writes enriched findings to the `wazuh-findings-v5-{category}` data streams, embedding the triggering event and the rule metadata.

See [Ruleset Management](modules/ruleset-management/index.md) for full details.

### Alerting plugin

A Wazuh fork of the OpenSearch Alerting plugin. Its monitors are what the Ruleset Management plugin runs threat detection on, and a dedicated monitor drives Active Response.

See [Alerting](modules/alerting/index.md) for full details.

### Notifications plugin

A Wazuh fork of the OpenSearch Notifications plugin. It delivers messages through Slack, Microsoft Teams, Amazon Chime, email (SMTP or SES), AWS SNS and custom webhooks, and provides the `active_response` channel type, which queues Active Response execution requests in the `wazuh-active-responses` data stream.

See [Notifications](modules/notifications/index.md) for full details.

### Reporting plugin

A Wazuh fork of the OpenSearch Reporting plugin. It enables on-demand and scheduled report generation from the Wazuh Dashboard, producing PDF or PNG exports of dashboards and visualizations, and CSV or XLSX exports of saved searches.

See [Reporting](modules/reporting/index.md) for full details.

### Common Utils library

A Wazuh fork of the OpenSearch Common Utils library. It provides the shared models and transport actions used across the Wazuh forks of Alerting, Notifications and Ruleset Management, and by the Content Manager.

### Security plugin

The Security plugin extends OpenSearch's security capabilities for Wazuh-specific needs:

- **Role-based access control (RBAC)**: Defines predefined roles and permissions for Wazuh operations.
- **User management**: Provides APIs and configuration for managing users and their access levels.
- **TLS/SSL**: Handles transport and REST layer encryption.

See [Access control](security/access-control.md) for full details.

## Data flow

1. **Wazuh Agents** collect security events from monitored endpoints and forward them to the **Wazuh Manager**.
2. The **Wazuh Manager** decodes and normalizes the events and forwards them to the **Wazuh Indexer** through its indexer connector.
3. The **Setup plugin** ensures the correct index templates, data streams, and lifecycle policies exist for the events to be stored.
4. The **Ruleset Management plugin** evaluates the events against the detection rules through document-level **Alerting** monitors and stores the resulting findings in the `wazuh-findings-v5-{category}` data streams.
5. An Active Response **Alerting** monitor turns matching findings into execution requests, which the **Notifications plugin** queues in the `wazuh-active-responses` data stream for the **Wazuh Manager** to run on agents.
6. The **Content Manager plugin** keeps the detection content up to date by synchronizing with the CTI API and managing user customizations, which the bundled **Wazuh Engine** validates and tests.
7. The **Wazuh Dashboard** queries the Indexer to visualize events, findings, and inventory data.
