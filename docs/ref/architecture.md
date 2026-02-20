# Architecture

The Wazuh Indexer is built on top of [OpenSearch](https://opensearch.org/) and extends it with a set of purpose-built plugins that provide security event indexing, content management, access control, and reporting capabilities.

## Component Overview

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
│                    ┌─────────┴──────────┐                  │        │
│                    │  System Indices    │                  │        │
│                    │  .cti-consumers    │                  │        │
│                    │  .cti-rules        │                  │        │
│                    │  .cti-decoders     │                  │        │
│                    │  .cti-integrations │                  │        │
│                    │  .cti-kvdbs        │                  │        │
│                    │  .cti-policies     │                  │        │
│                    │  .cti-iocs         │                  │        │
│                    └────────────────────┘                  │        │
└─────────────────────────────────┬──────────────────────────┼────────┘
                                  │ Unix Socket              │
                          ┌───────┴────────┐          ┌──────┴───────┐
                          │  Wazuh Engine  │          │  Wazuh       │
                          │  (Analysis &   │          │  Dashboard   │
                          │   Detection)   │          │  (UI)        │
                          └────────────────┘          └──────────────┘
```

## Plugins

### Setup Plugin

The Setup plugin initializes the Wazuh Indexer environment when the cluster starts. It is responsible for:

- **Index templates**: Defines the mappings and settings for all Wazuh indices (alerts, events, statistics, vulnerabilities, etc.).
- **ISM (Index State Management) policies**: Configures lifecycle policies for automatic rollover, deletion, and retention of time-series indices.
- **Data streams**: Creates the initial data stream indices that receive incoming event data.
- **State indices**: Sets up internal indices used by other Wazuh components to track operational state.

The Setup plugin runs once during cluster initialization and ensures the required infrastructure is in place before other plugins begin operating.

### Content Manager Plugin

The Content Manager is the most feature-rich plugin. It handles:

- **CTI synchronization**: Periodically fetches threat intelligence content (rules, decoders, integrations, KVDBs, IoCs) from the Wazuh CTI API. On first run, it downloads a full snapshot; subsequent runs apply incremental patches.
- **User-generated content**: Provides a REST API for creating, updating, and deleting custom decoders, rules, integrations, and KVDBs in a draft space.
- **Promotion workflow**: Changes made in the draft space can be previewed and promoted to the Wazuh Engine for activation.
- **Engine communication**: Communicates with the Wazuh Engine via a Unix socket for logtest execution, content validation, and configuration reload.
- **Policy management**: Manages the Engine routing policy that controls how events are processed.

See [Content Manager](modules/content-manager/index.md) for full details.

### Security Plugin

The Security plugin extends OpenSearch's security capabilities for Wazuh-specific needs:

- **Role-based access control (RBAC)**: Defines predefined roles and permissions for Wazuh operations.
- **User management**: Provides APIs and configuration for managing users and their access levels.
- **TLS/SSL**: Handles transport and REST layer encryption.

### Reporting Plugin

The Reporting plugin enables on-demand and scheduled report generation from the Wazuh Dashboard, producing PDF or CSV exports of dashboards and saved searches.

## Data Flow

1. **Wazuh Agents** collect security events from monitored endpoints and forward them to the **Wazuh Server**.
2. The **Wazuh Engine** on the server analyzes events using rules and decoders, then forwards alerts and events to the **Wazuh Indexer** via the Indexer API.
3. The **Setup Plugin** ensures the correct index templates, data streams, and lifecycle policies exist.
4. The **Content Manager Plugin** keeps the Engine's detection content up to date by synchronizing with the CTI API and managing user customizations.
5. The **Wazuh Dashboard** queries the Indexer to visualize alerts, events, and security analytics.
