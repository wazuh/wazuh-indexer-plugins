# Description

The Wazuh Indexer is a highly scalable, full-text search and analytics engine built on top of [OpenSearch](https://opensearch.org/) 3. In Wazuh 5.0 it becomes the **core component of the Wazuh platform**: in addition to indexing and storing security data, it now embeds the Wazuh Engine and hosts the threat detection, alerting, notification, reporting, and content management logic that previously ran on the Wazuh Server.

The Wazuh Indexer can be deployed as a single-node instance for development and small environments, or as a multi-node cluster for production workloads requiring high availability and horizontal scalability.

## What's new in 5.0

Wazuh 5.0 consolidates most of the platform's data plane and detection logic inside the Indexer:

- The **Wazuh Engine** is bundled into the Wazuh Indexer packages and Docker images (x86_64 and aarch64). Plugins communicate with the Engine over a local Unix socket.
- **Threat detection** has been migrated from the Wazuh Server to the Indexer through the Security Analytics plugin (a Wazuh fork of the OpenSearch Security Analytics plugin), with extended Sigma rules syntax and per-space rules, log types and detectors.
- **Active Response** has been migrated to the Indexer, driven by a dedicated Alerting monitor and persisted in the `wazuh-active-responses` data stream.
- **Filebeat is no longer used** to forward events between the Wazuh Server and the Indexer. Events now reach the Indexer through a built-in indexer connector.
- Time-series data (events, findings, metrics, raw events, active responses) is stored in **data streams** with **ISM policies** for automatic rollover and retention.
- A new **Content Manager** plugin owns the lifecycle of detection content (ruleset, vulnerabilities feed, IoC feed) and exposes a REST API for user-defined content with a `draft → test → custom` promotion workflow.
- The **Wazuh Common Schema (WCS)** has been reworked and now lives in the `wazuh-indexer-plugins` repository, bumped to ECS 9.1.0, with per-category event and finding data streams.

See the [release notes](release-notes.md) for the full list of changes and breaking changes.

## Core concepts

The Wazuh Indexer stores data as JSON **documents**. Each document contains a set of fields (keys) mapped to values — strings, numbers, booleans, dates, arrays, nested objects, and more.

An **index** is a collection of related documents. For time-series data such as events, findings, metrics and active responses, the Wazuh Indexer uses **data streams** backed by rolling indices, managed by **Index State Management (ISM)** policies that handle rollover and retention based on age and size.

Documents are distributed across **shards** spread across cluster nodes. This distribution provides redundancy against hardware failures and allows query throughput to scale as nodes are added.

![Indexer shards](https://documentation.wazuh.com/current/_images/wazuh-indexer1.png)

Detection content (rules, decoders, integrations, KVDBs, filters, policies, IoCs and the vulnerabilities feed) is organized into **spaces**:

- `standard` — read-only content sourced from the Wazuh CTI API.
- `draft` — user-editable workspace for new or modified resources.
- `test` — staging space used to validate draft content against the Wazuh Engine.
- `custom` — promoted user-defined content active in the Engine.

The Content Manager enforces the `draft → test → custom` promotion workflow and keeps the Engine synchronized with the active content.

## Bundled plugins

The Wazuh Indexer ships with a curated set of plugins. Some are Wazuh-developed; others are Wazuh forks of upstream OpenSearch plugins tailored for the platform.

### Setup plugin

The Setup plugin initializes the indexer environment on cluster startup. It creates all required index templates, ISM policies, data streams, and internal state indices, ensuring the correct schema and lifecycle rules are in place before any data is ingested. It also defines the [Wazuh Common Schema](modules/setup/schema.md) — the standardized field mappings used across all Wazuh indices — and exposes a Settings API used to manage Wazuh-level settings that now reside in the Indexer (including Engine settings).

### Content Manager plugin

The Content Manager keeps the Wazuh detection content up to date. It synchronizes the ruleset, vulnerabilities feed, and IoC feed from the Wazuh CTI API, and provides a REST API for user-defined threat intelligence resources — rules, decoders, integrations, KVDBs, filters and policies — supporting drafting, testing, promotion, manual or scheduled updates, subscription management and version checks.

A daily ping to the Wazuh CTI API surfaces content updates and deployment telemetry. The plugin communicates with the bundled Wazuh Engine through a Unix socket to validate user content and execute the [logtest](modules/content-manager/rule-testing.md) feature, which is split into a normalization phase (decoders) and a detection phase (rules).

A snapshot of the ruleset, vulnerabilities feed and IoC feed is bundled with the Wazuh Indexer packages, so a freshly installed cluster has content available offline.

See [Content Manager](modules/content-manager/index.md) for details.

### Security Analytics plugin

A Wazuh fork of the OpenSearch Security Analytics plugin. It is the home of **threat detection** in 5.0:

- Per-space log types, rules and threat detectors.
- Extended Sigma rules syntax, including case-insensitive operators, the `exists` modifier, IPv6 support and dynamic event field referencing in findings.
- Enriched findings written to `wazuh-findings-v5-{category}` data streams, embedding the full triggering event source and rule metadata (id, title, tags, level, status, MITRE, compliance).

### Alerting plugin

A Wazuh fork of the OpenSearch Alerting plugin. It provides real-time alerting based on predefined monitors. Monitors are the core component used by the Security Analytics plugin for threat detection, and a dedicated monitor drives Active Response.

### Notifications plugin

A Wazuh fork of the OpenSearch Notifications plugin. It supports multiple delivery channels — Slack, Microsoft Teams, Amazon Chime, Email (SMTP/SES), AWS SNS, and custom webhooks — and ships default webhooks for Slack, Jira, PagerDuty and Shuffle. It also provides a dedicated channel type that powers **Active Response**, batching execution requests through a bulk processor.

### Reporting plugin

A Wazuh fork of the OpenSearch Reporting plugin, bundled by default in Wazuh Indexer packages. It generates PDF and CSV reports from dashboards and saved searches, on demand or on a schedule, with optional email delivery.

### Common Utils library

A Wazuh fork of the OpenSearch Common Utils library. It provides the shared models and transport actions used across the Wazuh forks of Alerting, Notifications, Security Analytics and the Content Manager — including the Active Response channel definition.

### Security plugin

The Security plugin provides role-based access control (RBAC), user authentication, and TLS encryption for both the REST API and inter-node transport layers. Wazuh 5.0 ships with a new set of reserved users and roles aligned with the new plugins (Content Manager, Alerting, Notifications, Reporting, Security Analytics). See [Access Control](security/access-control.md) for details.

## Bundled Wazuh Engine

The Wazuh Engine is shipped inside the Wazuh Indexer packages and Docker images. It is responsible for:

- Decoding and normalizing events before they are indexed.
- Validating user-defined threat intel content submitted through the Content Manager.
- Enrichment: IoC content management, GeoIP enrichment, and engine filters for event pre-processing.
- Executing logtest requests issued by the Content Manager.

The Engine listens on a local Unix socket with restricted permissions (`750`) and is reachable only by the Indexer plugins running on the same node.

## Data storage

The Wazuh Indexer organizes data into purpose-specific indices and data streams. Time-series streams are categorized per event type (access management, applications, cloud services, network activity, security, system activity, unclassified).

| Index pattern              | Description                                                                                                  |
| -------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `wazuh-events-v5-{cat}`    | Decoded and normalized security events from monitored endpoints, per category.                               |
| `wazuh-events-raw-v5`      | Raw incoming events, retained briefly under an aggressive ISM purge policy (gated by an Engine setting).     |
| `wazuh-findings-v5-{cat}`  | Enriched findings produced by Security Analytics, embedding the triggering event and rule metadata.          |
| `wazuh-states-v5-*`        | Stateful inventory data (vulnerabilities, packages, ports, FIM, services, browser extensions, SCA, etc.).    |
| `wazuh-active-responses`   | Active Response execution requests, driven by a dedicated Alerting monitor.                                  |
| `wazuh-metrics-*`          | Agent and communications telemetry metrics.                                                                  |
| `wazuh-threatintel-*`      | Content Manager system indices for CTI content (rules, decoders, integrations, KVDBs, filters, policies, IoCs). |
| `.wazuh-cti-consumers`     | Internal index tracking consumer state for CTI synchronization.                                              |

Agent and rule metadata is now relocated under the `wazuh.*` namespace, and inventory coverage has been extended to Linux systemd units and macOS launchd daemons/agents alongside Windows services. For a complete list of indices and their schemas, see the [Setup Plugin](modules/setup/index.md) documentation.

## Integration with the Wazuh platform

In 5.0 the Wazuh Indexer is the central processing and storage tier of the platform:

- **Wazuh Agents** collect endpoint data and send it to the Wazuh Server.
- **Wazuh Server** acts as the ingestion gateway. It no longer runs analysis, threat detection, content management or active response — these have moved into the Indexer. Events are forwarded to the Indexer through the built-in indexer connector (Filebeat is no longer required).
- **Wazuh Indexer**, through the bundled Wazuh Engine and its plugins, normalizes events, runs threat detection, manages detection content, dispatches notifications and active responses, and stores all resulting data.
- **Wazuh Dashboard** (an OpenSearch Dashboards fork) provides the web UI for searching, visualizing and managing Wazuh data, and interacts with the Setup, Content Manager, Security Analytics, Alerting, Notifications and Reporting plugin APIs.

The Indexer exposes a standard REST API compatible with the OpenSearch API, so existing OpenSearch tools, clients and integrations work with the Wazuh Indexer out of the box.
