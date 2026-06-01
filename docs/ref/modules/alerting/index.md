# Alerting

The Wazuh Indexer Alerting plugin monitors data stored in the Wazuh Indexer, evaluates user-defined trigger conditions on a schedule, and executes actions when those conditions are met. Actions typically deliver notifications through the [Notifications](../notifications/index.md) plugin (Slack, email, webhooks, etc.) but can also drive Wazuh-specific workflows such as [Active Response](#active-response).

The plugin is a fork of the [OpenSearch Alerting plugin](https://docs.opensearch.org/docs/latest/observing-your-data/alerting/) adapted for Wazuh.

## Key Capabilities

- **Multiple monitor types:** Query-level, bucket-level, document-level, and the Wazuh-specific Active Response monitor. See [Architecture](architecture.md) for details.
- **Flexible triggers:** Define conditions using the full OpenSearch query DSL, aggregation results, or per-document matching with percolate queries.
- **Notification actions:** When a trigger fires, send alerts through any channel configured in the Notifications plugin — Slack, Microsoft Teams, email, custom webhooks, PagerDuty, and more.
- **Workflows:** Chain multiple monitors into composite workflows for complex detection scenarios.
- **Alert lifecycle management:** Track alerts through Active, Acknowledged, Completed, and Error states. Add comments to alerts for collaboration.
- **RBAC integration:** Access to monitors, alerts, and destinations is governed by the Security plugin with backend-role–based filtering.
- **Cross-cluster monitoring:** Monitor indices on remote clusters connected via cross-cluster search.
- **REST API:** Full programmatic control over monitors, workflows, alerts, findings, and comments. See [API Reference](api.md).
- **Dashboard UI:** Create, manage, and monitor alerts through the Wazuh Dashboard interface.

## Wazuh Integration Points

### Security Analytics

The [Security Analytics](../security-analytics/index.md) plugin uses alerting monitors to evaluate incoming events against Sigma detection rules. When an event matches a rule, Security Analytics creates a finding and can trigger an alert. The alerting monitor drives the detection loop — periodically querying new events and running them through the configured detectors.

### Notifications

Alerting actions route through the [Notifications](../notifications/index.md) plugin for message delivery. When a trigger fires, the alerting plugin calls the Notifications plugin via its internal transport interface to send messages to configured channels. This means any destination supported by Notifications (Slack, Teams, email, webhooks, SNS) is available as an alerting action target.

### Active Response

The Alerting plugin includes a Wazuh-specific **Active Response monitor type** that extends document-level monitoring for automated response workflows. This monitor type has specific constraints:

- **Indices:** Must target indices matching the `wazuh-findings-v5*` prefix.
- **Schedule:** Maximum interval of 1 minute (60,000 ms).
- **Triggers:** Only `DocumentLevelTrigger` is supported.

When an Active Response monitor triggers, it writes execution requests to the `wazuh-active-responses` data stream. The Wazuh Manager retrieves documents from this data stream to distribute and execute Active Response actions on agents. Each document references the source event that triggered the response.

## Default Monitors

On first startup, a sample alerting monitor is created alongside the [default notification channels](../notifications/index.md#default-notification-channels). This monitor serves as a template that users can customize and enable. Review it under **Alerting > Monitors** in the Wazuh Dashboard before enabling alerts.

## Dependencies

| Dependency | Purpose |
| --- | --- |
| [Notifications plugin](../notifications/index.md) | Delivers alert notifications to configured channels |
| Security plugin | Enforces RBAC on monitors, alerts, and destinations |
| Job Scheduler plugin | Schedules and executes monitors at configured intervals |
| [wazuh-indexer-common-utils](https://github.com/wazuh/wazuh-indexer-common-utils) | Shared utility functions and common components |

## Further Reading

For the full upstream API reference, advanced configuration, and Dashboard usage guides, see the [OpenSearch Alerting documentation](https://docs.opensearch.org/docs/latest/observing-your-data/alerting/).

## Version

The current plugin version is **5.0.0-alpha0** (see `VERSION.json` in the repository root).
