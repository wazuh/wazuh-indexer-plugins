# Notifications

The Wazuh Indexer Notifications plugin is a specialized component designed to extend the Wazuh Indexer (based on OpenSearch) with multi-channel notification capabilities. It allows the system to send alerts, reports, and messages via **Email** (SMTP/SES), **Slack**, **Microsoft Teams**, **Amazon Chime**, **Amazon SNS**, and **Custom Webhooks**.

## Key capabilities

- **Multi-channel delivery:** Send notifications to Slack, Microsoft Teams, Chime, Email (SMTP and AWS SES), AWS SNS, and custom HTTP webhooks.
- **Unified REST API:** Create, update, delete, and query notification channel configurations through a single API surface at `/_plugins/_notifications/`.
- **Test notifications:** Validate channel configuration by sending a test message before relying on it for production alerts.
- **Feature discovery:** Other plugins can query supported notification features dynamically.
- **RBAC integration:** Access to notification configurations is governed by the Wazuh Indexer Security plugin, with backend-role–based filtering.
- **Extensible architecture:** The plugin uses a Service Provider Interface (SPI) pattern, making it straightforward to add new destination types.

## Supported channel types

- **`slack`** (HTTPS webhook) — posts messages to a Slack channel via an Incoming Webhook URL.
- **`chime`** (HTTPS webhook) — posts messages to an Amazon Chime room via a webhook URL.
- **`microsoft_teams`** (HTTPS webhook) — posts messages to a Microsoft Teams channel via a connector webhook.
- **`webhook`** (HTTP/HTTPS) — sends a payload to an arbitrary HTTP endpoint with configurable method, headers, and URL.
- **`email`** (SMTP / AWS SES) — sends email messages. Requires an `smtp_account` or `ses_account` configuration.
- **`sns`** (AWS SNS SDK) — publishes a message to an Amazon SNS topic.
- **`smtp_account`** — defines SMTP server connection details (host, port, method, credentials).
- **`ses_account`** — defines AWS SES sending details (region, role ARN, from address).
- **`email_group`** — defines a group of email recipients for reuse across email-type channels.

## Default notification channels

On first startup, the Notifications plugin automatically creates a set of **default notification channels**. These channels are pre-configured with placeholder URLs and are **disabled by default**, they serve as templates that users can customize with their own credentials and then enable.

The following default channels are created:

- **Slack Channel** (`slack`) — targets Slack, default URL `https://hooks.slack.com/services/YOUR_WORKSPACE_ID/YOUR_CHANNEL_ID/YOUR_WEBHOOK_TOKEN`.
- **Jira Channel** (`webhook`) — targets Jira Cloud, default URL `https://your-domain.atlassian.net/rest/api/3/issue`.
- **PagerDuty Channel** (`webhook`) — targets the PagerDuty Events API v2, default URL `https://events.pagerduty.com/v2/enqueue`.
- **Shuffle Channel** (`webhook`) — targets Shuffle SOAR, default URL `https://shuffler.io/api/v1/hooks/WEBHOOK_ID`.

### Behavior

- Default channels are created **only on the cluster manager node** during startup.
- The initialization is **idempotent**: channels that already exist are not recreated or overwritten.
- All default channels are created with an **empty access list**, making them visible to all users.
- Each channel has a **fixed ID** (e.g., `default_slack_channel`), so they can be referenced predictably.

### Configuring a default channel

To activate a default channel:

1. Retrieve the channel configuration using the [List Notification Configs](api.md) API or through the Wazuh Dashboard.
2. Update the channel with your real credentials (webhook URL, API keys, headers, etc.).
3. Set `is_enabled` to `true`.

For example, to configure the Slack channel:

```bash
curl -sk -u admin:admin -X PUT \
  "https://localhost:9200/_plugins/_notifications/configs/default_slack_channel" \
  -H 'Content-Type: application/json' \
  -d '{
    "config": {
      "name": "Slack Channel",
      "description": "Production Slack notifications",
      "config_type": "slack",
      "is_enabled": true,
      "slack": {
        "url": "https://hooks.slack.com/services/T0123/B0456/xyzSecretToken"
      }
    }
  }'
```

> **Note:** A sample alerting monitor is created alongside these channels. Review it under **Alerting > Monitors** in the Wazuh Dashboard before enabling alerts.

## Dependencies

This plugin has a dependency on the [wazuh-indexer-common-utils](https://github.com/wazuh/wazuh-indexer-common-utils) repository. It uses the Common Utils jar to provide shared utility functions and common components required for plugin functionality.
