# Notifications

The Wazuh Indexer Notifications plugin is a specialized component designed to extend the Wazuh Indexer (based on OpenSearch) with multi-channel notification capabilities. It allows the system to send alerts, reports, and messages via **Email** (SMTP/SES), **Slack**, **Microsoft Teams**, **Amazon Chime**, **Amazon SNS**, and **Custom Webhooks**.

## Key Capabilities

- **Multi-channel delivery:** Send notifications to Slack, Microsoft Teams, Chime, Email (SMTP and AWS SES), AWS SNS, and custom HTTP webhooks.
- **Unified REST API:** Create, update, delete, and query notification channel configurations through a single API surface at `/_plugins/_notifications/`.
- **Test notifications:** Validate channel configuration by sending a test message before relying on it for production alerts.
- **Feature discovery:** Other plugins can query supported notification features dynamically.
- **RBAC integration:** Access to notification configurations is governed by the Wazuh Indexer Security plugin, with backend-role–based filtering.
- **Extensible architecture:** The plugin uses a Service Provider Interface (SPI) pattern, making it straightforward to add new destination types.

## Supported Channel Types

| Channel Type | Protocol | Description |
|---|---|---|
| `slack` | HTTPS (Webhook) | Posts messages to a Slack channel via an Incoming Webhook URL. |
| `chime` | HTTPS (Webhook) | Posts messages to an Amazon Chime room via a webhook URL. |
| `microsoft_teams` | HTTPS (Webhook) | Posts messages to a Microsoft Teams channel via a connector webhook. |
| `webhook` | HTTP/HTTPS | Sends a payload to an arbitrary HTTP endpoint with configurable method, headers, and URL. |
| `email` | SMTP / AWS SES | Sends email messages. Requires an `smtp_account` or `ses_account` configuration. |
| `sns` | AWS SNS SDK | Publishes a message to an Amazon SNS topic. |
| `smtp_account` | — | Defines SMTP server connection details (host, port, method, credentials). |
| `ses_account` | — | Defines AWS SES sending details (region, role ARN, from address). |
| `email_group` | — | Defines a group of email recipients for reuse across email-type channels. |

## Version

The current plugin version is **5.0.0-alpha0** (see `VERSION.json` in the repository root).
