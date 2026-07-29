# Architecture

The Notifications plugin follows a layered architecture that separates destination definitions, transport logic, and plugin orchestration.

## High-level architecture

The Notifications plugin runs inside the Wazuh Indexer and acts as a bridge between internal producers of alerts (such as Alerting, Reporting, and ISM) and external delivery services like SMTP servers, webhooks, and AWS services.

At a high level, the architecture is composed of three main parts:

- **Notification producers (inside the Indexer)**
  Internal plugins such as **Alerting**, **Reporting**, **ISM**, and other Wazuh Indexer components generate alerts and events. When they need to send a notification (for example, a Slack message or an email), they call the **Notifications plugin** either through the **REST API** exposed by the Indexer, or internal transport actions.

- **Notifications plugin (inside the Indexer)**
  The plugin itself is structured in several layers:

  - **REST / Transport layer** — exposes the `/_plugins/_notifications/...` REST endpoints. Receives requests to create, update, list, and delete notification channel configurations, send test notifications, and query features. Validates requests and delegates the work internally.
  - **Security integration** — uses the Security plugin to validate permissions for each request. When `filter_by_backend_roles` is enabled, it filters which notification configurations each user can see or use based on backend roles.
  - **Destination and transport layer** — defines each supported channel type (Slack, Chime, Microsoft Teams, custom webhook, SMTP, SES, SNS) and the corresponding delivery logic. Manages HTTP client pools, connection and socket timeouts, host deny lists, and HTTP response size limits. Retrieves SMTP/SES/SNS credentials from the OpenSearch Keystore or other secure settings.
  - **Persistence and configuration** — stores notification channel configurations in the internal `.notifications` index. Exposes internal metrics through the stats endpoint so operators can inspect request counts and error patterns.

- **External destination services (outside the Indexer)**
  After the plugin resolves the destination type, the corresponding transport sends the message to SMTP servers (corporate mail, Gmail, etc.), webhook endpoints (Slack, Microsoft Teams, Amazon Chime, custom HTTP integrations), or AWS services such as SES and SNS.

  Once delivery is attempted, the plugin updates the notification status (for example, `sent` or `failed`) and returns the outcome to the caller (Alerting, Reporting, or the user calling the REST API).

For the underlying module layout, class hierarchy, and REST handler mapping, see the [development guide](../../../dev/plugins/notifications.md).

## Send notification sequence

The following sequence describes the flow when an internal plugin (e.g., Alerting) sends a notification:

1. The alerting monitor triggers an alert and calls the Notification plugin via the internal transport interface.
2. The Security plugin verifies the caller's permissions.
3. The notification is persisted in the `.notifications` index with status `pending`.
4. The plugin resolves the destination type and delegates to the matching transport (email via SMTP or SES, webhook for Slack/Chime/Teams/custom, or SNS). On failure, retries are attempted up to the configured limit.
5. The delivery status is returned and the notification record is updated to `sent` or `failed`.
6. The calling plugin acknowledges the result and updates its own alert status.

## Configuration management sequence

1. A user (via Dashboard or REST API) creates or updates a notification channel configuration.
2. The configuration is validated and persisted in the `.notifications` index.
3. On retrieval, configurations can be filtered by type, name, status, and other fields.
