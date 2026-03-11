# Architecture

The Notifications plugin follows a layered architecture that separates destination definitions, transport logic, and plugin orchestration.

## High-Level Architecture

The Notifications plugin runs inside the Wazuh Indexer and acts as a bridge between internal producers of alerts (such as Alerting, Reporting, and ISM) and external delivery services like SMTP servers, webhooks, and AWS services.

At a high level, the architecture is composed of three main parts:

- **Notification producers (inside the Indexer)**  
  Internal plugins such as **Alerting**, **Reporting**, **ISM**, and other Wazuh Indexer components generate alerts and events.  
  When they need to send a notification (for example, a Slack message or an email), they call the **Notifications plugin** either through:
  - The **REST API** exposed by the Indexer, or
  - Internal **transport actions**.

- **Notifications plugin (inside the Indexer)**  
  The plugin itself is structured in several layers:

  - **REST / Transport layer**  
    - Exposes the `/_plugins/_notifications/...` REST endpoints.  
    - Receives requests to create, update, list, and delete notification channel configurations, send test notifications, and query features.  
    - Validates requests and delegates the work to internal transport actions.

  - **Security integration**  
    - Uses the **Security plugin** to validate permissions for each request.  
    - When `filter_by_backend_roles` is enabled, it filters which notification configurations each user can see or use based on backend roles.

  - **Core SPI layer**  
    - Defines common contracts and models such as `NotificationCore`, `BaseDestination`, and concrete destination types like `SlackDestination`, `SmtpDestination`, `SesDestination`, and `SnsDestination`.  
    - Encapsulates message content (`MessageContent`) and delivery responses (`DestinationMessageResponse`).

  - **Core implementation (transport logic)**  
    - Implements concrete transports:
      - `WebhookDestinationTransport` for Slack, Microsoft Teams, Chime, and generic webhooks (HTTP/HTTPS).
      - `SmtpDestinationTransport` for email via SMTP.
      - `SesDestinationTransport` for email via AWS SES.
      - `SnsDestinationTransport` for messages via AWS SNS.  
    - Manages HTTP client pools, connection and socket timeouts, host deny lists, and HTTP response size limits.  
    - Retrieves SMTP/SES/SNS credentials from the OpenSearch Keystore or other secure settings via a credential provider.

  - **Persistence and configuration**  
    - Stores notification channel configurations in an internal index (for example, `.notifications`).  
    - Uses `NotificationConfigIndex` and `ConfigIndexingActions` to create, read, update, and delete configurations.  
    - Exposes internal metrics through the stats endpoint so operators can inspect request counts and error patterns.

- **External destination services (outside the Indexer)**  
  After the plugin resolves the destination type, the corresponding transport sends the message to:
  - **SMTP servers** (corporate mail, Gmail, etc.),
  - **Webhook endpoints** (Slack, Microsoft Teams, Amazon Chime, custom HTTP integrations),
  - **AWS services** such as SES and SNS.  

  Once delivery is attempted, the plugin updates the notification status (for example, `sent` or `failed`) and returns the outcome to the caller (Alerting, Reporting, or the user calling the REST API).

## Plugin Layers

### 1. Core SPI (`core-spi`)

The **Service Provider Interface** layer defines the contracts and models:

- **`NotificationCore`**: Interface that the core implementation must satisfy. Defines `sendMessage()` and related operations.
- **`BaseDestination`**: Abstract base class for all destination types. Subclasses include `SlackDestination`, `ChimeDestination`, `MicrosoftTeamsDestination`, `CustomWebhookDestination`, `SmtpDestination`, `SesDestination`, and `SnsDestination`.
- **`MessageContent`**: Encapsulates the notification message (title, text body, HTML body, attachment).
- **`DestinationMessageResponse`**: Standard response from any delivery attempt (status code, response body).

### 2. Core Implementation (`core`)

The **Core** layer provides the actual delivery logic:

- **Transport Providers:**
  - `WebhookDestinationTransport` — handles Slack, Chime, Microsoft Teams, and custom webhook delivery via HTTP POST.
  - `SmtpDestinationTransport` — sends emails using SMTP protocol (supports STARTTLS/SSL).
  - `SesDestinationTransport` — sends emails via the AWS SES SDK.
  - `SnsDestinationTransport` — publishes messages to AWS SNS topics.

- **HTTP Client Pool:** `DestinationClientPool` manages a pool of `DestinationHttpClient` instances with configurable connection limits, timeouts, and host deny lists.

- **Credential Management:** The `CredentialsProvider` abstraction loads SMTP/SES/SNS credentials from the OpenSearch Keystore or from secure settings.

- **Plugin Settings (`PluginSettings`):** All tunable parameters — email size limits, connection pools, timeouts, allowed config types, host deny lists — are centralized here and dynamically updatable via cluster settings.

### 3. Notification Plugin (`notifications`)

The **Plugin** module ties everything together:

- **REST Handlers:** Map HTTP requests to internal transport actions (see [API Reference](api.md)).
- **Transport Actions:** Asynchronous action classes (`CreateNotificationConfigAction`, `DeleteNotificationConfigAction`, `GetNotificationConfigAction`, `UpdateNotificationConfigAction`, `SendNotificationAction`, `SendTestNotificationAction`, `GetPluginFeaturesAction`, `GetChannelListAction`, `PublishNotificationAction`).
- **Index Operations:** `NotificationConfigIndex` manages the `.notifications` index for storing channel configurations. `ConfigIndexingActions` handles create/read/update/delete operations on the index.
- **Metrics:** The `Metrics` class tracks counters for all API operations (create, update, delete, info, features, channels, send test).
- **Security:** `UserAccessManager` enforces RBAC based on backend roles when `filter_by_backend_roles` is enabled.

## Send Notification Sequence

The following sequence describes the flow when an internal plugin (e.g., Alerting) sends a notification:

1. The **Alerting Monitor** triggers an alert and calls the Notification plugin via the **Transport Interface**.
2. The **Security Plugin** verifies the caller's permissions.
3. The notification is **persisted** in the notifications index with status `pending/in-progress`.
4. The plugin resolves the destination type and delegates to the appropriate transport:
   - **Email:** `SmtpDestinationTransport` or `SesDestinationTransport` sends the email. On failure, retries up to the configured limit.
   - **Webhook:** `WebhookDestinationTransport` sends the HTTP request to Slack, Chime, Teams, or a custom endpoint.
   - **SNS:** `SnsDestinationTransport` publishes to the SNS topic.
5. The delivery status is returned and the notification record is updated.
6. The **Alerting plugin** acknowledges the result and updates the alert status.

## Configuration Management Sequence

1. A user (via Dashboard or REST API) creates or updates a notification channel configuration.
2. The request is routed to `NotificationConfigRestHandler`.
3. The configuration is validated and persisted in the `.notifications` index.
4. On retrieval, configurations can be filtered by type, name, status, and other fields.
