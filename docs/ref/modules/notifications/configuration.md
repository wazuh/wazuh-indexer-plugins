# Configuration

The Notifications plugin is configured through settings in `opensearch.yml` and cluster-level dynamic settings. The plugin also supports default values from a YAML configuration file bundled with the plugin.

## Configuration Files

On startup, the plugin loads default settings from:

- **Core defaults:** `<opensearch-config>/opensearch-notifications-core/notifications-core.yml`
- **Plugin defaults:** `<opensearch-config>/opensearch-notifications/notifications.yml`

These files provide initial values that can be overridden by settings in `opensearch.yml` or through the cluster settings API.

---

## Core Settings (`opensearch.notifications.core.*`)

These settings control the core notification delivery engine.

### Email Settings

| Setting | Type | Default | Description |
|---|---|---|---|
| `opensearch.notifications.core.email.size_limit` | Integer | `10000000` (10 MB) | Maximum total size of an email message including attachments. Minimum: `10000` (10 KB). |
| `opensearch.notifications.core.email.minimum_header_length` | Integer | `160` | Minimum header length for email messages. Used to calculate available body size. |

### HTTP Connection Settings

| Setting | Type | Default | Description |
|---|---|---|---|
| `opensearch.notifications.core.http.max_connections` | Integer | `60` | Maximum number of simultaneous HTTP connections for webhooks. |
| `opensearch.notifications.core.http.max_connection_per_route` | Integer | `20` | Maximum HTTP connections per destination route. |
| `opensearch.notifications.core.http.connection_timeout` | Integer | `5000` | HTTP connection timeout in milliseconds. |
| `opensearch.notifications.core.http.socket_timeout` | Integer | `50000` | HTTP socket timeout in milliseconds. |
| `opensearch.notifications.core.http.host_deny_list` | List\<String\> | `[]` | List of denied hosts. Webhook destinations targeting these hosts will be blocked. Inherits from legacy `plugins.destination.host.deny_list` if not set. |

### General Core Settings

| Setting | Type | Default | Description |
|---|---|---|---|
| `opensearch.notifications.core.max_http_response_size` | Integer | Same as `http.max_content_length` | Maximum allowed HTTP response size in bytes. Protects against oversized responses from webhook endpoints. |
| `opensearch.notifications.core.allowed_config_types` | List\<String\> | `["slack", "chime", "microsoft_teams", "webhook", "email", "sns", "ses_account", "smtp_account", "email_group"]` | List of channel types that users are allowed to create. Remove a type from this list to disable it cluster-wide. |
| `opensearch.notifications.core.tooltip_support` | Boolean | `true` | Enable or disable tooltip support in the Dashboard UI. |

---

## Plugin Settings (`opensearch.notifications.*`)

These settings control the plugin's general behavior.

| Setting | Type | Default | Description |
|---|---|---|---|
| `opensearch.notifications.general.operation_timeout_ms` | Long | `60000` | Timeout in milliseconds for internal operations (index reads/writes). Minimum: `100`. |
| `opensearch.notifications.general.default_items_query_count` | Integer | `100` | Default number of items returned per query when not specified. Minimum: `10`. |
| `opensearch.notifications.general.filter_by_backend_roles` | Boolean | `false` | When `true`, users can only see notification configurations created by users who share the same backend role. Inherits from `plugins.alerting.filter_by_backend_roles` if not set. |

---

## Email Destination Secure Settings

SMTP and SES credentials are stored securely in the **OpenSearch Keystore** rather than in plain text configuration files.

### SMTP Account Credentials

To configure SMTP credentials for an email account named `my_smtp_account`:

```bash
# Add SMTP username
bin/opensearch-keystore add opensearch.notifications.core.email.my_smtp_account.username

# Add SMTP password
bin/opensearch-keystore add opensearch.notifications.core.email.my_smtp_account.password
```

The secure setting key prefix is `opensearch.notifications.core.email.<account_name>.username` and `opensearch.notifications.core.email.<account_name>.password`.

> **Note:** Legacy settings from Alerting (`plugins.alerting.destination.email.<account_name>.*`) are also supported as fallback.

---

## Example Configuration

A minimal `opensearch.yml` configuration for the Notifications plugin:

```yaml
# Notification core settings
opensearch.notifications.core.email.size_limit: 10000000
opensearch.notifications.core.http.max_connections: 60
opensearch.notifications.core.http.connection_timeout: 5000
opensearch.notifications.core.http.socket_timeout: 50000
opensearch.notifications.core.http.host_deny_list:
  - "10.0.0.0/8"
  - "172.16.0.0/12"

# Allowed channel types (remove a type to disable it)
opensearch.notifications.core.allowed_config_types:
  - slack
  - chime
  - microsoft_teams
  - webhook
  - email
  - sns
  - ses_account
  - smtp_account
  - email_group

# Plugin settings
opensearch.notifications.general.operation_timeout_ms: 60000
opensearch.notifications.general.default_items_query_count: 100
opensearch.notifications.general.filter_by_backend_roles: false
```

---

## Dynamic Settings Update

All settings marked as `Dynamic` can be updated at runtime through the cluster settings API:

```bash
curl -X PUT "https://localhost:9200/_cluster/settings" \
  -H 'Content-Type: application/json' \
  -d '{
    "persistent": {
      "opensearch.notifications.core.http.max_connections": 100,
      "opensearch.notifications.general.filter_by_backend_roles": true
    }
  }'
```
