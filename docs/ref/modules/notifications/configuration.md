## Notifications settings

The Notifications plugin is configured through settings in `opensearch.yml` and cluster-level dynamic settings. The plugin also supports default values from a YAML configuration file bundled with the plugin.

### Configuration files

On startup, the plugin loads default settings from:

- **Core defaults:** `/etc/wazuh-indexer/wazuh-indexer-notifications-core/notifications-core.yml`
- **Plugin defaults:** `/etc/wazuh-indexer/wazuh-indexer-notifications/notifications.yml`

These files provide initial values that can be overridden by settings in `opensearch.yml` or through the cluster settings API.

---

### Core settings (`opensearch.notifications.core.*`)

These settings control the core notification delivery engine.

#### Email settings

- **`opensearch.notifications.core.email.size_limit`** (Integer, default `10000000` / 10 MB, minimum `10000` / 10 KB) — maximum total size of an email message including attachments.
- **`opensearch.notifications.core.email.minimum_header_length`** (Integer, default `160`) — minimum header length for email messages. Used to calculate available body size.

#### HTTP connection settings

- **`opensearch.notifications.core.http.max_connections`** (Integer, default `60`) — maximum number of simultaneous HTTP connections for webhooks.
- **`opensearch.notifications.core.http.max_connection_per_route`** (Integer, default `20`) — maximum HTTP connections per destination route.
- **`opensearch.notifications.core.http.connection_timeout`** (Integer, default `5000`) — HTTP connection timeout in milliseconds.
- **`opensearch.notifications.core.http.socket_timeout`** (Integer, default `50000`) — HTTP socket timeout in milliseconds.
- **`opensearch.notifications.core.http.host_deny_list`** (List\<String\>, default `[]`) — list of denied hosts. Webhook destinations targeting these hosts will be blocked. Inherits from legacy `plugins.destination.host.deny_list` if not set.

#### General core settings

- **`opensearch.notifications.core.max_http_response_size`** (Integer, default same as `http.max_content_length`) — maximum allowed HTTP response size in bytes. Protects against oversized responses from webhook endpoints.
- **`opensearch.notifications.core.allowed_config_types`** (List\<String\>, default `["slack", "chime", "microsoft_teams", "webhook", "email", "sns", "ses_account", "smtp_account", "email_group"]`) — list of channel types that users are allowed to create. Remove a type from this list to disable it cluster-wide.
- **`opensearch.notifications.core.tooltip_support`** (Boolean, default `true`) — enable or disable tooltip support in the Dashboard UI.

---

### Plugin settings (`opensearch.notifications.*`)

These settings control the plugin's general behavior.

- **`opensearch.notifications.general.operation_timeout_ms`** (Long, default `60000`, minimum `100`) — timeout in milliseconds for internal operations (index reads/writes).
- **`opensearch.notifications.general.default_items_query_count`** (Integer, default `100`, minimum `10`) — default number of items returned per query when not specified.
- **`opensearch.notifications.general.filter_by_backend_roles`** (Boolean, default `false`) — when `true`, users can only see notification configurations created by users who share the same backend role. Inherits from `plugins.alerting.filter_by_backend_roles` if not set.

---

### Email destination secure settings

SMTP and SES credentials are stored securely in the **OpenSearch Keystore** rather than in plain text configuration files.

#### SMTP account credentials

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

### Example configuration

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

### Dynamic settings update

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
