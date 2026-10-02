## Notifications settings

The Notifications plugin is configured through settings in `opensearch.yml` and cluster-level dynamic settings. The plugin also supports default values from a YAML configuration file bundled with the plugin.

Settings marked **dynamic** can be changed at runtime through the cluster settings API (see [Dynamic settings update](#dynamic-settings-update)). Settings marked **static** are read from `opensearch.yml` when the node starts, so changing them requires a node restart.

### Configuration files

On startup, the plugin loads default settings from:

- **Core defaults:** `/etc/wazuh-indexer/wazuh-indexer-notifications-core/notifications-core.yml`
- **Plugin defaults:** `/etc/wazuh-indexer/wazuh-indexer-notifications/notifications.yml`

These files provide initial values that can be overridden by settings in `opensearch.yml` or through the cluster settings API.

The `host_deny_list` and `allowed_config_types` keys of `notifications-core.yml` are not read: the defaults of those two settings are built into the plugin, so the shipped `host_deny_list: []` does not empty the deny list. Set them in `opensearch.yml` or through the cluster settings API instead.

---

### Core settings (`opensearch.notifications.core.*`)

These settings control the core notification delivery engine.

#### Email settings

- **`opensearch.notifications.core.email.size_limit`** (Integer, default `10000000` / 10 MB, minimum `10000` / 10 KB, dynamic) — maximum total size of an email message including attachments.
- **`opensearch.notifications.core.email.minimum_header_length`** (Integer, default `160`, dynamic) — minimum header length for email messages. Used to calculate available body size.

#### HTTP connection settings

The HTTP settings apply to the webhook-based channels (`slack`, `chime`, `microsoft_teams` and `webhook`), not to email. The plugin builds its HTTP client once, the first time it sends a notification after the node starts, using the values of `max_connections`, `max_connection_per_route`, `connection_timeout` and `socket_timeout` in effect at that moment. The cluster settings API accepts changes to these four settings, but they only take effect after a node restart.

- **`opensearch.notifications.core.http.max_connections`** (Integer, default `60`, dynamic, applied after a restart) — maximum number of simultaneous HTTP connections for webhooks.
- **`opensearch.notifications.core.http.max_connection_per_route`** (Integer, default `20`, dynamic, applied after a restart) — maximum HTTP connections per destination route.
- **`opensearch.notifications.core.http.connection_timeout`** (Integer, default `5000`, dynamic, applied after a restart) — HTTP connection timeout in milliseconds.
- **`opensearch.notifications.core.http.socket_timeout`** (Integer, default `50000`, dynamic, applied after a restart) — HTTP socket timeout in milliseconds.
- **`opensearch.notifications.core.http.host_deny_list`** (List\<String\>, default: the reserved ranges listed below, dynamic) — hosts and IP ranges that webhook-based channels cannot send to. A message to a matching host fails with `Host of url is denied, based on plugin setting [notification.core.http.host_deny_list]`. Email, SES and SNS deliveries are not checked. A value you set replaces the whole default list, so include every range that must stay blocked. If not set, inherits the legacy `plugins.destination.host.deny_list` setting when that one is set in `opensearch.yml`. By default, the list blocks loopback, link-local (including the cloud instance metadata endpoint `169.254.169.254`), private and other reserved addresses, so webhooks to hosts on an internal network are denied:

  `127.0.0.0/8`, `169.254.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `0.0.0.0/8`, `100.64.0.0/10`, `192.0.0.0/24`, `192.0.2.0/24`, `198.18.0.0/15`, `192.88.99.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4`, `240.0.0.0/4`, `255.255.255.255/32`, `::1/128`, `fe80::/10`, `fc00::/7`, `::/128`, `2001:db8::/32`, `ff00::/8`.

#### General core settings

- **`opensearch.notifications.core.max_http_response_size`** (Integer, default `104857600` / 100 MB, the default of `http.max_content_length`, dynamic) — maximum allowed HTTP response size in bytes. Protects against oversized responses from webhook endpoints.
- **`opensearch.notifications.core.allowed_config_types`** (List\<String\>, default `["slack", "chime", "microsoft_teams", "webhook", "email", "sns", "ses_account", "smtp_account", "email_group", "active_response"]`, dynamic) — channel types the plugin advertises through [`GET /_plugins/_notifications/features`](api.md#get-plugin-features). Clients such as the Wazuh Dashboard read this list to decide which channel types to offer, so removing `active_response` hides the channel type that [Active Response](../alerting/index.md#active-response) monitors send through from the Dashboard. The REST API does not enforce the list: configurations of a type missing from it can still be created and used.
- **`opensearch.notifications.core.tooltip_support`** (Boolean, default `true`, dynamic) — enable or disable tooltip support in the Dashboard UI.

---

### Plugin settings (`opensearch.notifications.*`)

These settings control the plugin's general behavior.

- **`opensearch.notifications.general.operation_timeout_ms`** (Long, default `60000`, minimum `100`, dynamic) — timeout in milliseconds for internal operations (index reads/writes).
- **`opensearch.notifications.general.default_items_query_count`** (Integer, default `100`, minimum `10`, dynamic) — default number of items returned per query when not specified.
- **`opensearch.notifications.general.filter_by_backend_roles`** (Boolean, default `false`, dynamic) — when `true`, users can only see notification configurations created by users who share the same backend role. Inherits from `plugins.alerting.filter_by_backend_roles` if not set.
- **`opensearch.notifications.active_response.bulk_flush_interval_ms`** (Long, default `500`, minimum `100`, static) — maximum time, in milliseconds, that queued Active Response documents wait before the plugin bulk-writes them to the `wazuh-active-responses` data stream.
- **`opensearch.notifications.active_response.bulk_max_actions`** (Integer, default `1000`, minimum `1`, static) — number of queued Active Response documents that triggers a bulk write before the flush interval elapses.

---

### Resource creation limits (`plugins.notifications.*`)

These settings cap how many notification configuration documents can exist, to bound resource usage. All are dynamic. Creation requests that would exceed a limit are rejected with HTTP 400; existing configurations are unaffected when a limit is lowered.

- **`plugins.notifications.max_notification_configs`** (Integer, default `40`, minimum `0`, no upper bound, dynamic) — global cap on the total number of notification configuration documents of any type (channels, groups, senders, and active responses all count against this shared limit).
- **`plugins.notifications.max_notification_groups`** (Integer, default `10`, minimum `0`, no upper bound, dynamic) — cap on the number of `email_group` configurations. Counts against, and in addition to, `max_notification_configs`.
- **`plugins.notifications.max_notification_senders`** (Integer, default `5`, minimum `0`, no upper bound, dynamic) — cap on the number of `smtp_account` and `ses_account` configurations combined. Counts against, and in addition to, `max_notification_configs`.
- **`plugins.notifications.max_active_responses`** (Integer, default `10`, minimum `0`, no upper bound, dynamic) — cap on the number of `active_response` configurations. Counts against, and in addition to, `max_notification_configs`.

> **Note:** These are separate from `opensearch.notifications.general.default_items_query_count` and other `general.*` settings above — they live under a distinct `plugins.notifications.*` prefix.

---

### Email destination secure settings

SMTP credentials are stored securely in the **Wazuh Indexer keystore** rather than in plain text configuration files. SES and SNS channels do not use the keystore: they authenticate with the AWS default credentials chain, optionally assuming the IAM role set in the channel's `role_arn`.

#### SMTP account credentials

The account name in the keystore key is the `name` of the `smtp_account` configuration. To configure credentials for an `smtp_account` named `my_smtp_account`, run the following commands on every node. Each command prompts for the value.

```bash
# Add SMTP username
sudo -u wazuh-indexer /usr/share/wazuh-indexer/bin/opensearch-keystore add opensearch.notifications.core.email.my_smtp_account.username

# Add SMTP password
sudo -u wazuh-indexer /usr/share/wazuh-indexer/bin/opensearch-keystore add opensearch.notifications.core.email.my_smtp_account.password
```

Run `opensearch-keystore` as the `wazuh-indexer` user, as shown. Run as `root`, it leaves `/etc/wazuh-indexer/opensearch.keystore` owned by `root:root`, which the Wazuh Indexer cannot read: reloading the keystore fails with `access_denied_exception` and the Wazuh Indexer fails to start. To recover, run `sudo chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/opensearch.keystore`.

The credentials are reloadable secure settings. Apply them without a restart by reloading the keystore on every node:

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X POST \
  "https://127.0.0.1:9200/_nodes/reload_secure_settings"
```

Set both the username and the password. If either is missing, the plugin connects to the SMTP server without authenticating.

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

# Channel types advertised to clients such as the Wazuh Dashboard
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
  - active_response

# Plugin settings
opensearch.notifications.general.operation_timeout_ms: 60000
opensearch.notifications.general.default_items_query_count: 100
opensearch.notifications.general.filter_by_backend_roles: false

# Active Response bulk indexing (static)
opensearch.notifications.active_response.bulk_flush_interval_ms: 500
opensearch.notifications.active_response.bulk_max_actions: 1000

# Resource creation limits
plugins.notifications.max_notification_configs: 40
plugins.notifications.max_notification_groups: 10
plugins.notifications.max_notification_senders: 5
plugins.notifications.max_active_responses: 10
```

---

### Dynamic settings update

Settings marked as dynamic can be updated at runtime through the cluster settings API:

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X PUT \
  "https://127.0.0.1:9200/_cluster/settings" \
  -H 'Content-Type: application/json' \
  -d '{
    "persistent": {
      "opensearch.notifications.core.email.size_limit": 20000000,
      "opensearch.notifications.general.filter_by_backend_roles": true,
      "plugins.notifications.max_notification_configs": 20
    }
  }'
```

Static settings are rejected with `not dynamically updateable`; set them in `opensearch.yml` and restart the node.
