# Troubleshooting

Common issues and solutions when working with the Notifications plugin.

---

## Channel configuration issues

### Slack notifications are not delivered

**Symptoms:** Creating a Slack config succeeds, but test notifications fail with a non-200 status.

#### Possible causes

1. **Invalid webhook URL.** Verify the Incoming Webhook URL is active in your Slack workspace settings.
2. **Host deny list.** Check if the Slack domain is included in `opensearch.notifications.core.http.host_deny_list`.
3. **Network connectivity.** The Wazuh Indexer node must have outbound HTTPS access to `hooks.slack.com`.

#### Resolution

```bash
# Verify the config
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD \
  "https://127.0.0.1:9200/_plugins/_notifications/configs/<config-id>"

# Send a test notification
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X POST \
  "https://127.0.0.1:9200/_plugins/_notifications/feature/test/<config-id>"
```

Check the `delivery_status` in the response for the HTTP status code and error message.

---

### Webhook to an internal host is denied

**Symptoms:** A webhook-based channel (Slack, Chime, Microsoft Teams or custom webhook) that targets a host on your network fails with status `400` and `Host of url is denied, based on plugin setting [notification.core.http.host_deny_list]`.

**Cause:** By default, `opensearch.notifications.core.http.host_deny_list` blocks loopback, link-local, private and other reserved address ranges, so webhooks to internal services, such as a self-hosted Jira or Shuffle instance, are denied. See [HTTP connection settings](configuration.md#http-connection-settings) for the full default list.

#### Resolution

Set the deny list without the range your endpoint is in. The value replaces the whole default list, so keep every other range. For example, to allow `192.168.0.0/16`:

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X PUT \
  "https://127.0.0.1:9200/_cluster/settings" \
  -H 'Content-Type: application/json' \
  -d '{
    "persistent": {
      "opensearch.notifications.core.http.host_deny_list": [
        "127.0.0.0/8", "169.254.0.0/16", "10.0.0.0/8", "172.16.0.0/12",
        "0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
        "198.18.0.0/15", "192.88.99.0/24", "198.51.100.0/24", "203.0.113.0/24",
        "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
        "::1/128", "fe80::/10", "fc00::/7", "::/128", "2001:db8::/32", "ff00::/8"
      ]
    }
  }'
```

---

### Email delivery fails with a connection error

**Symptoms:** Email notifications fail with status `503` and `Couldn't connect to host`, or take a long time to fail.

#### Possible causes

1. **SMTP server unreachable.** Verify the Wazuh Indexer node can reach the SMTP server on the configured port.
2. **TLS configuration mismatch.** Ensure the SMTP `method` (none, ssl, start_tls) matches the server's requirements.

The `opensearch.notifications.core.http.*` timeouts do not apply to email: they control only webhook-based channels. The plugin sets no timeout on SMTP connections, so an unresponsive server can hold up the delivery for a long time.

---

### Webhook delivery fails with timeout

**Symptoms:** Notifications to a webhook-based channel fail with a timeout error.

**Cause:** The endpoint takes longer to accept the connection or to answer than the configured timeouts allow. The defaults are 5000 ms to connect and 50000 ms to wait for the response.

#### Resolution

Increase the timeouts, then restart the Wazuh Indexer on every node. The plugin builds its HTTP client once, the first time it sends a notification after the node starts, so a new timeout only takes effect after a restart.

```bash
# Increase timeouts via cluster settings
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X PUT \
  "https://127.0.0.1:9200/_cluster/settings" \
  -H 'Content-Type: application/json' \
  -d '{
    "persistent": {
      "opensearch.notifications.core.http.connection_timeout": 10000,
      "opensearch.notifications.core.http.socket_timeout": 120000
    }
  }'
```

---

### SMTP credentials not found

**Symptoms:** Email delivery to an SMTP server that requires authentication fails with an authentication error from the server.

**Cause:** The keystore holds no username and password for the account, so the plugin connects without authenticating. The account name in the keystore key must match the `name` of the `smtp_account` configuration, and both the username and the password must be set.

#### Resolution

SMTP credentials must be stored in the Wazuh Indexer keystore, not in `opensearch.yml`. On every node, add them as the `wazuh-indexer` user. Running `opensearch-keystore` as `root` leaves the keystore unreadable by the Wazuh Indexer, which then fails to start.

```bash
sudo -u wazuh-indexer /usr/share/wazuh-indexer/bin/opensearch-keystore add opensearch.notifications.core.email.<account_name>.username
sudo -u wazuh-indexer /usr/share/wazuh-indexer/bin/opensearch-keystore add opensearch.notifications.core.email.<account_name>.password
```

Then reload the keystore. No restart is needed:

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X POST \
  "https://127.0.0.1:9200/_nodes/reload_secure_settings"
```

If the reload reports `access_denied_exception`, the keystore is owned by `root`. Run `sudo chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/opensearch.keystore` and reload again. See [Email destination secure settings](configuration.md#email-destination-secure-settings).

---

## Permission issues

### "User doesn't have backend roles configured"

**Symptoms:** API calls return 403 Forbidden with the message "User doesn't have backend roles configured."

**Cause:** The setting `opensearch.notifications.general.filter_by_backend_roles` is `true`, but the current user has no backend roles assigned.

#### Resolution

- Assign backend roles to the user in the Security plugin, or
- Disable RBAC filtering:

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X PUT \
  "https://127.0.0.1:9200/_cluster/settings" \
  -H 'Content-Type: application/json' \
  -d '{
    "persistent": {
      "opensearch.notifications.general.filter_by_backend_roles": false
    }
  }'
```

---

### User cannot see other users' configurations

**Cause:** When `filter_by_backend_roles` is enabled, users can only see configurations created by users who share at least one backend role. Users with the `all_access` role can see all configurations.

---

## HTTP response size limit

### Webhook response is truncated

**Symptoms:** The `status_text` of a webhook-based delivery holds only the beginning of the endpoint's response.

**Cause:** The plugin reads at most half of `opensearch.notifications.core.max_http_response_size`, counted in characters, from a webhook response and drops the rest. The delivery itself still succeeds.

#### Resolution

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X PUT \
  "https://127.0.0.1:9200/_cluster/settings" \
  -H 'Content-Type: application/json' \
  -d '{
    "persistent": {
      "opensearch.notifications.core.max_http_response_size": 209715200
    }
  }'
```

---

## Logs

Enable debug logging for the Notifications plugin:

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X PUT \
  "https://127.0.0.1:9200/_cluster/settings" \
  -H 'Content-Type: application/json' \
  -d '{
    "persistent": {
      "logger.org.opensearch.notifications": "DEBUG",
      "logger.org.opensearch.notifications.core": "DEBUG"
    }
  }'
```

Check the Wazuh Indexer logs for entries prefixed with `notifications:`.
