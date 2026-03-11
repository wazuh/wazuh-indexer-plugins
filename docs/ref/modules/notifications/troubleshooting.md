# Troubleshooting

Common issues and solutions when working with the Notifications plugin.

---

## Channel Configuration Issues

### Slack notifications are not delivered

**Symptoms:** Creating a Slack config succeeds, but test notifications fail with a non-200 status.

**Possible causes:**

1. **Invalid webhook URL.** Verify the Incoming Webhook URL is active in your Slack workspace settings.
2. **Host deny list.** Check if the Slack domain is included in `opensearch.notifications.core.http.host_deny_list`.
3. **Network connectivity.** The Wazuh Indexer node must have outbound HTTPS access to `hooks.slack.com`.

**Resolution:**

```bash
# Verify the config
curl -sk -u admin:admin \
  "https://localhost:9200/_plugins/_notifications/configs/<config-id>"

# Send a test notification
curl -sk -u admin:admin -X POST \
  "https://localhost:9200/_plugins/_notifications/feature/test/<config-id>"
```

Check the `delivery_status` in the response for the HTTP status code and error message.

---

### Email delivery fails with timeout

**Symptoms:** Email notifications fail with connection timeout errors.

**Possible causes:**

1. **SMTP server unreachable.** Verify the Wazuh Indexer node can reach the SMTP server on the configured port.
2. **Timeout too short.** The default connection timeout is 5000 ms and socket timeout is 50000 ms. Increase if needed.
3. **TLS configuration mismatch.** Ensure the SMTP `method` (none, ssl, start_tls) matches the server's requirements.

**Resolution:**

```bash
# Increase timeouts via cluster settings
curl -X PUT "https://localhost:9200/_cluster/settings" \
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

**Symptoms:** Email delivery fails with "Credential not found for account" error.

**Resolution:** SMTP credentials must be stored in the OpenSearch Keystore, not in `opensearch.yml`.

```bash
bin/opensearch-keystore add opensearch.notifications.core.email.<account_name>.username
bin/opensearch-keystore add opensearch.notifications.core.email.<account_name>.password
```

Restart the node after adding keystore entries.

---

## Permission Issues

### "User doesn't have backend roles configured"

**Symptoms:** API calls return 403 Forbidden with the message "User doesn't have backend roles configured."

**Cause:** The setting `opensearch.notifications.general.filter_by_backend_roles` is `true`, but the current user has no backend roles assigned.

**Resolution:**

- Assign backend roles to the user in the Security plugin, or
- Disable RBAC filtering:

```bash
curl -X PUT "https://localhost:9200/_cluster/settings" \
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

## HTTP Response Size Limit

### "HTTP response too large" error

**Symptoms:** Webhook notifications to endpoints that return large responses fail.

**Cause:** The response from the webhook destination exceeds `opensearch.notifications.core.max_http_response_size`.

**Resolution:**

```bash
curl -X PUT "https://localhost:9200/_cluster/settings" \
  -H 'Content-Type: application/json' \
  -d '{
    "persistent": {
      "opensearch.notifications.core.max_http_response_size": 20971520
    }
  }'
```

---

## Plugin Stats

To inspect the plugin's internal metrics and check for anomalies:

```bash
curl -sk -u admin:admin \
  "https://localhost:9200/_plugins/_notifications/_local/stats"
```

This returns counters for all API operations, which can help identify whether requests are reaching the plugin.

---

## Logs

Enable debug logging for the Notifications plugin:

```bash
curl -X PUT "https://localhost:9200/_cluster/settings" \
  -H 'Content-Type: application/json' \
  -d '{
    "persistent": {
      "logger.org.opensearch.notifications": "DEBUG",
      "logger.org.opensearch.notifications.core": "DEBUG"
    }
  }'
```

Check the Wazuh Indexer logs for entries prefixed with `notifications:`.
