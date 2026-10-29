# Audit logs

The security plugin records security-relevant activity as audit events: failed logins, requests denied for missing privileges, and changes to the security configuration (users, roles, role mappings, action groups and the rest of the security index). Wazuh Indexer stores these events as documents in the `security-auditlog` data stream.

## Where the events are stored

The packaged `/etc/wazuh-indexer/opensearch.yml` sends audit events to the `security-auditlog` data stream:

```yaml
plugins.security.audit.type: internal_opensearch_data_stream
plugins.security.audit.config.data_stream.name: security-auditlog
```

The Setup plugin creates the data stream and its index template at startup, and manages it with the `security-auditlog-policy` ISM policy: the backing index rolls over daily and each one is deleted at 7 days of age. See [Retention](../modules/setup/retention.md) to keep the events for a different period.

Only users with access to the `security-auditlog` data stream can read the events. By default that is the `admin` user (`all_access`). The data stream name is deliberately outside `wazuh-*`, which the Wazuh Dashboard reads on behalf of every dashboard user.

<div class="warning">

`plugins.security.audit.type` is a static node setting. Without it, the security plugin has nowhere to write audit events and drops them, even though the dashboard's **Audit logs** page shows audit logging as enabled.

</div>

## Viewing the events

In the Wazuh Dashboard, create an index pattern for `security-auditlog*` with `@timestamp` as the time field, and open it in **Discover**. The [`stateless/security-auditlog`](https://github.com/wazuh/wazuh-indexer-plugins/blob/main/wcs/stateless/security-auditlog/docs/fields.csv) WCS module describes every mapped field. Useful fields:

| Field | Content |
| --- | --- |
| `audit_category` | Event type, for example `FAILED_LOGIN`, `MISSING_PRIVILEGES` or `COMPLIANCE_INTERNAL_CONFIG_WRITE`. |
| `audit_request_effective_user` | User the request ran as. |
| `audit_request_remote_address` | Address the request came from. |
| `audit_rest_request_method`, `audit_rest_request_path` | REST request that produced the event. |
| `audit_request_privilege` | Permission that was checked, on `MISSING_PRIVILEGES` events. |
| `audit_trace_resolved_indices` | Indices the request touched. |
| `audit_request_body` | Request body, or the changed security configuration document. Passwords sent to the security REST API are replaced with `__SENSITIVE__`, and password hashes with `__HASH__`. |

## Which events are recorded

The audit configuration is stored in the security index and can be changed at runtime on the dashboard's **Audit logs** page, or in `/etc/wazuh-indexer/opensearch-security/audit.yml` followed by `securityadmin.sh`. The shipped defaults are:

- REST and transport auditing enabled, except for the `AUTHENTICATED` and `GRANTED_PRIVILEGES` categories. Those two record every successful request, including each request the dashboard makes for a logged-in user, and would fill a small deployment's disk.
- Index administration requests, including reads of index templates, mappings and data streams, are recorded as `INDEX_EVENT`. A tool that polls those APIs with an administrative user adds one event per call.
- The `kibanaserver` user, used by the Wazuh Dashboard for its own requests, is ignored.
- Compliance auditing of the security configuration (`internal_config`) enabled: every change to users, roles, role mappings and the rest of the security index is recorded with the user who made it.

To record successful logins too, enable the `AUTHENTICATED` category, and check the size of the backing indices with `GET _cat/indices/.ds-security-auditlog-*?v` before keeping it on.

## Enabling audit logs on an existing installation

Package upgrades keep the installed `opensearch.yml`, so installations created before this setting was shipped don't store audit events. The upgraded Setup plugin already creates the `security-auditlog` data stream and its retention policy; only the node setting is missing.

1. On every node, add these lines to `/etc/wazuh-indexer/opensearch.yml`:

    ```yaml
    plugins.security.audit.type: internal_opensearch_data_stream
    plugins.security.audit.config.data_stream.name: security-auditlog
    ```

2. Restart the nodes one at a time:

    ```bash
    systemctl restart wazuh-indexer
    ```

3. Check that events arrive, for example after a failed login:

    ```bash
    curl -sk -u admin:<password> "https://<node>:9200/security-auditlog/_search?size=1&sort=@timestamp:desc&pretty"
    ```

Keep the data stream name `security-auditlog`. Under any other name the security plugin creates the data stream without the retention policy, and its backing index is never deleted.
