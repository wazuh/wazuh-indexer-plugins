# Configuration migration

This page describes how to carry over a Wazuh indexer `4.x` configuration to a `5.x` installation. The configuration layout has changed only slightly between major versions, but several OpenSearch 3.x settings have been renamed or removed and must be reviewed before reusing any `4.x` file as-is.

> **Important**:
> Do not copy `4.x` configuration files verbatim into a `5.x` installation. Use them as a reference and re-create each setting against the `5.x` layout described below.

### Configuration paths

Both `4.x` and `5.x` install configuration under `/etc/wazuh-indexer/`. The canonical `5.x` layout is:

| Path | Purpose |
| --- | --- |
| `/etc/wazuh-indexer/opensearch.yml` | Main cluster and node configuration |
| `/etc/wazuh-indexer/jvm.options` | JVM heap and GC settings |
| `/etc/wazuh-indexer/log4j2.properties` | Logging configuration |
| `/etc/wazuh-indexer/certs/` | Transport and HTTP TLS certificates |
| `/etc/wazuh-indexer/opensearch-security/` | Security plugin configuration (see [Authentication migration](#security-configuration)) |

For a full description of each file, see [Configuration](../../ref/configuration/index.md).

### Migration procedure

Perform these steps on the new `5.x` host. The `4.x` cluster is not modified by this procedure.

1. Install the `5.x` package on a fresh host following [Installation](../../ref/getting-started/installation.md). This creates the default `5.x` configuration tree under `/etc/wazuh-indexer/`.
2. Stop the new service before editing configuration:

    ```bash
    systemctl stop wazuh-indexer
    ```

3. Copy the relevant `4.x` configuration values into the corresponding `5.x` file. Do not overwrite the `5.x` file with the `4.x` file. Review each setting against the [Settings changes](#settings-changes) section below.
4. Migrate certificates by placing the existing trust and node certificates under `/etc/wazuh-indexer/certs/` and updating the `plugins.security.ssl.*` paths in `opensearch.yml` accordingly.
5. Re-create authentication configuration. See [Authentication migration](#security-configuration).
6. Start the service:

    ```bash
    systemctl daemon-reload
    systemctl enable wazuh-indexer
    systemctl start wazuh-indexer
    ```

7. Confirm the node joins the new `5.x` cluster:

    ```bash
    curl -k -u $USERNAME:$PASSWORD https://$WAZUH_INDEXER_IP_ADDRESS:9200/_cat/nodes?v
    ```

### Settings changes

The following `4.x` settings have changed in `5.x` and must be reviewed before reuse.

| `4.x` setting | `5.x` replacement | Notes |
| --- | --- | --- |
| `transport.port` | `http.port` | Transport-level port configuration has been consolidated; clusters now use `http.port` only. |
| `opensearch_performance_analyzer.*` | _Removed_ | The `opensearch-performance-analyzer` plugin is no longer shipped. Remove any related entries. |
| Multi-tenancy settings | _Disabled by default_ | Multi-tenancy is off by default. Enable explicitly only if required. |

Additional `4.x` settings may have been removed or renamed by the OpenSearch 3.x base. Before starting the service, validate every setting against the [Compatibility](../../ref/compatibility.md) page and the upstream OpenSearch 3.x release notes.

### JVM and logging

`jvm.options` and `log4j2.properties` are usually safe to port over by copying individual non-default lines into the `5.x` files. Do not replace the `5.x` files outright, since the defaults shipped with `5.x` are tuned for the new base engine.


## Security configuration

This section describes how to migrate security configuration from Wazuh indexer `4.x` to `5.x`. Authentication is managed by the OpenSearch Security plugin in both versions, but `5.x` ships a new set of default internal users and expects configuration files in their canonical location.

### Configuration location

In `5.x`, all security plugin configuration lives under:

```
/etc/wazuh-indexer/opensearch-security/
```

The relevant files are:

| File | Purpose |
| --- | --- |
| `internal_users.yml` | Local user accounts and password hashes |
| `roles.yml` | Role definitions |
| `roles_mapping.yml` | Mapping from authenticated identities to roles |
| `config.yml` | Authentication backends (internal, LDAP, SAML, OIDC, JWT, etc.) |

For the `5.x` defaults, see [Access Control](../../ref/security/access-control.md).

### Default internal users in `5.x`

`5.x` ships with a new set of internal users tailored to the Wazuh stack. The `4.x` defaults are not carried over.

| User | Purpose |
| --- | --- |
| `wazuh-server` | Used by the Wazuh Server; read/write to stateful indices, write-only to stateless indices |
| `wazuh-dashboard` | Used by the Wazuh Dashboard; read access across most indices, management permissions on metrics indices |

A full list of the default users and roles, together with their permissions, is available in [Access Control](../../ref/security/access-control.md).

### Migration procedure

Perform these steps on the new `5.x` host. The `4.x` cluster is not modified by this procedure.

1. Locate the `4.x` security configuration files under `/etc/wazuh-indexer/opensearch-security/` on the previous installation.
2. On the new `5.x` host, do **not** overwrite the shipped files. Edit them in place under `/etc/wazuh-indexer/opensearch-security/`.
3. For each custom entry in the `4.x` files, decide whether it should be re-created in `5.x`:
    - Custom internal users → add to `internal_users.yml` (regenerate password hashes with the bundled hash tool).
    - Custom roles → add to `roles.yml` keeping the `5.x` index patterns and permission names.
    - Role mappings → add to `roles_mapping.yml` referencing the new role names.
    - External authentication backends (LDAP, SAML, OIDC, JWT, Kerberos) → re-create the corresponding `authc` / `authz` blocks in `config.yml`.

    > **Tip — bulk copy alternative**:
    > Reviewing every entry individually is the safest option, but it is also tedious and risks silently dropping a custom user or role you set up long ago and no longer remember. As an alternative, you can copy **all** custom entries from the `4.x` files into the corresponding `5.x` files at once, then prune afterwards. This guarantees nothing is lost, at the cost of dragging along stale or obsolete entries. If you take this approach, be aware that copied entries may reference `4.x` index patterns or permission names that changed in `5.x`, and may collide with the new `5.x` default users and roles — so still validate the result against [Access Control](../../ref/security/access-control.md) before applying.

4. Apply the configuration with the `securityadmin` tool shipped with the package.
5. Restart the service and verify authentication works for each backend before pointing production traffic at the new cluster.

> The exact syntax for each authentication backend (LDAP, SAML, OIDC, etc.) is defined and maintained by the upstream OpenSearch Security plugin and may evolve between OpenSearch versions. Always cross-check the backend configuration against the upstream documentation referenced below before applying it.

### External authentication backends

Wazuh indexer `5.x` supports the same backends as the underlying OpenSearch Security plugin, including LDAP, Active Directory, SAML, OIDC, JWT, Kerberos, and client-certificate authentication. The migration steps are identical regardless of backend: re-create the `authc` and `authz` blocks in `config.yml` against the `5.x` schema, then apply with `securityadmin`.

Refer to the upstream OpenSearch Security documentation for the exact syntax of each backend:

- [OpenSearch Security — Access control](https://docs.opensearch.org/3.5/security/access-control/index/)
- [OpenSearch Security — Authentication backends](https://docs.opensearch.org/3.5/security/authentication-backends/authc-index/)
- [OpenSearch Security — Configuration](https://docs.opensearch.org/3.5/security/configuration/index/)


## Related documentation

- [Migration Guide](./README.md) — entry point and prerequisites
- [Authentication migration](#security-configuration) — security plugin configuration
- [Access Control](../../ref/security/access-control.md) — 5.x default users and roles
- [Defining Users and Roles](../../ref/security/defining-users-and-roles.md) — how to declare new users and roles in 5.x
