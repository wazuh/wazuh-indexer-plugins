# Migration Guide

This guide describes how to migrate an existing Wazuh indexer 4.x deployment to Wazuh indexer 5.x.

> **Important**
> Only configuration is migrated by this procedure, and it is migrated manually. There is no automatic upgrade tooling and no in-place upgrade: a fresh 5.x installation and manual re-creation of configuration and security settings are required. Indexed data is handled separately — 4.x indices created by OpenSearch 2.x can be moved with snapshot and restore, and they keep their 4.x names and mappings on the 5.x cluster (see [Migrating indexed data](#migrating-indexed-data)).

## Scope

Wazuh indexer 5.x is a major release based on OpenSearch 3.x. It ships with new index schemas, a revised security model, and renamed or removed configuration settings. As a result, a 4.x cluster cannot be upgraded in place. The migration covers **configuration only** — base node settings, certificates, and OpenSearch Security authentication/authorization. Indexed data is covered separately under [Migrating indexed data](#migrating-indexed-data).

The procedure is:

1. Stand up a new 5.x cluster on a fresh host.
2. Re-create base configuration, certificates, and security settings against the 5.x layout.

The 4.x cluster is never modified by this procedure. Historical 4.x data can either be restored into the 5.x cluster from a snapshot or left on a 4.x environment kept running in parallel as a read-only legacy deployment — see [Migrating indexed data](#migrating-indexed-data).

## Prerequisites

Before starting:

- A backup of the 4.x cluster configuration, security configuration, and certificates. See [Back up and Restore](../../ref/backup-restore.md).
- A supported host for the 5.x installation. See [Compatibility](../../ref/compatibility.md) and [Requirements](../../ref/getting-started/requirements.md).
- 5.x packages obtained via any of the methods listed under [Packages](../../ref/getting-started/packages.md).

## Configuration migration

Migration from 4.x to 5.x is a selective carry-over: re-create each setting against the 5.x configuration tree rather than copying 4.x files verbatim. Both versions install configuration under `/etc/wazuh-indexer/`, and the layout has changed only slightly, but several OpenSearch 3.x settings have been renamed or removed and must be reviewed before any 4.x value is reused.

> **Important**
> Do not copy 4.x configuration files over the 5.x files. The defaults shipped with 5.x are tuned for the new base engine. Use the 4.x files as a reference and re-apply each setting into the corresponding 5.x file.

The canonical 5.x configuration layout is:

| Path | Purpose |
| --- | --- |
| `/etc/wazuh-indexer/opensearch.yml` | Main cluster and node configuration |
| `/etc/wazuh-indexer/jvm.options` | JVM heap and GC settings |
| `/etc/wazuh-indexer/log4j2.properties` | Logging configuration |
| `/etc/wazuh-indexer/certs/` | Transport and HTTP TLS certificates |
| `/etc/wazuh-indexer/opensearch-security/` | Security plugin configuration (see [Security migration](#security-migration)) |

For a full description of each file, see [Configuration](../../ref/configuration/index.md).

### Procedure

Perform these steps on the new 5.x host.

1. Install the 5.x package on a fresh host following [Installation](../../ref/getting-started/installation.md). This creates the default 5.x configuration tree under `/etc/wazuh-indexer/`.
2. Stop the new service before editing configuration:

    ```bash
    systemctl stop wazuh-indexer
    ```

3. Copy the relevant 4.x configuration values into the corresponding 5.x files — do not overwrite the 5.x files. Review each setting against [Settings changes](#settings-changes) below.
4. Migrate certificates by placing the existing trust and node certificates under `/etc/wazuh-indexer/certs/` and updating the `plugins.security.ssl.*` paths in `opensearch.yml` accordingly.
5. Port `jvm.options` and `log4j2.properties` by copying only individual non-default lines into the 5.x files. Do not replace the 5.x files outright.
6. Re-create the security configuration. See [Security migration](#security-migration).
7. Start the service:

    ```bash
    systemctl enable --now wazuh-indexer
    ```

8. Confirm the node joins the new 5.x cluster:

    ```bash
    curl -k -u $USERNAME:$PASSWORD https://$WAZUH_INDEXER_IP_ADDRESS:9200/_cat/nodes?v
    ```

### Settings changes

The following 4.x settings have changed in 5.x and must be reviewed before reuse. This list is not exhaustive: validate every remaining setting against the upstream OpenSearch 3.x breaking changes and release notes before starting the service.

| 4.x setting | 5.x replacement | Notes |
| --- | --- | --- |
| `opensearch_performance_analyzer.*` | _Removed_ | The `opensearch-performance-analyzer` plugin is no longer shipped. Remove any related entries. |
| `plugins.anomaly_detection.*` | _Removed_ | The `opensearch-anomaly-detection` plugin is no longer shipped. Remove any related entries. |
| `plugins.asynchronous_search.*` | _Removed_ | The `opensearch-asynchronous-search` plugin is no longer shipped. Remove any related entries. |
| `plugins.ml_commons.*` | _Removed_ | The `opensearch-ml` plugin is no longer shipped. Remove any related entries. |
| `plugins.query.datasources.*` | _Removed_ | The `opensearch-sql` plugin is no longer shipped. Remove any related entries. |
| `plugins.neural_search.*` | _Removed_ | The `opensearch-neural-search` plugin is no longer shipped. Remove any related entries. |
| `knn.*` | _Removed_ | The `opensearch-knn` plugin is no longer shipped. Remove any related entries. |
| `compatibility.override_main_response_version` | _Removed_ | Present in 4.x `opensearch.yml` for legacy Filebeat compatibility. Removed in OpenSearch 3.0; a node that still defines it **will not boot**. Delete the setting. |
| Multi-tenancy settings | _Disabled by default_ | Dashboard multi-tenancy is off by default in 5.x. |

## Security migration

Authentication and authorization are managed by the OpenSearch Security plugin in both versions, but 5.x ships a new set of default internal users, roles, and role mappings tailored to the Wazuh stack — the 4.x defaults are not carried over. For the full, up-to-date list of 5.x default users, roles, and permissions, see [Access Control](../../ref/security/access-control.md).

In 5.x, all security plugin configuration lives under `/etc/wazuh-indexer/opensearch-security/`:

| File | Purpose |
| --- | --- |
| `config.yml` | Authentication and authorization backends (internal, LDAP, SAML, OIDC, JWT, etc.) |
| `internal_users.yml` | Local user accounts and password hashes |
| `roles.yml` | Role definitions |
| `roles_mapping.yml` | Mapping from authenticated identities to roles |
| `action_groups.yml` | Reusable groups of permissions referenced by roles |
| `tenants.yml` | Dashboard tenants |
| `nodes_dn.yml` | Node certificate distinguished names allowed into the cluster |
| `allowlist.yml` | REST API paths reachable while the cluster is in a restricted state (replaces 4.x `whitelist.yml`) |
| `audit.yml` | Audit-logging configuration |

### Procedure

Perform these steps on the new 5.x host.

1. Export the live 4.x security configuration. The on-disk files under `/etc/wazuh-indexer/opensearch-security/` may be stale, since the active configuration is stored in the security index. Use the backup procedure to write the live configuration to disk before reusing it. See [Back up and Restore](../../ref/backup-restore.md).
2. On the new 5.x host, do **not** overwrite the shipped files. Edit them in place under `/etc/wazuh-indexer/opensearch-security/`. For each custom entry in the 4.x files, decide whether it should be re-created in 5.x:
    - Custom internal users → add to `internal_users.yml` (existing password hashes can be reused as-is).
    - Custom roles → add to `roles.yml`, keeping the 5.x index patterns and permission names.
    - Role mappings → add to `roles_mapping.yml`, referencing the new role names.
    - External authentication backends (LDAP, Active Directory, SAML, OIDC, JWT, Kerberos, client-certificate) → re-create the corresponding `authc` / `authz` blocks in `config.yml` against the 5.x schema.

    > **Tip — bulk copy alternative**
    > Reviewing every entry individually is the safest option, but it is tedious and risks silently dropping a custom user or role you set up long ago and no longer remember. As an alternative, copy **all** custom entries from the 4.x files into the corresponding 5.x files at once, then prune afterwards. This guarantees nothing is lost, at the cost of dragging along stale entries. Copied entries may reference 4.x index patterns or permission names that changed in 5.x, and may collide with the new 5.x default users and roles — so still validate the result against [Access Control](../../ref/security/access-control.md) before applying.

3. Apply the configuration with the `/usr/share/wazuh-indexer/bin/indexer-security-init.sh` script shipped with the package.
4. Restart the service and verify authentication works for each backend before pointing production traffic at the new cluster.

> The exact syntax for each external authentication backend is defined and maintained by the upstream OpenSearch Security plugin and may evolve between OpenSearch versions. Always cross-check the backend configuration against the upstream documentation before applying it:
>
> - [OpenSearch Security — Access control](https://docs.opensearch.org/3.6/security/access-control/index/)
> - [OpenSearch Security — Authentication backends](https://docs.opensearch.org/3.6/security/authentication-backends/authc-index/)
> - [OpenSearch Security — Configuration](https://docs.opensearch.org/3.6/security/configuration/index/)

## Migrating indexed data

Wazuh indexer 4.x indices are never upgraded in place and are never converted to the 5.x schemas. Their data can still be moved into a 5.x cluster with [snapshot and restore](https://docs.opensearch.org/3.6/tuning-your-cluster/availability-and-recovery/snapshots/snapshot-restore/), provided the indices were created by OpenSearch 2.x: take the snapshot on the 4.x cluster without the cluster state, register the same repository as read-only on the 5.x cluster, and restore the indices under a prefix such as `restored_`. Restored indices keep their original names, mappings, and documents, and are legacy read-only data sitting next to the `v5` indices rather than part of them. To query them from the 5.x dashboard, create an index pattern that matches the restored names.

The OpenSearch version that created an index is reported by `index.version.created`. Check it on the 4.x cluster before taking the snapshot:

```bash
curl -k -u $USERNAME:$PASSWORD https://$WAZUH_INDEXER_IP_ADDRESS:9200/$INDEX/_settings
```

Indices created by OpenSearch 1.x, that is, by Wazuh indexer 4.x releases older than the first one based on OpenSearch 2.x, fall outside the range a 5.x cluster can read. They cannot be restored, and there is no `_reindex` path from a 5.x cluster into them either. Keep them on a legacy 4.x environment, or reindex them on a 4.x cluster that is based on OpenSearch 2.x before snapshotting.

### What a restore does not do

| Concern | Description |
| --- | --- |
| Index schema | 5.x uses new templates and mappings under `wazuh-events-v5`, `wazuh-findings-v5`, and `wazuh-states-v5`. These have no direct counterpart in 4.x, so restored indices are not read by the 5.x modules and dashboards that target the `v5` index patterns. |
| Engine version | The OpenSearch 3.x base in 5.x reads Lucene segments produced by its own and the immediately preceding major version only. Indices created by OpenSearch 2.x are within that range; indices created by OpenSearch 1.x are not. |
| Document shape | Field names, types, and parent-child relationships in the v5 mappings differ from 4.x documents in ways that cannot be transformed losslessly by a reindex, so 4.x data stays in its 4.x shape after the restore. |

### Optionally keeping a legacy 4.x environment

Whether to retain the old cluster is entirely your decision and depends on whether you still need historical 4.x data and whether that data can be restored into 5.x. If you do not need it, the 4.x environment can be decommissioned once the 5.x cluster is in service.

If you do need historical visibility and prefer not to restore the data into 5.x, you can run the existing 4.x cluster alongside the new 5.x deployment:

1. Leave the 4.x cluster in place after the migration; do **not** uninstall it.
2. Switch the 4.x cluster to a read-only role: stop ingestion from the Wazuh server into 4.x, and optionally mark its indices read-only to prevent accidental writes.
3. Keep the existing 4.x dashboard pointed at the 4.x cluster for users who need historical data; the 5.x dashboard only queries the cluster it is configured against.
4. Plan a retention window after which the 4.x environment can be decommissioned according to your data-retention policy.
