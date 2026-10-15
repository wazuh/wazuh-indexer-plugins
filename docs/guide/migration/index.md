# Migration guide

This guide describes how to migrate an existing Wazuh indexer 4.x deployment to Wazuh indexer 5.x.

> **Important**
> Only configuration is migrated, and it is migrated manually. There is no automatic upgrade tooling, and **indexed data is not migrated** (see [Indexed data](#indexed-data)). The procedure requires a fresh 5.x installation and manual re-creation of configuration and security settings. If you need to retain access to historical 4.x data, see [Optionally keeping a legacy 4.x environment](#optionally-keeping-a-legacy-4x-environment).

## Scope

Wazuh indexer 5.x is a major release based on OpenSearch 3.x. It ships with new index schemas, a revised security model, and renamed or removed configuration settings. As a result, a 4.x cluster cannot be upgraded in place. The migration covers **configuration only** — base node settings, certificates, and OpenSearch Security authentication/authorization. It does **not** cover indexed data.

The procedure is:

1. Stand up a new 5.x cluster on a fresh host.
2. Re-create base configuration, certificates, and security settings against the 5.x layout.

The 4.x cluster is never modified by this procedure.

## Prerequisites

Before starting:

- A backup of the 4.x cluster configuration, security configuration, and certificates. See [Back up and restore](../../ref/backup-restore.md).
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

### Configuration procedure

Perform these steps on every node of the new 5.x cluster. Steps 2 to 6 run with the service stopped; steps 7 to 9 need it running.

1. Install the 5.x package on a fresh host following [Installation](../../ref/getting-started/installation.md). This creates the default 5.x configuration tree under `/etc/wazuh-indexer/`.
2. Stop the new service before editing configuration:

    ```bash
    systemctl stop wazuh-indexer
    ```

3. Copy the relevant 4.x configuration values into the corresponding 5.x files — do not overwrite the 5.x files. Review each setting against [Settings changes](#settings-changes) below.
4. To keep the 4.x certificates, deploy them as described in [Deploying certificates](../../ref/getting-started/installation.md#deploying-certificates): the node pair as `indexer.pem` and `indexer-key.pem`, plus `admin.pem`, `admin-key.pem` and `root-ca.pem`, all under `/etc/wazuh-indexer/certs/`, so the 5.x certificate paths in `opensearch.yml` stay valid. Then set `plugins.security.nodes_dn` and `plugins.security.authcz.admin_dn` to the subjects of those certificates. To keep the certificates the 5.x package issued instead, skip this step. See [Generated at installation](#generated-at-installation).
5. Port `jvm.options` and `log4j2.properties` by copying only individual non-default lines into the 5.x files. Do not replace the 5.x files outright.
6. Edit the security configuration files. See steps 1 and 2 of the [Security procedure](#security-procedure).
7. Start the service:

    ```bash
    systemctl enable --now wazuh-indexer
    ```

8. Confirm the node joins the new 5.x cluster. `$WAZUH_INDEXER_ADMIN_PASSWORD` is the `admin` password from `/etc/wazuh/credentials.env`, as described in [Installation](../../ref/getting-started/installation.md#testing-the-cluster-installation):

    ```bash
    curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD "https://127.0.0.1:9200/_cat/nodes?v"
    ```

9. Once every node has joined, load the security configuration from a single node. See steps 3 and 4 of the [Security procedure](#security-procedure).

### Settings changes

The following 4.x settings have changed in 5.x and must be reviewed before reuse. This list is not exhaustive: validate every remaining setting against the upstream OpenSearch 3.x breaking changes and release notes before starting the service.

#### Removed

- `compatibility.override_main_response_version`: present in 4.x `opensearch.yml` for legacy Filebeat compatibility. Removed in OpenSearch 3.0; a node that still defines it **will not boot**. Delete the setting.
- `opensearch_performance_analyzer.*`: the `opensearch-performance-analyzer` plugin is no longer shipped. Remove any related entries.
- `plugins.anomaly_detection.*`: the `opensearch-anomaly-detection` plugin is no longer shipped. Remove any related entries.
- `plugins.asynchronous_search.*`: the `opensearch-asynchronous-search` plugin is no longer shipped. Remove any related entries.
- `plugins.ml_commons.*`: the `opensearch-ml` plugin is no longer shipped. Remove any related entries.
- `plugins.query.datasources.*`: the `opensearch-sql` plugin is no longer shipped. Remove any related entries.
- `plugins.neural_search.*`: the `opensearch-neural-search` plugin is no longer shipped. Remove any related entries.
- `knn.*`: the `opensearch-knn` plugin is no longer shipped. Remove any related entries.
- Observability and notebooks: the `opensearch-observability` plugin is no longer shipped. Remove any related entries.

#### Renamed or changed

- `cluster.initial_master_nodes` → `cluster.initial_cluster_manager_nodes`. The old name is deprecated. The 5.x file already sets the new one: carry the node list over to it and do not add the old setting.
- `plugins.security.ssl.transport.enforce_hostname_verification` → `transport.ssl.enforce_hostname_verification`, and `plugins.security.ssl.transport.resolve_hostname` → `transport.ssl.resolve_hostname`. The 5.x file already sets the new keys, and a node that defines both the old and the new name of a setting fails to start, so do not add the 4.x lines. `transport.ssl.enforce_hostname_verification` is `true` in 5.x (it was `false` in 4.x), so each node certificate must list the node's address in its subject alternative names. `transport.ssl.resolve_hostname` stays `false`.
- `plugins.security.ssl.http.enabled_ciphers` and `plugins.security.ssl.http.enabled_protocols`: the 4.x installation assistant pinned TLS 1.2 and four cipher suites. 5.x does not set them and uses the OpenSearch defaults. Carry them over only if your security policy requires a restricted list.
- `plugins.security.system_indices.indices`: the 5.x list drops the indices of the plugins that are no longer shipped and adds `.wazuh-internal-state`. Keep the 5.x values.
- Multi-tenancy settings: dashboard multi-tenancy is disabled by default in 5.x.

#### Generated at installation

The 5.x package issues the node's TLS certificates and generates the passwords of its default users when it is installed, and writes the following settings itself. See [Installation](../../ref/getting-started/installation.md). Their values differ from the ones the 4.x installation wrote, and that is expected. Keep the generated values, unless you migrate the 4.x certificates (step 4 of the [Configuration procedure](#configuration-procedure)), in which case set them to match those certificates.

- Certificate paths, `plugins.security.ssl.http.pem*_filepath` and `plugins.security.ssl.transport.pem*_filepath`: 5.x always names the node pair `indexer.pem` and `indexer-key.pem`. A 4.x node installed step by step uses the same names, while the 4.x installation assistant named the pair after the node, for example `node-1.pem`.
- `plugins.security.authcz.admin_dn` and `plugins.security.nodes_dn`: 5.x fills them in with the subjects of the certificates it issued. The fields appear in a different order than in the 4.x files (`C=US,...,CN=admin` instead of `CN=admin,...,C=US`). Keep the 5.x values.

## Security migration

Authentication and authorization are managed by the OpenSearch Security plugin in both versions, but 5.x ships a new set of default internal users, roles, and role mappings tailored to the Wazuh stack — the 4.x defaults are not carried over. For the full, up-to-date list of 5.x default users, roles, and permissions, see [Access control](../../ref/security/access-control.md).

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
| `allowlist.yml` | When enabled, limits every user except the super admin to the listed REST endpoints and methods. 5.x no longer ships the deprecated `whitelist.yml` |
| `audit.yml` | Audit-logging configuration |

### Security procedure

Step 1 runs on the 4.x cluster. The remaining steps run on the new 5.x cluster: step 2 on every node, with the service running or stopped, and steps 3 and 4 with the cluster running and every node joined.

1. Export the live 4.x security configuration. The on-disk files under `/etc/wazuh-indexer/opensearch-security/` may be stale, since the active configuration is stored in the security index. Use the backup procedure to write the live configuration to disk before reusing it. See [Back up and restore](../../ref/backup-restore.md).
2. On **every** node of the new 5.x cluster, do **not** overwrite the shipped files. Edit them in place under `/etc/wazuh-indexer/opensearch-security/`, making the same changes on each node. For each custom entry in the 4.x files, decide whether it should be re-created in 5.x:
    - Custom internal users → add to `internal_users.yml` (existing password hashes can be reused as-is).
    - Custom roles → add to `roles.yml`, keeping the 5.x index patterns and permission names.
    - Role mappings → add to `roles_mapping.yml`, referencing the new role names.
    - External authentication backends (LDAP, Active Directory, SAML, OIDC, JWT, Kerberos, client-certificate) → re-create the corresponding `authc` / `authz` blocks in `config.yml` against the 5.x schema.

    > **Tip — bulk copy alternative**
    > Reviewing every entry individually is the safest option, but it is tedious and risks silently dropping a custom user or role you set up long ago and no longer remember. As an alternative, copy **all** custom entries from the 4.x files into the corresponding 5.x files at once, then prune afterwards. This guarantees nothing is lost, at the cost of dragging along stale entries. Copied entries may reference 4.x index patterns or permission names that changed in 5.x, and may collide with the new 5.x default users and roles — so still validate the result against [Access control](../../ref/security/access-control.md) before applying.

3. Apply the configuration with the `/usr/share/wazuh-indexer/bin/indexer-security-init.sh` script shipped with the package. Run it **once**, from a single node whose files carry all the changes. The cluster stores the security configuration in its security index, so the change reaches every node.
4. Verify authentication works for each backend, against every node, before pointing production traffic at the new cluster. Changes applied with the script take effect without a restart.

> **Warning**
> `indexer-security-init.sh` uploads the files under `/etc/wazuh-indexer/opensearch-security/` of the node it runs on to the security index, replacing the configuration of the whole cluster. Running it later from a node whose files lack the migrated entries removes them on every node, and the migrated users can no longer log in. Keep the files of all nodes in sync, both now and whenever you change the security configuration later.

> The exact syntax for each external authentication backend is defined and maintained by the upstream OpenSearch Security plugin and may evolve between OpenSearch versions. Always cross-check the backend configuration against the upstream documentation before applying it:
>
> - [OpenSearch Security — Access control](https://docs.opensearch.org/3.6/security/access-control/index/)
> - [OpenSearch Security — Authentication backends](https://docs.opensearch.org/3.6/security/authentication-backends/authc-index/)
> - [OpenSearch Security — Configuration](https://docs.opensearch.org/3.6/security/configuration/index/)

## Indexed data

Wazuh indexer 4.x data is not migrated to 5.x. There is no in-place upgrade and no `_reindex` path that turns 4.x data into 5.x data. To retain access to historical 4.x data, see [Optionally keeping a legacy 4.x environment](#optionally-keeping-a-legacy-4x-environment).

A snapshot of 4.x indices can still be restored on a 5.x cluster: this is a standard OpenSearch feature (see [Snapshot and restore](https://docs.opensearch.org/3.6/tuning-your-cluster/availability-and-recovery/snapshots/snapshot-restore/)). Only indices created on OpenSearch 2.x can be restored: a 4.x cluster upgraded from an earlier 4.x release that ran on OpenSearch 1.x may still hold indices created back then, and those cannot be restored on 5.x. The restored indices are plain OpenSearch indices, though. None of the Wazuh 5.x central components reads the legacy `wazuh-alerts-*` and `wazuh-archives-*` indices, so restoring them does not make the 4.x data part of the 5.x deployment.

### Why

Wazuh indexer 5.x introduces new index schemas (the `v5` suffix) and new index templates. The schemas, field types, and routing of the 5.x indices differ from 4.x, so the 4.x data cannot be turned into 5.x data:

| Concern | Description |
| --- | --- |
| Index schema | 5.x uses new templates and mappings for `wazuh-events-v5-*`, `wazuh-findings-v5-*`, and `wazuh-states-*`. These have no direct counterpart in 4.x. |
| Index compatibility | The OpenSearch 3.x base in 5.x reads indices created on its own and the immediately preceding major version only. A snapshot of 4.x indices created on OpenSearch 2.x can be restored. |
| Document shape | 5.x events and findings are data streams whose field names follow the Wazuh Common Schema, and their mappings reject fields they do not define. 4.x documents cannot be written into them without being transformed, and that transformation is not lossless. |

### Optionally keeping a legacy 4.x environment

Whether to retain the old cluster is entirely your decision and depends on whether you still need historical 4.x data. If you do not, the 4.x environment can be decommissioned once the 5.x cluster is in service.

If you do need historical visibility, you can run the existing 4.x cluster alongside the new 5.x deployment:

1. Leave the 4.x cluster in place after the migration; do **not** uninstall it.
2. Switch the 4.x cluster to a read-only role: stop ingestion from the Wazuh server into 4.x, and optionally mark its indices read-only to prevent accidental writes.
3. Keep the existing 4.x dashboard pointed at the 4.x cluster for users who need historical data; the Wazuh 5.x dashboard modules do not read 4.x indices.
4. Plan a retention window after which the 4.x environment can be decommissioned according to your data-retention policy.
