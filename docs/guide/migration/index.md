# Migration Guide

This guide describes how to migrate an existing Wazuh indexer 4.x deployment to Wazuh indexer 5.x.

> **Important**:
> No automatic upgrade tooling is provided for the 4.x → 5.x migration. The procedure is manual and requires a fresh 5.x installation, manual configuration migration, and a parallel legacy environment to retain 4.x data.

## Scope

Wazuh indexer 5.x is a major release based on OpenSearch 3.x and ships with new index schemas, a revised security model, and renamed configuration settings. As a result, a 4.x cluster cannot be upgraded in place. Operators must:

1. Stand up a new 5.x cluster.
2. Re-create configuration and authentication settings against the 5.x layout.
3. Keep the previous 4.x environment available for read-only access to historical data.

## Prerequisites

Before starting:

- A backup of the 4.x cluster configuration and certificates. See [Back up and Restore](../../ref/backup-restore.md).
- A supported host for the 5.x installation. See [Compatibility](../../ref/compatibility.md) and [Requirements](../../ref/getting-started/requirements.md).
- 5.x packages obtained via any of the methods listed under [Packages](../../ref/getting-started/packages.md).

## Configuration migration

Migration from `4.x` to `5.x` is a selective carry-over process. Re-create settings in the new `5.x` configuration tree, review renamed or removed options, and re-apply security authentication and authorization in the OpenSearch Security files.

Use the pages below to migrate base node configuration first, then security/authentication settings.


1. [Configuration migration](configuration.md) — map 4.x configuration files to their 5.x equivalents and address removed or renamed settings.
2. [Authentication migration](configuration.md#security-configuration) — re-create login configuration (internal users, LDAP, SSO, OIDC) under the new security layout.

## Legacy `4.x` indices

Wazuh indexer `4.x` indices cannot be migrated to `5.x` cluster. No automatic reindex path is provided. To retain access to historical `4.x` data, keep the `4.x` environment running in parallel as a legacy, read-only deployment.

### Why `4.x` data cannot be migrated

Wazuh indexer `5.x` introduces new index schemas with the `v5` suffix and new index templates. The schemas, field types, and routing of the `5.x` indices differ from `4.x` in ways that prevent the older shards from being opened by a `5.x` cluster.

| Concern | Description |
| --- | --- |
| Index schema | `5.x` uses new templates and mappings under `wazuh-events-v5`, `wazuh-findings-v5`, and `wazuh-states-v5`. These have no direct counterpart in `4.x`. |
| Engine version | The OpenSearch 3.x base in `5.x` reads Lucene segments produced by its own and the immediately preceding major version only. Older `4.x` shards fall outside the supported range. |
| Document shape | Field names, types, and parent-child relationships in the v5 mappings differ from `4.x` documents in ways that cannot be transformed losslessly by a reindex. |

For these reasons, neither in-place upgrade, snapshot restore, nor `_reindex` from a `4.x` snapshot are supported.

### Keeping a legacy `4.x` environment

To preserve historical visibility into `4.x` data, run the existing `4.x` cluster alongside the new `5.x` deployment:

1. Leave the `4.x` cluster in place after the migration; do **not** uninstall it.
2. Switch the `4.x` cluster to a read-only role:
    - Stop ingestion from the Wazuh server into `4.x`.
    - Optionally, mark indices read-only at the cluster level to prevent accidental writes.
3. Move current traffic to `5.x`. A `4.x` Wazuh server and dashboard cannot operate against a `5.x` Wazuh indexer, so upgrade the Wazuh server and dashboard to `5.x` as well and point that upgraded stack at the new cluster.
4. Keep the existing `4.x` dashboard pointed at the `4.x` cluster for users who need to query historical data; a `5.x` dashboard cannot read `4.x` indices.
5. Plan a retention window after which the `4.x` environment can be decommissioned according to your data-retention policy.
