# Legacy `4.x` indices

This page explains why Wazuh indexer `4.x` indices cannot be migrated to `5.x` and how to keep historical data accessible after the migration.

> **Important**:
> Data stored in `4.x` indices cannot be migrated to a `5.x` cluster. No automatic reindex path is provided. To retain access to historical `4.x` data, keep the `4.x` environment running in parallel as a legacy, read-only deployment.

## Why `4.x` data cannot be migrated

Wazuh indexer `5.x` introduces new index schemas with the `v5` suffix and new index templates. The schemas, field types, and routing of the `5.x` indices differ from `4.x` in ways that prevent the older shards from being opened by a `5.x` cluster.

| Concern | Description |
| --- | --- |
| Index schema | `5.x` uses new templates and mappings under `wazuh-events-v5`, `wazuh-findings-v5`, and `wazuh-states-v5`. These have no direct counterpart in `4.x`. |
| Engine version | The OpenSearch 3.x base in `5.x` reads Lucene segments produced by its own and the immediately preceding major version only. Older `4.x` shards fall outside the supported range. |
| Document shape | Field names, types, and parent-child relationships in the v5 mappings differ from `4.x` documents in ways that cannot be transformed losslessly by a reindex. |

For these reasons, neither in-place upgrade, snapshot restore, nor `_reindex` from a `4.x` snapshot are supported.

## Keeping a legacy `4.x` environment

To preserve historical visibility into `4.x` data, run the existing `4.x` cluster alongside the new `5.x` deployment:

1. Leave the `4.x` cluster in place after the migration; do **not** uninstall it.
2. Switch the `4.x` cluster to a read-only role:
    - Stop ingestion from the Wazuh server into `4.x`.
    - Optionally, mark indices read-only at the cluster level to prevent accidental writes.
3. Point the Wazuh server and dashboard at the new `5.x` cluster for current traffic.
4. Keep dashboard access to the `4.x` cluster available for users who need to query historical data.
5. Plan a retention window after which the `4.x` environment can be decommissioned according to your data-retention policy.

## Out of scope

The following workflows are explicitly not supported as part of the `4.x` → `5.x` migration:

- Snapshot restore from a `4.x` cluster into a `5.x` cluster.
- In-place upgrade of `4.x` indices to the v5 schema.
- `_reindex` from a `4.x` remote cluster into `5.x`.
- Automated migration tooling for documents, mappings, or templates.

## Related documentation

- [Migration Guide](README.md) — entry point and prerequisites
- [Configuration migration](configuration.md) — migrating cluster configuration
- [Authentication migration](authentication.md) — migrating login configuration
- [Back up and Restore](../../ref/backup-restore.md) — snapshot operations within a single major version
