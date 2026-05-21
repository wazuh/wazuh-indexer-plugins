# Migration Guide

This guide describes how to migrate an existing Wazuh indexer 4.x deployment to Wazuh indexer 5.x.

> **Important**:
> No automatic upgrade tooling is provided for the 4.x → 5.x migration. The procedure is manual and requires a fresh 5.x installation, manual configuration migration, and a parallel legacy environment to retain 4.x data.

## Scope

Wazuh indexer 5.x is a major release based on OpenSearch 3.x and ships with new index schemas, a revised security model, and renamed configuration settings. As a result, a 4.x cluster cannot be upgraded in place. Operators must:

1. Stand up a new 5.x cluster.
2. Re-create configuration and authentication settings against the 5.x layout.
3. Keep the previous 4.x environment available for read-only access to historical data.

## Summary of 5.x breaking changes

| Area | Change |
| --- | --- |
| Base engine | OpenSearch 3.x (see [Compatibility](../../ref/compatibility.md)) |
| Indices | New v5 schemas (`wazuh-events-v5`, `wazuh-findings-v5`, `wazuh-states-v5`); 4.x indices are not readable by 5.x |
| Default users | `wazuh-server` and `wazuh-dashboard` replace the 4.x defaults |
| Networking | `transport.port` removed; clusters now use `http.port` only |
| Multi-tenancy | Disabled by default |
| Removed plugin | `opensearch-performance-analyzer` |
| Bundled binary | Wazuh Engine ships at `/usr/share/wazuh-indexer/engine/bin/wazuh-engine` |

## How to use this guide

Work through the following pages in order:

1. [Configuration migration](configuration.md) — map 4.x configuration files to their 5.x equivalents and address removed or renamed settings.
2. [Authentication migration](authentication.md) — re-create login configuration (internal users, LDAP, SSO, OIDC) under the new security layout.
3. [Legacy 4.x indices](legacy-indices.md) — understand why 4.x data cannot be migrated and how to keep a parallel legacy environment for historical access.

## Prerequisites

Before starting:

- A backup of the 4.x cluster configuration and certificates. See [Back up and Restore](../../ref/backup-restore.md).
- A supported host for the 5.x installation. See [Compatibility](../../ref/compatibility.md) and [Requirements](../../ref/getting-started/requirements.md).
- 5.x packages obtained via any of the methods listed under [Packages](../../ref/getting-started/packages.md).

## Related documentation

- [Upgrade](../../ref/upgrade.md) — rolling-upgrade procedure for minor and patch upgrades within the same major version. It does **not** apply to the 4.x → 5.x transition described here.
- [Installation](../../ref/getting-started/installation.md) — installing a fresh 5.x cluster.
- [Access Control](../../ref/security/access-control.md) — 5.x default users and roles.
