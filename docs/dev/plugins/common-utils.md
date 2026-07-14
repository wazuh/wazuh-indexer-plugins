# Wazuh Indexer Common Utils — development guide

`wazuh-indexer-common-utils` is a Wazuh fork of the OpenSearch Common Utils library. It is not a standalone plugin — it ships as a shared JAR dependency consumed by the Wazuh forks of Alerting, Notifications, and Security Analytics, and by the Content Manager plugin.

## What it provides

The library defines cross-plugin models and transport-action contracts so that plugins can call each other's functionality without a direct compile-time dependency on each other's internals:

- **`org.opensearch.commons.alerting`** — shared alerting models and `AlertingPluginInterface`, the transport bridge other plugins use to call into Alerting (e.g., Security Analytics fetches findings via `AlertingPluginInterface.INSTANCE.getFindings()`).
- **`org.opensearch.commons.notifications`** — shared notification channel/config models and `NotificationsPluginInterface`, used to send notifications from other plugins without depending on the Notifications plugin directly.
- **`org.opensearch.commons.notifications.model.ActiveResponse`** — the Active Response channel definition; the Wazuh-specific extension that lets a Notifications channel drive Active Response execution requests.
- **`org.opensearch.commons.replication`** — shared cross-cluster replication models and `ReplicationPluginInterface`.
- **`org.opensearch.commons.authuser`** — shared user/role context passed across plugin boundaries for RBAC enforcement.
- **`org.opensearch.commons.destination`** — shared destination message/response models used by notification transports.

## Relationship to the Security Analytics `commons/` submodule

Don't confuse this repository with the `commons/` submodule inside `wazuh-indexer-security-analytics` (`wazuh-indexer-security-analytics/commons/src/main/java/com/wazuh/securityanalytics/action/`). That submodule defines the `W*Action` classes (`WIndexIntegrationAction`, `WIndexRuleAction`, `WIndexDetectorAction`, etc.) used specifically for Content Manager → Security Analytics communication — it's a separate, narrower set of shared classes scoped to that one integration, not part of this library.

## Working with this library

Changes here affect every plugin that depends on it. When modifying a shared model or interface:

1. Check all consumers (`wazuh-indexer-alerting`, `wazuh-indexer-notifications`, `wazuh-indexer-security-analytics`, and `wazuh-indexer-plugins`' Content Manager) for usages before changing a method signature or model field.
2. Bump the version and republish before consumers can pick up the change — this is a versioned dependency, not a monorepo shared source set.
3. See `RELEASING.md` and `CHANGELOG.md` in the repository root for the release process.
