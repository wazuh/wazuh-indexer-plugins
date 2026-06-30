# Access Control

Wazuh Indexer uses the OpenSearch Security plugin to manage access control and security features. This allows you to define users, roles, and permissions for accessing indices and performing actions within the Wazuh Indexer.

> You can find a more detailed overview of the OpenSearch Security plugin in the [OpenSearch documentation](https://docs.opensearch.org/3.6/security/access-control/index/).

## Wazuh default Internal Users

Wazuh defines internal users and roles for the different Wazuh components to handle index management.

These default users and roles definitions are stored in the `internal_users.yml`, `roles.yml`, and `roles_mapping.yml` files on the `/etc/wazuh-indexer/opensearch-security/` directory.
> Find more info about the configurations files in the [Configuration files](./index.md#configuration-files) section.

### Users

| User              | Description                                                                                                                              | Roles                                                                                                                              |
|-------------------|------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------|
| `wazuh-server`    | User for the Wazuh Manager with read/write access to stateful indices and write-only access to stateless indices.                         | `stateless-write`, `stateful-delete`, `stateful-write`, `stateful-read`, `cm_subscription_read`                                    |
| `wazuh-dashboard` | User for Wazuh Dashboard with read access to stateful and stateless indices, and management level permissionsfor the monitoring indices. | `sample-data-management`, `metrics-write`, `metrics-read`, `stateless-read`, `stateful-read`, `cm_subscription_write` |

### Roles

| Role Name                | Access Description                                                             | Index Patterns                           | Permissions                                                                              |
|--------------------------|--------------------------------------------------------------------------------|------------------------------------------|------------------------------------------------------------------------------------------|
| `stateful-read`          | Grants read-only permissions to stateful indices.                              | `wazuh-states-*`                         | `read`                                                                                   |
| `stateful-write`         | Grants write-only permissions to stateful indices.                             | `wazuh-states-*`                         | `index`                                                                                  |
| `stateful-delete`        | Grants delete permissions to stateful indices.                                 | `wazuh-states-*`                         | `delete`                                                                                 |
| `stateless-read`         | Grants read-only permissions to stateless indices.                             | `wazuh-alerts*`, `wazuh-archives*`       | `read`                                                                                   |
| `stateless-write`        | Grants write-only permissions to stateless indices.                            | `wazuh-alerts*`, `wazuh-archives*`       | `index`                                                                                  |
| `metrics-read`           | Grants read permissions to metrics indices.                                    | `wazuh-monitoring*`, `wazuh-statistics*` | `read`                                                                                   |
| `metrics-write`          | Grants write permissions to metrics indices.                                   | `wazuh-monitoring*`, `wazuh-statistics*` | `index`                                                                                  |
| `sample-data-management` | Grants full permissions to sample data indices.                                | `*-sample-*`                             | `data_access`, `manage`                                                                  |
| `cm_subscription_read`   | Grants permissions to retrieve subscriptions for the server.                   | N/A                                      | `cluster:monitor/content_manager/subscription/get`                                                |
| `cm_subscription_write`  | Grants permissions to create and delete subscriptions for the content manager. | N/A                                      | `cluster:admin/content_manager/subscription/create`, `cluster:admin/content_manager/subscription/delete` |

## Sensitive configuration endpoints

A small set of endpoints modify configuration with a high impact on the platform. They are protected by two independent controls:

| Endpoint                                      | Method | Permission (cluster action)           |
|-----------------------------------------------|--------|---------------------------------------|
| `/_plugins/_content_manager/policy/{space}`   | `PUT`  | `cluster:admin/content_manager/policy/update`   |
| `/_plugins/_content_manager/update`           | `POST` | `cluster:admin/content_manager/update/trigger`  |
| `/_plugins/_setup/settings`                   | `PUT`  | `cluster:admin/setup/settings/update`         |

1. **RBAC** — each endpoint is gated by the cluster permission above, enforced by the OpenSearch Security plugin. Only the superuser `admin` (role `all_access`, cluster wildcard `*`) holds these permissions; no bundled standard user does — `wazuh-server` and `wazuh-dashboard` are intentionally excluded from all three. To delegate any of these actions without granting full superuser, create a dedicated role granting only the permission(s) above and map it to the chosen user.
2. **Per-endpoint disable settings** — each endpoint can be disabled independently by setting its node setting to `false`, after which it returns `403 Forbidden` for **every** caller, regardless of role (intended for externally managed deployments such as Wazuh Cloud): `plugins.content_manager.catalog.update_on_demand` (content update trigger), `plugins.content_manager.catalog.policy_update.enabled` (policy updates), and `plugins.setup.settings_update.enabled` (setup settings). See [Protecting sensitive configuration](../modules/content-manager/configuration.md#protecting-sensitive-configuration).
