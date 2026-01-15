# Access Control

Wazuh Indexer uses the OpenSearch Security plugin to manage access control and security features. This allows you to define users, roles, and permissions for accessing indices and performing actions within the Wazuh Indexer.

> You can find a more detailed overview of the OpenSearch Security plugin in the [OpenSearch documentation](https://docs.opensearch.org/3.3/security/access-control/index/).

## Wazuh default Internal Users

Wazuh defines internal users and roles for the different Wazuh components to handle index management.

These default users and roles definitions are stored in the `internal_users.yml`, `roles.yml`, and `roles_mapping.yml` files on the `/etc/wazuh-indexer/opensearch-security/` directory.
> Find more info about the configurations files in the [Configuration Files](/ref/configuration/configuration-files.md) section.

### Users

| User              | Description                                                                                                                              | Roles                                                                                                                              |
|-------------------|------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------|
| `wazuh-server`    | User for the Wazuh Server with read/write access to stateful indices and write-only access to stateless indices.                         | `stateless-write`, `stateful-delete`, `stateful-write`, `stateful-read`, `cm_subscription_read`                                    |
| `wazuh-dashboard` | User for Wazuh Dashboard with read access to stateful and stateless indices, and management level permissionsfor the monitoring indices. | `sample-data-management`, `metrics-write`, `metrics-read`, `stateless-read`, `stateful-read`, `cm_update`, `cm_subscription_write` |

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
| `cm_subscription_read`   | Grants permissions to retrieve subscriptions for the server.                   | N/A                                      | `plugin:content_manager/subscription_get`                                                |
| `cm_subscription_write`  | Grants permissions to create and delete subscriptions for the content manager. | N/A                                      | `plugin:content_manager/subscription_post`, `plugin:content_manager/subscription_delete` |
| `cm_update`              | Grants permissions to perform update operations in the content manager.        | N/A                                      | `plugin:content_manager/update`                                                          |
