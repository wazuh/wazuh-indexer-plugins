# Access Control

Wazuh Indexer uses the OpenSearch Security Plugin to manage access control and security features. This allows you to define users, roles, and permissions for accessing indices and performing actions within the Wazuh Indexer.

> You can find a more detailed overview of the OpenSearch Security Plugin in the [OpenSearch documentation](https://docs.opensearch.org/docs/latest/security/access-control/index/).

## Wazuh default Internal Users

Wazuh defines internal users and roles for the different Wazuh components to handle index management.

These users and roles are defined in the `internal_users.wazuh.yml`, `roles.wazuh.yml`, and `roles_mapping.wazuh.yml` files on the `distribution/src/config/security` directory from the [Wazuh Indexer repository](https://github.com/wazuh/wazuh-indexer).
> Find more info about the configurations files in the [Configuration Files](/ref/configuration/configuration-files.md) section.

### Users

| User              | Description                                                                                    | Roles                                                                                        |
|-------------------|------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------|
| `wazuh-server`    | Server-side user with read/write access to stateful and write-only access to stateless.        | `stateless-write`, `stateful-delete`, `stateful-write`, `stateful-read`                      |
| `wazuh-dashboard` | Dashboard user with read access to stateful/stateless, and write access to monitoring indices. | `sample-data-management`, `metrics-write`, `metrics-read`, `stateless-read`, `stateful-read` |

### Roles

| Role Name                | Access Description                                       | Index Patterns                           | Permissions             |
|--------------------------|----------------------------------------------------------|------------------------------------------|-------------------------|
| `stateful-read`          | Read-only access to stateful index data                  | `wazuh-states-*`                         | `read`                  |
| `stateful-write`         | Write-only access to stateful index data                 | `wazuh-states-*`                         | `index`                 |
| `stateful-delete`        | Delete access to stateful index data                     | `wazuh-states-*`                         | `delete`                |
| `stateless-read`         | Read-only access to stateless alert and archive indexes  | `wazuh-alerts*`, `wazuh-archives*`       | `read`                  |
| `stateless-write`        | Write-only access to stateless alert and archive indexes | `wazuh-alerts*`, `wazuh-archives*`       | `index`                 |
| `metrics-read`           | Read access to monitoring and statistics indexes         | `wazuh-monitoring*`, `wazuh-statistics*` | `read`                  |
| `metrics-write`          | Write access to monitoring and statistics indexes        | `wazuh-monitoring*`, `wazuh-statistics*` | `index`                 |
| `sample-data-management` | Full access to internal dashboard sample data            | `*-sample-*`                             | `data_access`, `manage` |
