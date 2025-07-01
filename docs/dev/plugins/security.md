# OpenSearch Security Plugin - Security Configuration

This document provides an overview of the OpenSearch Security Plugin configuration customized for the Wazuh Indexer, including internal users, roles, and their mappings.

## Wazuh default Internal Users

Wazuh defines internal users and roles for the different Wazuh components to handle index management.

These users and roles are defined in the `internal_users.wazuh.yml`, `roles.wazuh.yml`, and `roles_mapping.wazuh.yml` files on the `distribution/src/config/security` directory from the [Wazuh Indexer repository](https://github.com/wazuh/wazuh-indexer).
> Find more info about the configurations files in the [Configuration Files](/ref/configuration/configuration-files.md) section.


### Users

| User             | Description                                                                                     | Roles                                                                                                                       |
| ---------------- | ----------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `wazuh-server`    | Server-side user with read/write access to stateful and write-only access to stateless.         | `stateless-write`, `stateful-delete`, `stateful-write`, `stateful-read`|
| `wazuh-dashboard` | Dashboard user with read access to stateful/stateless, and write access to monitoring indices.  | `sample-data-management`, `metrics-write`, `metrics-read`, `stateless-read`, `stateful-read` |

### Roles

| Role Name                | Access Description                                                   | Index Patterns                           | Permissions                         |
| ------------------------ | -------------------------------------------------------------------- | ---------------------------------------- | ----------------------------------- |
| `stateful-read`          | Read-only access to stateful index data                              | `wazuh-states-*`                         | `read`                              |
| `stateful-write`         | Write-only access to stateful index data                             | `wazuh-states-*`                         | `index`                             |
| `stateful-delete`        | Delete access to stateful index data                                 | `wazuh-states-*`                         | `delete`                            |
| `stateless-read`         | Read-only access to stateless alert and archive indexes              | `wazuh-alerts*`, `wazuh-archives*`       | `read`                              |
| `stateless-write`        | Write-only access to stateless alert and archive indexes             | `wazuh-alerts*`, `wazuh-archives*`       | `index`                             |
| `metrics-read`           | Read access to monitoring and statistics indexes                     | `wazuh-monitoring*`, `wazuh-statistics*` | `read`                              |
| `metrics-write`          | Write access to monitoring and statistics indexes                    | `wazuh-monitoring*`, `wazuh-statistics*` | `index`                             |
| `sample-data-management` | Full access to internal dashboard sample data                        | `*-sample-*`                             | `data_access`, `manage`             |



## Creating a New Internal User and its Roles

_The following steps requires to have the [Wazuh Indexer repository](https://github.com/wazuh/wazuh-indexer) cloned_

### 1. Add a New Internal User

Edit the `internal_users.wazuh.yml` file located at: `distribution/src/config/security/` from the Wazuh Indexer repository,
adding a new user entry with the following structure:
```yaml
new-user:
  # The hash can be generated using the OpenSearch tool `plugins/opensearch-security/tools/hash.sh -p <new-password>`
  hash: "<HASHED-PASSWORD>"
  reserved: false
  backend_roles: []
  description: "New user description"
```

### 2. Add a New Role

Edit the `roles.wazuh.yml` file located at: `distribution/src/config/security/` from the Wazuh Indexer repository, add as
many roles as needed following this structure:

_You can see more possible actions for `cluster_permissions`, `index_permissions` on the [Default action groups documentation](https://docs.opensearch.org/docs/latest/security/access-control/default-action-groups/)_

```yaml
role-read:
   cluster_permissions: []
   index_permissions:
     - index_patterns:
         - "wazuh-*"
       dls: ""
       fls: []
       masked_fields: []
       allowed_actions:
         - "read"
   tenant_permissions: []
   static: true

role-write:
   cluster_permissions: []
   index_permissions:
     - index_patterns:
         - "wazuh-*"
       dls: ""
       fls: []
       masked_fields: []
       allowed_actions:
         - "index"
   tenant_permissions: []
   static: true
```

### 3. Add the Role Mapping

Edit the `roles_mapping.wazuh.yml` file located at: `distribution/src/config/security/` from the Wazuh Indexer repository,
adding the new role mapping, note that the mapping name must match the role name:
```yaml
role-read:
   reserved: true
   hidden: false
   backend_roles: [ ]
   hosts: [ ]
   users:
     - "new-user"
   and_backend_roles: [ ]

role-write:
   reserved: true
   hidden: false
   backend_roles: [ ]
   hosts: [ ]
   users:
     - "new-user"
   and_backend_roles: [ ]
```
