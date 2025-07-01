# Configuration Files

## Security Plugin

Wazuh Indexer uses the OpenSearch Security Plugin to manage access control and security features.

The configuration files for the security plugin are located in the `distribution/src/config/security` directory of the Wazuh Indexer repository.

> More information about the Access Control and Security Plugin can be found in the [OpenSearch documentation](https://docs.opensearch.org/docs/latest/security/access-control/index/).

#### `roles.wazuh.yml`

This file defines the roles and their permissions for the Wazuh Indexer. Each role specifies the cluster permissions, index permissions, and tenant permissions.

```yaml
stateful-read:
  cluster_permissions: []
  index_permissions:
  - index_patterns:
    - "wazuh-states-*"
    dls: ""
    fls: []
    masked_fields: []
    allowed_actions:
    - "read"
  tenant_permissions: []
  static: true

stateful-write:
  cluster_permissions: []
  index_permissions:
  - index_patterns:
    - "wazuh-states-*"
    dls: ""
    fls: []
    masked_fields: []
    allowed_actions:
    - "index"
  tenant_permissions: []
  static: true

stateful-delete:
  cluster_permissions: []
  index_permissions:
  - index_patterns:
    - "wazuh-states-*"
    dls: ""
    fls: []
    masked_fields: []
    allowed_actions:
    - "delete"
  tenant_permissions: []
  static: true

stateless-read:
  cluster_permissions: []
  index_permissions:
  - index_patterns:
    - "wazuh-alerts*"
    - "wazuh-archives*"
    dls: ""
    fls: []
    masked_fields: []
    allowed_actions:
    - "read"
  tenant_permissions: []
  static: true

stateless-write:
  cluster_permissions: []
  index_permissions:
  - index_patterns:
    - "wazuh-alerts*"
    - "wazuh-archives*"
    dls: ""
    fls: []
    masked_fields: []
    allowed_actions:
    - "index"
  tenant_permissions: []
  static: true

metrics-read:
  cluster_permissions: []
  index_permissions:
  - index_patterns:
    - "wazuh-monitoring*"
    - "wazuh-statistics*"
    dls: ""
    fls: []
    masked_fields: []
    allowed_actions:
    - "read"
  tenant_permissions: []
  static: true

metrics-write:
  cluster_permissions: []
  index_permissions:
  - index_patterns:
    - "wazuh-monitoring*"
    - "wazuh-statistics*"
    dls: ""
    fls: []
    masked_fields: []
    allowed_actions:
    - "index"
  tenant_permissions: []
  static: true

sample-data-management:
  cluster_permissions: []
  index_permissions:
  - index_patterns:
    - "*-sample-*"
    dls: ""
    fls: []
    masked_fields: []
    allowed_actions:
    - "data_access"
    - "manage"
  tenant_permissions: []
  static: true
```

#### internal_users.wazuh.yml

This file defines the internal users for the Wazuh Indexer. Each user has a hashed password, reserved status, backend roles, and a description.

```yaml
wazuh-server:
  # The hash is the hash of the password "wazuh-server"
  hash: "$2y$12$4pwjkynhYg09QJtJ5zxAcuqUSOV8JBziFDca6u9cV/H9oglVCGZEW"
  reserved: true
  backend_roles: []
  description: "Wazuh Server user with read/write access to stateful and write-only access to stateless indexes."

wazuh-dashboard:
  # The hash is the hash of the password "wazuh-dashboard"
  hash: "$2y$12$Mn2XvokTfwo2NWL2AK83yOkio1qmJyZrAp0iEWqs3lz0L8ruhu9LK"
  reserved: true
  backend_roles: []
  description: "Wazuh Dashboard user with read access to stateful and stateless indexes, write access to metrics indexes and management for sample data indexes."
```

#### roles_mapping.wazuh.yml

This file maps users and backend roles to the defined roles. It specifies which users or backend roles have access to each role.

```yaml
stateful-read:
  reserved: true
  hidden: false
  backend_roles: []
  hosts: []
  users:
    - "wazuh-server"
    - "wazuh-dashboard"
  and_backend_roles: []

stateful-write:
  reserved: true
  hidden: false
  backend_roles: []
  hosts: []
  users:
    - "wazuh-server"
  and_backend_roles: []

stateful-delete:
  reserved: true
  hidden: false
  backend_roles: []
  hosts: []
  users:
    - "wazuh-server"
  and_backend_roles: []

stateless-write:
  reserved: true
  hidden: false
  backend_roles: []
  hosts: []
  users:
    - "wazuh-server"
  and_backend_roles: []

stateless-read:
  reserved: true
  hidden: false
  backend_roles: []
  hosts: []
  users:
    - "wazuh-dashboard"
  and_backend_roles: []

metrics-read:
  reserved: true
  hidden: false
  backend_roles: []
  hosts: []
  users:
    - "wazuh-dashboard"
  and_backend_roles: []

metrics-write:
  reserved: true
  hidden: false
  backend_roles: []
  hosts: []
  users:
    - "wazuh-dashboard"
  and_backend_roles: []

sample-data-management:
  reserved: true
  hidden: false
  backend_roles: []
  hosts: []
  users:
    - "wazuh-dashboard"
  and_backend_roles: []
```
