# OpenSearch Security Plugin - Security Configuration

This document provides an overview of the OpenSearch Security Plugin configuration customized for the Wazuh Indexer, including internal users, roles, and their mappings.

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

---

### Testing the New User and Role

The new user and role can be validated by configuring them on the [Configuration Files](/ref/configuration/configuration-files.md) of a running the Wazuh Indexer.

> **Prerequisites**
>  * You must have a running Wazuh Indexer instance.

1. Edit the `roles_mapping.yml`, `roles.yml`, and `internal_users.yml` files on `/etc/wazuh-indexer/opensearch-security/`.
2. Restart the Wazuh Indexer service to apply the changes:
    ```bash
    sudo systemctl restart wazuh-indexer
    ```
3. Use the Wazuh Indexer API or the Wazuh Dashboard to test the new user and role:
    > For the Wazuh Dashboard, follow the step _4. Test Access_ from the [Define Users and Roles](/ref/security/defining-users-and-roles.md) guide.

    *Testing using the Wazuh Indexer API:*
    You can use `curl` commands to validate the created user has the correct access to the index/cluster.
    * Validate the write access using following command:
        ```bash
        curl -u new-user:<new-password> -X POST "https://<wazuh-indexer-host>:9200/wazuh-test/_doc" -H 'Content-Type: application/json' -d '{"test": "data"}'
        ```
    * Validate the read access using following command:
        ```bash
        curl -u new-user:<new-password> -X GET "https://<wazuh-indexer-host>:9200/wazuh-test/_search"
        ```
