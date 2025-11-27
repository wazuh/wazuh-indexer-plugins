# Defining default users and roles for Wazuh Indexer

The Wazuh Indexer packages include a set of default users and roles specially crafted for Wazuh's use cases.
This guide provides instructions to extend or modify these users and roles so they end up being included in the Wazuh Indexer package by default.

Note that the access control and permissions management are handled by the OpenSearch's security plugin. As a result, we provide configuration files for it. The data is applied during the cluster's initialization, as a result of running the `indexer-security-init.sh` script.

## Considerations and conventions

As these configuration files are included in the Wazuh Indexer package, they are hosted in the `wazuh-indexer` repository. Be aware of that when reading this guide.

Any security related resource (roles, action groups, users, ...) created by us **must be reserved** (`reserved: true`). This ensures they cannot be modified by the users, in order to guarantee the correct operation of Wazuh Central Components. Also, they should be visible (`hidden: false`) unless explicitly defined otherwise.

## 1. Adding a new user

Add the new user to the `internal_users.wazuh.yml` file located at: `wazuh-indexer/distribution/src/config/security/`.
```yaml
new-user:
  # Generate the hash using the tool at `plugins/opensearch-security/tools/hash.sh -p <new-password>`
  hash: "<HASHED-PASSWORD>"
  reserved: true
  hidden: false
  backend_roles: []
  description: "New user description"
```
OpenSearch's reference:
- [internal_users.yml](https://docs.opensearch.org/docs/latest/security/configuration/yaml/#internal_usersyml)
## 2. Adding a new role
Add the new role to the `roles.wazuh.yml` file located at: `wazuh-indexer/distribution/src/config/security/`.
- Under `index_permissions.index_patterns`, list the index patterns the role will have effect on.
- Under `index_permissions.allowed_actions`, list the allowed action groups or indiviual permissions granted to this role.

_The default action groups for `cluster_permissions` and `index_permissions` are listed in the [Default action groups documentation](https://docs.opensearch.org/docs/latest/security/access-control/default-action-groups/)_

```yaml
role-read:
   reserved: true
   hidden: false
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
   reserved: true
   hidden: false
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

OpenSearch's reference: 
- [roles.yml](https://docs.opensearch.org/docs/latest/security/configuration/yaml/#rolesyml)
- [action_groups.yml](https://docs.opensearch.org/docs/latest/security/configuration/yaml/#action_groupsyml)
- [Default action groups](https://docs.opensearch.org/docs/latest/security/access-control/default-action-groups/)

## 3. Adding a new role mapping 

Add the new role mapping to `roles_mapping.wazuh.yml` file located at: `wazuh-indexer/distribution/src/config/security/`. Note that **the mapping name must match the role name**.
- Under `users`, list the users the role will be mapped to.

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

OpenSearch's reference: 
- [roles_mapping.yml](https://docs.opensearch.org/docs/latest/security/configuration/yaml/#roles_mappingymll)

## Testing the configuration

The validation of the new configuration needs to be tested on a running deployment of Wazuh Indexer containing the security plugin.

You can follow any of these paths:

### A. Generating a new Wazuh Indexer package

1. Apply your changes to the configuration files in `wazuh-indexer/distribution/src/config/security/`.
2. Generate a new package (see [Build Packages](../build-packages.md)).
3. Follow the official installation and configuration steps.
4. Check the new changes are applied (you can use the UI or the API).

### B. Applying the new configuration to an existing Wazuh Indexer deployment (using the UI or API)

1. Use the Wazuh Indexer API or the Wazuh Dashboard to create a new security resource. Follow the steps in [Defining users and roles](https://docs.opensearch.org/docs/latest/security/access-control/users-roles).

### C. Applying the new configuration to an existing Wazuh Indexer deployment (using configuration files)

1. Add the new configuration to the affected file within `/etc/wazuh-indexer/opensearch-security/`.
2. Run the `/usr/share/wazuh-indexer/bin/indexer-security-init.sh` script to load the new configuration.

<div class="warning">

The `indexer-security-init.sh` will overwrite your security configuration, including passwords. Use it under your own risk.

Alternatively, apply the new configuration using fine-grained options. See [Applying changes to configuration files](https://docs.opensearch.org/docs/latest/security/configuration/security-admin/)

</div>