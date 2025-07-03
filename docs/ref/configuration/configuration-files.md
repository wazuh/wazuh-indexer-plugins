# Configuration Files

## Security - Access Control

Wazuh Indexer uses the OpenSearch Security Plugin to manage access control and security features.

The configuration files for the security plugin are located under the `/etc/wazuh-indexer/opensearch-security/` directory,
even though it is recommended to create new users and roles through the Wazuh Dashboard by following the guide [Define Users and Roles](/ref/security/defining-users-and-roles.md),
you can also edit the configuration files directly.

These files include:

- **`roles.yml`**: Defines the roles and their permissions for the Wazuh Indexer. Each role specifies the cluster permissions, index permissions, and tenant permissions.

- **`internal_users.yml`**: Defines the internal users for the Wazuh Indexer. Each user has a hashed password, reserved status, backend roles, and a description.

- **`roles_mapping.yml`**: Maps users and backend roles to the defined roles. This file specifies which users or backend roles have access to each role.

> To test the access control configuration, you can follow the step _4. Test Access_ from the [Define Users and Roles](/ref/security/defining-users-and-roles.md) guide.
