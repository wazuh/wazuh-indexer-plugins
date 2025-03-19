## Wazuh RBAC

The Wazuh Role-Based Access Control (RBAC) system and its resources are now managed within the indexer. This template is shared by both `wazuh-internal-users` and `wazuh-custom-users` indices, defining fields for user roles, rules, and policies.

- wazuh-internal-users: Default users and roles built-in with Wazuh.
- wazuh-custom-users: Users and roles created by the admin.

The detail of the fields can be found in csv file [Users Fields](https://github.com/wazuh/wazuh-indexer-plugins/blob/main/ecs/users/docs/fields.csv).
