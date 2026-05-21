# Authentication migration

This page describes how to migrate login configuration from Wazuh indexer 4.x to 5.x. Authentication is managed by the OpenSearch Security plugin in both versions, but 5.x ships a new set of default internal users and expects configuration files in their canonical location.

> **Important**:
> 4.x security configuration files cannot be copied directly to a 5.x installation. The default users and role mappings have changed, and configuration must be re-created against the 5.x layout described below.

## Configuration location

In 5.x, all security plugin configuration lives under:

```
/etc/wazuh-indexer/opensearch-security/
```

The relevant files are:

| File | Purpose |
| --- | --- |
| `internal_users.yml` | Local user accounts and password hashes |
| `roles.yml` | Role definitions |
| `roles_mapping.yml` | Mapping from authenticated identities to roles |
| `config.yml` | Authentication backends (internal, LDAP, SAML, OIDC, JWT, etc.) |

For the 5.x defaults, see [Access Control](../../ref/security/access-control.md).

## Default internal users in 5.x

5.x ships with a new set of internal users tailored to the Wazuh stack. The 4.x defaults are not carried over.

| User | Purpose |
| --- | --- |
| `wazuh-server` | Used by the Wazuh Server; read/write to stateful indices, write-only to stateless indices |
| `wazuh-dashboard` | Used by the Wazuh Dashboard; read access across most indices, management permissions on metrics indices |

A full list of the default users and roles, together with their permissions, is available in [Access Control](../../ref/security/access-control.md).

## Migration procedure

Perform these steps on the new 5.x host. The 4.x cluster is not modified by this procedure.

1. Locate the 4.x security configuration files under `/etc/wazuh-indexer/opensearch-security/` on the previous installation.
2. On the new 5.x host, do **not** overwrite the shipped files. Edit them in place under `/etc/wazuh-indexer/opensearch-security/`.
3. For each custom entry in the 4.x files, decide whether it should be re-created in 5.x:
    - Custom internal users → add to `internal_users.yml` (regenerate password hashes with the bundled hash tool).
    - Custom roles → add to `roles.yml` keeping the 5.x index patterns and permission names.
    - Role mappings → add to `roles_mapping.yml` referencing the new role names.
    - External authentication backends (LDAP, SAML, OIDC, JWT, Kerberos) → re-create the corresponding `authc` / `authz` blocks in `config.yml`.
4. Apply the configuration with the `securityadmin` tool shipped with the package.
5. Restart the service and verify authentication works for each backend before pointing production traffic at the new cluster.

> The exact syntax for each authentication backend (LDAP, SAML, OIDC, etc.) is defined and maintained by the upstream OpenSearch Security plugin and may evolve between OpenSearch versions. Always cross-check the backend configuration against the upstream documentation referenced below before applying it.

## External authentication backends

Wazuh indexer 5.x supports the same backends as the underlying OpenSearch Security plugin, including LDAP, Active Directory, SAML, OIDC, JWT, Kerberos, and client-certificate authentication. The migration steps are identical regardless of backend: re-create the `authc` and `authz` blocks in `config.yml` against the 5.x schema, then apply with `securityadmin`.

Refer to the upstream OpenSearch Security documentation for the exact syntax of each backend:

- [OpenSearch Security — Access control](https://docs.opensearch.org/3.5/security/access-control/index/)
- [OpenSearch Security — Authentication backends](https://docs.opensearch.org/3.5/security/authentication-backends/authc-index/)
- [OpenSearch Security — Configuration](https://docs.opensearch.org/3.5/security/configuration/index/)

## Related documentation

- [Migration Guide](README.md) — entry point and prerequisites
- [Configuration migration](configuration.md) — main configuration files
- [Access Control](../../ref/security/access-control.md) — 5.x default users and roles
- [Defining Users and Roles](../../ref/security/defining-users-and-roles.md) — how to declare new users and roles in 5.x
