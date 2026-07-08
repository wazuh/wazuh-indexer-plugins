# Access Control

Wazuh Indexer uses the OpenSearch Security plugin to manage access control and security features. This allows you to define users, roles, and permissions for accessing indices and performing actions within the Wazuh Indexer.

> You can find a more detailed overview of the OpenSearch Security plugin in the [OpenSearch documentation](https://docs.opensearch.org/3.6/security/access-control/index/).

## Wazuh default Internal Users

Wazuh defines internal users and roles for the different Wazuh components to handle index management.

These default users and roles definitions are stored in the `internal_users.yml`, `roles.yml`, and `roles_mapping.yml` files on the `/etc/wazuh-indexer/opensearch-security/` directory. Content Manager permission names are resolved through action groups defined in `action_groups.yml`.
> Find more info about the configurations files in the [Configuration files](./index.md#configuration-files) section.

### Users

Each default user is mapped 1:1 to the role of the matching name in `roles_mapping.yml`. The `wazuh-admin` user is additionally reachable through the `admin` backend role.

| User             | Mapped role      | Description                                                                                                                                                                                                                                                    |
| ---------------- | ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `wazuh-manager`  | `wazuh_manager`  | Service account for the Wazuh Manager: read/write on stateless (events, metrics) indices, read/write/delete on stateful (states) indices, and read on consumers, threat intelligence and active-responses.                                                     |
| `wazuh-admin`    | `wazuh_admin`    | Administrator: read access to all Wazuh indices, write access to Wazuh settings, full Content Manager and Security Analytics access, and management of alerting, notifications, reporting and index management. Excludes super-admin (security configuration). |
| `wazuh-demo`     | `wazuh_demo`     | Default interactive user: read data, manage threat intelligence content, full Content Manager content operations and Security Analytics, and read-only alerting, notifications, reporting and index management.                                                |
| `wazuh-readonly` | `wazuh_readonly` | Read-only access to indices, settings, subscriptions and Security Analytics (detectors, findings, alerts).                                                                                                                                                     |
> **Security note:** The bundled password hashes decode to the username. Change every default password immediately after installation.

### Roles

Five default roles are defined in `roles.yml`. Each role is self-contained (it grants everything its user needs on its own) and is `reserved` - it cannot be edited in place. To customize, duplicate the role and edit the copy (see [Defining Users and Roles](./defining-users-and-roles.md)).

#### `wazuh_manager`

Service account used by the Wazuh Manager for data ingestion and content reads.

**Cluster permissions:** `cluster_composite_ops`, `cluster_monitor`.

| Index pattern                                                            | Permissions               |
| ------------------------------------------------------------------------ | ------------------------- |
| `.wazuh-cti-consumers`, `wazuh-active-responses*`, `wazuh-threatintel-*` | `read`                    |
| `wazuh-events-v5-*`, `wazuh-metrics-*`                                   | `read`, `index`           |
| `wazuh-states-*`                                                         | `read`, `index`, `delete` |
| `.wazuh-threatintel-vulnerabilities*`, `wazuh-threatintel-*`             | `manage_point_in_time`    |

#### `wazuh_admin`

Full access to all Wazuh features, excluding super-admin features such as the security configuration.

**Cluster permissions:**

- Base: `cluster_composite_ops`, `cluster_monitor`
- Wazuh settings (setup plugin): `plugin:wazuh/settings/write`
- Content Manager: full
- Security Analytics: full
- Alerting: full

| Index pattern                              | Permissions                                                                                                                                          |
| ------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `*`, `.kibana*`                            | `get`, `read`, `indices:admin/aliases/get`, `indices:admin/opensearch/ism/*`, `indices:internal/plugins/replication/index/stop`, `indices:monitor/*` |
| `.wazuh-settings`                          | `read`, `index`                                                                                                                                      |
| `wazuh-events-v5*`                         | `index`                                                                                                                                              |
| `.wazuh-internal-state`                    | `read`, `index`, `delete`                                                                                                                            |
| `wazuh-threatintel-*`, `.opensearch-sap-*` | `index`, `delete`, `indices:admin/exists`, `indices:admin/refresh`                                                                                   |

#### `wazuh_demo`

Default interactive user: can visualize data and manage threat intelligence / Content Manager content.

**Cluster permissions:**

- Base: `cluster_composite_ops`, `cluster_monitor`
- Content Manager: full content operations(no subscription create/delete, no policy update)
- Security Analytics: full
- Alerting, Notifications, Reporting, Index management: **read-only**

| Index pattern                              | Permissions                                                        |
| ------------------------------------------ | ------------------------------------------------------------------ |
| `*`, `.kibana*`                            | `get`, `read`, `indices:admin/aliases/get`, `indices:monitor/*`    |
| `.wazuh-internal-state`                    | `read`                                                             |
| `wazuh-threatintel-*`, `.opensearch-sap-*` | `index`, `delete`, `indices:admin/exists`, `indices:admin/refresh` |

#### `wazuh_readonly`

Read-only access across the platform.

**Cluster permissions:**

- Base: `cluster_composite_ops`, `cluster_monitor`
- Content Manager: `subscription/get`, `logtest*`, `version/check`
- Security Analytics: read-only (`cluster:admin/opensearch/securityanalytics/*` get/search actions) plus `rules/evaluate`
- Alerting, Notifications, Reporting, Index management: **read-only**

| Index pattern           | Permissions                                                     |
| ----------------------- | --------------------------------------------------------------- |
| `*`, `.kibana*`         | `get`, `read`, `indices:admin/aliases/get`, `indices:monitor/*` |
| `.wazuh-settings`       | `read`                                                          |
| `.wazuh-internal-state` | `read`                                                          |


## Sensitive configuration endpoints

A small set of endpoints modify configuration with a high impact on the platform. They are protected by two independent controls:

| Endpoint                                    | Method | Permission (cluster action)                    |
| ------------------------------------------- | ------ | ---------------------------------------------- |
| `/_plugins/_content_manager/policy/{space}` | `PUT`  | `cluster:admin/content_manager/policy/update`  |
| `/_plugins/_content_manager/update`         | `POST` | `cluster:admin/content_manager/update/trigger` |
| `/_plugins/_setup/settings`                 | `PUT`  | `plugin:wazuh/settings/write`                  |

1. **RBAC** - each endpoint is gated by the cluster permission above, enforced by the OpenSearch Security plugin. Among the bundled users, only `wazuh-admin` holds these permissions; `wazuh-manager`, `wazuh-demo` and `wazuh-readonly` are excluded. The superuser `admin` (role `all_access`, cluster wildcard `*`) also holds them. To delegate any of these actions without granting full superuser, create a dedicated role granting only the permission(s) above and map it to the chosen user.
2. **Per-endpoint disable settings** - each endpoint can be disabled independently by setting its node setting to `false`, after which it returns `403 Forbidden` for **every** caller, regardless of role (intended for externally managed deployments such as Wazuh Cloud): `plugins.content_manager.catalog.update_on_demand` (content update trigger), `plugins.content_manager.catalog.policy_update.enabled` (policy updates), and `plugins.setup.settings_update.enabled` (setup settings). See [Protecting sensitive configuration](../modules/content-manager/configuration.md#protecting-sensitive-configuration).
