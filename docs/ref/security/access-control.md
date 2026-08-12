# Access Control

Wazuh Indexer uses the OpenSearch Security plugin to manage access control and security features. This allows you to define users, roles, and permissions for accessing indices and performing actions within the Wazuh Indexer.

> You can find a more detailed overview of the OpenSearch Security plugin in the [OpenSearch documentation](https://docs.opensearch.org/3.6/security/access-control/index/).

## Wazuh default Internal Users

Wazuh defines internal users and roles for the different Wazuh components to handle index management.

These default users and roles definitions are stored in the `internal_users.yml`, `roles.yml`, and `roles_mapping.yml` files on the `/etc/wazuh-indexer/opensearch-security/` directory. Content Manager permission names are resolved through action groups defined in `action_groups.yml`.
> Find more info about the configurations files in the [Configuration files](./index.md#configuration-files) section.

### Users

Each default user is mapped 1:1 to the role of the matching name in `roles_mapping.yml`. The `wazuh-admin` user is additionally reachable through the `admin` backend role.

- **`wazuh-manager`** → `wazuh_manager` — service account for the Wazuh Manager: read/write on stateless (events, metrics) indices, read/write/delete on stateful (states) indices, and read on consumers, threat intelligence and active-responses.
- **`wazuh-admin`** → `wazuh_admin` — administrator: read access to all Wazuh indices, write access to Wazuh settings, full Content Manager and Security Analytics access, and management of alerting, notifications, reporting and index management. Excludes super-admin (security configuration).
- **`wazuh-demo`** → `wazuh_demo` — default interactive user: read data, manage threat intelligence content, full Content Manager content operations and Security Analytics, and read-only alerting, notifications, reporting and index management.
- **`wazuh-readonly`** → `wazuh_readonly` — read-only access to indices, settings, subscriptions and Security Analytics (detectors, findings, alerts).

> **Security note:** The bundled password hashes decode to the username. Change every default password immediately after installation.

There is no dedicated internal user for the `dashboard_server` role below — it is mapped to the built-in OpenSearch `kibanaserver` user, which the Wazuh Dashboard authenticates as internally.

Besides the 1:1 roles, `wazuh_ai_assistant` is mapped to **every** authenticated user. It is the only role not tied to a single user, and exists to attach a Document Level Security query to an index.

### Roles

Seven default roles are defined in `roles.yml`. Each role is self-contained (it grants everything its user needs on its own) and is `reserved` - it cannot be edited in place. To customize, duplicate the role and edit the copy (see [Defining Users and Roles](./defining-users-and-roles.md)).

#### `dashboard_server`

Internal service account used by the Wazuh Dashboard to read notification configs and query Wazuh indices on behalf of dashboard users. Mapped to the built-in `kibanaserver` user, not to any `wazuh-*` user.

- **Cluster permissions:** `cluster:admin/opensearch/notifications/configs/get`.
- **Index permissions:** `read` on `wazuh-*`.

#### `wazuh_manager`

Service account used by the Wazuh Manager for data ingestion and content reads.

- **Cluster permissions:** `cluster_composite_ops`, `cluster_monitor`.
- **Index permissions:**
  - `read` on `.wazuh-settings`.
  - `read` on `.wazuh-cti-consumers`, `wazuh-active-responses*`, `wazuh-threatintel-*`.
  - `read`, `index` on `wazuh-events-v5-*`, `wazuh-metrics-*`.
  - `read`, `index`, `delete` on `wazuh-states-*`.
  - `manage_point_in_time` on `.wazuh-threatintel-vulnerabilities*`, `wazuh-threatintel-*`.

#### `wazuh_admin`

Full access to all Wazuh features, excluding super-admin features such as the security configuration.

- **Cluster permissions:**
  - Base: `cluster_composite_ops`, `cluster_monitor`.
  - Wazuh settings (setup plugin): `plugin:wazuh/settings/write`.
  - AI assistant sessions (setup plugin): `plugin:wazuh/ai_assistant/sessions/read`, `plugin:wazuh/ai_assistant/sessions/write` — see [AI assistant administrative sessions API](#ai-assistant-administrative-sessions-api) below.
  - AI assistant settings (setup plugin): `plugin:wazuh/ai_assistant/settings/read`, `plugin:wazuh/ai_assistant/settings/write` — see [AI assistant administrative API](#ai-assistant-administrative-api) below.
  - Content Manager: full.
  - Security Analytics: full (both the Wazuh custom actions and the upstream OpenSearch Security Analytics actions).
  - Alerting: full.
  - Anomaly detection: detector operations.
  - Notifications: full.
  - Reporting: full.
  - Index management: full (ISM, rollups, transforms).
- **Index permissions:**
  - `get`, `read`, `indices:admin/aliases/get`, `indices:admin/opensearch/ism/*`, `indices:internal/plugins/replication/index/stop`, `indices:monitor/*` on `*`, `.kibana*`.
  - `read`, `index` on `.wazuh-settings`.
  - `index` on `wazuh-events-v5*`.
  - `read`, `index`, `delete` on `.wazuh-internal-state`.
  - `index`, `delete`, `indices:admin/exists`, `indices:admin/refresh` on `wazuh-threatintel-*`, `.opensearch-sap-*`.

#### `wazuh_demo`

Default interactive user: can visualize data and manage threat intelligence / Content Manager content.

- **Cluster permissions:**
  - Base: `cluster_composite_ops`, `cluster_monitor`.
  - AI assistant sessions (setup plugin): `plugin:wazuh/ai_assistant/sessions/read`.
  - AI assistant settings (setup plugin): `plugin:wazuh/ai_assistant/settings/read`.
  - Content Manager: full content operations (no subscription create/delete, no policy update).
  - Security Analytics: full (both the Wazuh custom actions and the upstream OpenSearch Security Analytics actions).
  - Alerting, Anomaly detection, Notifications, Reporting, Index management: **read-only**.
- **Index permissions:**
  - `get`, `read`, `indices:admin/aliases/get`, `indices:monitor/*` on `*`, `.kibana*`.
  - `read` on `.wazuh-internal-state`.
  - `index`, `delete`, `indices:admin/exists`, `indices:admin/refresh` on `wazuh-threatintel-*`, `.opensearch-sap-*`.

#### `wazuh_readonly`

Read-only access across the platform.

- **Cluster permissions:**
  - Base: `cluster_composite_ops`, `cluster_monitor`.
  - AI assistant sessions (setup plugin): `plugin:wazuh/ai_assistant/sessions/read`.
  - AI assistant settings (setup plugin): `plugin:wazuh/ai_assistant/settings/read`.
  - Content Manager: `subscription/get`, `logtest*`, `version/check`.
  - Security Analytics: read-only (upstream `cluster:admin/opensearch/securityanalytics/*` get/search/list actions) plus the Wazuh custom `rules/evaluate`.
  - Alerting, Anomaly detection, Notifications, Reporting, Index management: **read-only**.
- **Index permissions:**
  - `get`, `read`, `indices:admin/aliases/get`, `indices:monitor/*` on `*`, `.kibana*`.
  - `read` on `.wazuh-settings`.
  - `read` on `.wazuh-internal-state`.

#### `wazuh_ai_assistant`

Grants every authenticated user access to their own AI assistant conversations, stored in the `wazuh-ai-assistant-sessions` data stream. Mapped to `*` (all users) in `roles_mapping.yml`.

- **Cluster permissions:** none.
- **Index permissions:**
  - `read` on `wazuh-ai-assistant-sessions*`, `.ds-wazuh-ai-assistant-sessions-*`, restricted with the DLS query `{"term": {"user": "${user.name}"}}`.
  - `write` on the same patterns, with no DLS query (DLS filters reads, not writes).

`${user.name}` is substituted at query time with the name of the authenticated user, so each user retrieves only the conversations whose `user` field holds their own username.

## AI assistant administrative sessions API

The per-owner DLS above blocks even `wazuh-admin`/`admin` from reading anyone else's conversations — deliberately, since the DLS is what makes `wazuh_ai_assistant` safe to map to every user. Administrators and the Dashboard backend still need a way to operate on any user's sessions for support, audit or moderation, without weakening that isolation. This is exposed as a privileged API in the setup plugin rather than by adding index permissions:

| Endpoint | Method | Cluster permission |
| --- | --- | --- |
| `/_plugins/_setup/ai_assistant/sessions` | `GET` | `plugin:wazuh/ai_assistant/sessions/read` |
| `/_plugins/_setup/ai_assistant/sessions/{id}` | `DELETE` | `plugin:wazuh/ai_assistant/sessions/write` |

Both cluster permissions are defined in `action_groups.wazuh.yml`, following the same pattern as `plugin:wazuh/settings/write`.

`wazuh_admin` holds both permissions (read + write). `wazuh_demo` and `wazuh_readonly` hold read only. `dashboard_server` and `wazuh_manager` hold neither.

## AI assistant administrative API

The AI assistant's providers configuration, assistant-wide settings and field policy live together in the hidden `.wazuh-internal-state` index.

| Endpoint | Method | Cluster permission |
| --- | --- | --- |
| `/_plugins/_setup/ai_assistant/settings` | `GET` | `plugin:wazuh/ai_assistant/settings/read` |
| `/_plugins/_setup/ai_assistant/settings` | `PUT` | `plugin:wazuh/ai_assistant/settings/write` |
| `/_plugins/_setup/ai_assistant/providers` | `GET` | `plugin:wazuh/ai_assistant/settings/read` |
| `/_plugins/_setup/ai_assistant/providers` | `POST` | `plugin:wazuh/ai_assistant/settings/write` |
| `/_plugins/_setup/ai_assistant/providers/{id}` | `PUT`, `DELETE` | `plugin:wazuh/ai_assistant/settings/write` |

`wazuh_admin` holds both permissions (read + write). `wazuh_demo` and `wazuh_readonly` hold read only. `dashboard_server` and `wazuh_manager` hold neither.

## Sensitive configuration endpoints

A small set of endpoints modify configuration with a high impact on the platform. They are protected by two independent controls:

| Endpoint                                    | Method | Permission (cluster action)                    |
| ------------------------------------------- | ------ | ---------------------------------------------- |
| `/_plugins/_content_manager/policy/{space}` | `PUT`  | `cluster:admin/content_manager/policy/update`  |
| `/_plugins/_content_manager/update`         | `POST` | `cluster:admin/content_manager/update/trigger` |
| `/_plugins/_setup/settings`                 | `PUT`  | `plugin:wazuh/settings/write`                  |

1. **RBAC** - each endpoint is gated by the cluster permission above, enforced by the OpenSearch Security plugin. Among the bundled users, only `wazuh-admin` holds these permissions; `wazuh-manager`, `wazuh-demo` and `wazuh-readonly` are excluded. The superuser `admin` (role `all_access`, cluster wildcard `*`) also holds them. To delegate any of these actions without granting full superuser, create a dedicated role granting only the permission(s) above and map it to the chosen user.
2. **Per-endpoint disable settings** - each endpoint can be disabled independently by setting its node setting to `false`, after which it returns `403 Forbidden` for **every** caller, regardless of role (intended for externally managed deployments such as Wazuh Cloud): `plugins.content_manager.catalog.update_on_demand` (content update trigger), `plugins.content_manager.catalog.policy_update.enabled` (policy updates), and `plugins.setup.settings_update.enabled` (setup settings). See [Protecting sensitive configuration](../modules/content-manager/configuration.md#protecting-sensitive-configuration).
