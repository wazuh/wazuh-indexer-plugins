# Access Control

Wazuh Indexer uses the OpenSearch Security plugin to manage access control and security features. This allows you to define users, roles, and permissions for accessing indices and performing actions within the Wazuh Indexer.

> You can find a more detailed overview of the OpenSearch Security plugin in the [OpenSearch documentation](https://docs.opensearch.org/3.6/security/access-control/index/).

## Wazuh default Internal Users

Wazuh defines internal users and roles for the different Wazuh components to handle index management.

These default users and roles definitions are stored in the `internal_users.yml`, `roles.yml`, and `roles_mapping.yml` files on the `/etc/wazuh-indexer/opensearch-security/` directory. Content Manager permission names are resolved through action groups defined in `action_groups.yml`.
> Find more info about the configurations files in the [Configuration files](./index.md#configuration-files) section.

### Users

One internal user ships with the indexer, mapped 1:1 to the role of the matching name in `roles_mapping.yml`:

- **`wazuh-manager`** → `wazuh_manager` — service account for the Wazuh Manager: read/write on stateless (events, metrics) indices, read/write/delete on stateful (states) indices, read/write on the agent statistics and configuration indexes, and read on consumers, threat intelligence and active-responses.

> **Security note:** The bundled password hash decodes to the username. Change the default password immediately after installation.

No administrative persona ships any more: administration goes through the built-in OpenSearch `admin` superuser, which holds `all_access`. To give somebody administrative access without handing them `all_access`, define a role with the permissions that job needs — the permission names available are listed in [Permissions](./permissions.md) — and map it to your own user (see [Defining Users and Roles](./defining-users-and-roles.md)).

There is no dedicated internal user for the `dashboard_server` role below — it is mapped to the built-in OpenSearch `kibanaserver` user, which the Wazuh Dashboard authenticates as internally.

Besides the 1:1 roles, `wazuh_ai_assistant` is mapped to **every** authenticated user. It is the only role mapped to more than one account, and exists to attach a Document Level Security query to an index.

### Roles

Three default roles are defined in `roles.yml`. Each role is self-contained (it grants everything its holder needs on its own) and is `reserved` - it cannot be edited in place. To customize, duplicate the role and edit the copy (see [Defining Users and Roles](./defining-users-and-roles.md)).

#### `dashboard_server`

Internal service account used by the Wazuh Dashboard to read notification configs and query Wazuh indices on behalf of dashboard users. Mapped to the built-in `kibanaserver` user, not to any `wazuh-*` user.

- **Cluster permissions:** `cluster:admin/opensearch/notifications/configs/get`.
- **Index permissions:** `read` on `wazuh-*`.

#### `wazuh_manager`

Service account used by the Wazuh Manager for data ingestion and content reads.

- **Cluster permissions:** `cluster_composite_ops`, `indices:data/read/scroll/clear`, `cluster_monitor`.
- **Index permissions:**
  - `read` on `.wazuh-settings`.
  - `read` on `.wazuh-cti-consumers`, `wazuh-active-responses*`, `wazuh-threatintel-*`.
  - `read`, `index` on `wazuh-events-v5-*`, `wazuh-metrics-*`.
  - `read`, `index`, `delete` on `wazuh-states-*`.
  - `read`, `index` and `delete` on `wazuh-agent-*`.
  - `manage_point_in_time` on `.wazuh-threatintel-vulnerabilities*`, `wazuh-threatintel-*`.

#### `wazuh_ai_assistant`

Grants every authenticated user access to their own AI assistant conversations, stored in the `wazuh-ai-assistant-sessions` data stream. Mapped to `*` (all users) in `roles_mapping.yml`.

- **Cluster permissions:**
  - `plugin:wazuh/ai_assistant/session/write` — the setup plugin's session write API.
- **Index permissions:**
  - `read` on `wazuh-ai-assistant-sessions*`, `.ds-wazuh-ai-assistant-sessions-*`, restricted with the DLS query `{"term": {"user": "${user.name}"}}`.

`${user.name}` is substituted at query time with the name of the authenticated user, so each user retrieves only the conversations whose `user` field holds their own username.

**Reads and writes are scoped by two different mechanisms, and the asymmetry is deliberate.** Document Level Security is a read-path filter: it cannot scope a write. A role granting index-level `write` on this data stream would therefore let any account holding it store a document naming somebody else in `user` — including one the victim then sees as their own. So the role grants no index-level `write` at all. Every write goes through `POST`/`PUT`/`PATCH`/`DELETE` on `/_plugins/_setup/ai_assistant/sessions`, gated by the cluster permission above, where the setup plugin derives `user` from the authenticated caller and discards whatever the request body said (see [Setup — API reference](../modules/setup/api-reference.md#ai-assistant-sessions)).

That is also what makes the read filter trustworthy: `user` is only a safe thing to filter on once it stops being client input.

Listing sessions and reading a transcript stay direct queries against the data stream, under the DLS filter above — there is no read endpoint, because DLS already scopes reads correctly and OpenSearch already provides search, sorting and pagination.

The per-owner DLS applies to every user, including `admin`

## Plugin-internal indices

Some indices are bookkeeping owned by a plugin rather than data a user queries. They are created by
the plugin at node startup and are only ever read or written by the plugin itself, never on behalf of
a REST caller, so **custom roles must not be given index-level privileges on them** — a role that
omits them behaves exactly the same:

| Index | Owner | Purpose |
| --- | --- | --- |
| `.wazuh-content-manager-resource-locks` | Content Manager | Short-lived mutex documents that serialize the resource-limit check when creating rules, decoders, integrations, KVDBs and filters. See [Content Manager — Resource creation lock](../modules/content-manager/architecture.md#resource-creation-lock). |
| `.wazuh-cti-consumers` | Content Manager | CTI synchronization state (status, offsets, source URL) per consumer. |
| `.wazuh-content-manager-jobs` | Content Manager | Job Scheduler metadata for the catalog sync and telemetry ping jobs. |

Where such an index has to be touched while serving a user request — the resource-creation lock is
taken and released inside a create request — the plugin stashes the caller's identity for the
duration of that operation, so it is authorized as the plugin and not as the user. This is what keeps
these indices out of every role, including custom roles that hold only `plugin:content_manager/*`
permissions. The stash is scoped to the internal index: the content operation the request came for is
still authorized against the user's own index permissions on `wazuh-threatintel-*`.

`.wazuh-internal-state` is deliberately not in this list. It is also written by the plugin in its own
context, but it is additionally declared as a security-plugin system index
(`plugins.security.system_indices.indices`), and the roles above grant it explicitly because the
Setup plugin's AI assistant endpoints read and write it on behalf of users.

## AI assistant administrative API

The AI assistant's providers configuration, assistant-wide settings and field policy live together in the hidden `.wazuh-internal-state` index.

| Endpoint | Method | Cluster permission |
| --- | --- | --- |
| `/_plugins/_setup/ai_assistant/settings` | `GET` | `plugin:wazuh/ai_assistant/settings/read` |
| `/_plugins/_setup/ai_assistant/settings` | `PUT` | `plugin:wazuh/ai_assistant/settings/write` |
| `/_plugins/_setup/ai_assistant/providers` | `GET` | `plugin:wazuh/ai_assistant/settings/read` |
| `/_plugins/_setup/ai_assistant/providers` | `POST` | `plugin:wazuh/ai_assistant/settings/write` |
| `/_plugins/_setup/ai_assistant/providers/{id}` | `PUT`, `DELETE` | `plugin:wazuh/ai_assistant/settings/write` |

No default role holds either permission: `dashboard_server` and `wazuh_manager` hold neither read nor write. Both are held only by `all_access`.

## Sensitive configuration endpoints

A small set of endpoints modify configuration with a high impact on the platform. They are protected by two independent controls:

| Endpoint                                    | Method | Permission (cluster action)                    |
| ------------------------------------------- | ------ | ---------------------------------------------- |
| `/_plugins/_content_manager/policy/{space}` | `PUT`  | `cluster:admin/content_manager/policy/update`  |
| `/_plugins/_content_manager/update`         | `POST` | `cluster:admin/content_manager/update/trigger` |
| `/_plugins/_setup/settings`                 | `PUT`  | `plugin:wazuh/settings/write`                  |

1. **RBAC** - each endpoint is gated by the cluster permission above, enforced by the OpenSearch Security plugin. No default role holds these permissions: `dashboard_server` and `wazuh_manager` are both excluded, so out of the box only the superuser `admin` (role `all_access`, cluster wildcard `*`) can call them. To delegate any of these actions without granting full superuser, create a dedicated role granting only the permission(s) above and map it to the chosen user.
2. **Per-endpoint disable settings** - each endpoint can be disabled independently by setting its node setting to `false`, after which it returns `403 Forbidden` for **every** caller, regardless of role (intended for externally managed deployments such as Wazuh Cloud): `plugins.content_manager.catalog.update_on_demand` (content update trigger), `plugins.content_manager.catalog.policy_update.enabled` (policy updates), and `plugins.setup.settings_update.enabled` (setup settings). See [Protecting sensitive configuration](../modules/content-manager/configuration.md#protecting-sensitive-configuration).
