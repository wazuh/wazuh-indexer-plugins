# Security

Wazuh Indexer uses the [OpenSearch Security plugin](https://docs.opensearch.org/3.6/security/) to manage access control and security features.

## Configuration files

The configuration files for the security plugin are located under the `/etc/wazuh-indexer/opensearch-security/` directory by default.

<div class="warning">

Modifying these files directly is not recommended. Instead, use the Wazuh Dashboard Security plugin to create new security resources. See [Defining users and roles](defining-users-and-roles.md).

</div>

Among these files, Wazuh Indexer uses these particularly to add its own security resources:

- **`internal_users.yml`**: Defines the internal users for the Wazuh Indexer. Each user has a hashed password, reserved status, backend roles, and a description. The hashes are generated during installation and are unique to each deployment.

- **`roles.yml`**: Defines the roles and their permissions within the Wazuh Indexer. Each role specifies the cluster permissions, index permissions, and tenant permissions.

- **`roles_mapping.yml`**: Maps users and backend roles to the defined roles. This file specifies which users or backend roles have access to each role.

- **`action_groups.yml`**: Defines named groups of permissions. Wazuh Indexer adds the action groups that name the Content Manager and Setup plugin permissions, listed in [Permissions](permissions.md).

The [Access control](access-control.md) section contains information about the security resources added to the Wazuh Indexer by default.

## Rate limiting of failed logins

Wazuh Indexer limits failed logins per user against the internal users database. The default is set in `config.yml`, under `config.dynamic`:

```yaml
auth_failure_listeners:
  internal_authentication_backend_limiting:
    type: username
    authentication_backend: internal
    allowed_tries: 3
    time_window_seconds: 60
    block_expiry_seconds: 60
    max_blocked_clients: 100000
    max_tracked_clients: 100000
```

- A user that fails to authenticate 3 times within 60 seconds is blocked for 60 seconds. Until the block expires, the node answers `401` to that user, even with the right password.
- Each node keeps its own blocks in memory. Restarting a node clears them.
- IP-based rate limiting is not enabled.

To change the values, edit the block in `/etc/wazuh-indexer/opensearch-security/config.yml`. To disable the limit, remove it. Then load the file from one node:

```bash
/usr/share/wazuh-indexer/bin/indexer-security-init.sh --options "-f /etc/wazuh-indexer/opensearch-security/config.yml -icl -nhnv"
```

The listeners can also be changed at runtime with the `_plugins/_security/api/authfailurelisteners` endpoint of the security REST API. A change made this way is overwritten the next time `config.yml` is loaded. See [API rate limiting](https://docs.opensearch.org/3.6/security/configuration/api-rate-limiting/) in the OpenSearch documentation for every setting.
