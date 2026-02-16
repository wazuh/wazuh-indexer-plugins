# Configuration Files

## Initialization plugin settings

#### Timeout for the OpenSearch client
- **Key**: `plugins.setup.timeout`
- **Type**: Integer
- **Default**: `30`
- **Minimum**: `5`
- **Maximum**: `120`
- **Description**: Timeout in seconds for index and search operations.

#### Backoff (delay) for the retry mechanism
- **Key**: `plugins.setup.backoff`
- **Type**: Integer
- **Default**: `15`
- **Minimum**: `5`
- **Maximum**: `60`
- **Description**: Delay in seconds for the retry mechanism involving initialization tasks.

### Example

Below, there is an example of custom values for these settings within the `opensearch.yml` file:

```yaml
plugins.setup.timeout: 60
plugins.setup.backoff: 30
```

## Security - Access Control

Wazuh Indexer uses the [OpenSearch Security plugin](https://docs.opensearch.org/3.3/security/) to manage access control and security features.

The configuration files for the security plugin are located under the `/etc/wazuh-indexer/opensearch-security/` directory by default.

<div class="warning">

Modifying these files directly is not recommened. Instead, use the Wazuh Dashboard Security plugin to create new security resouces. See [Define Users and Roles](/ref/security/defining-users-and-roles.md).

</div>

Among these files, Wazuh Indexer uses these particularly to add its own security resources:

- **`internal_users.yml`**: Defines the internal users for the Wazuh Indexer. Each user has a hashed password, reserved status, backend roles, and a description.

- **`roles.yml`**: Defines the roles and their permissions within the Wazuh Indexer. Each role specifies the cluster permissions, index permissions, and tenant permissions.

- **`roles_mapping.yml`**: Maps users and backend roles to the defined roles. This file specifies which users or backend roles have access to each role.

The [Access Control](/ref/security/access-control.md) section contains information about the security resources added to the Wazuh Indexer by default.