
# Usage: Common Utils

The Common Utils plugin provides centralized diagnostic tools and shared internal services. Since it acts as a foundational layer, its usage is primarily focused on system health monitoring, diagnostic APIs, and standardized resource management for other Wazuh plugins.

## Diagnostic API
Common Utils exposes a specialized API endpoint to validate the state of internal shared resources, such as the IPC (Inter-Process Communication) connection with the Wazuh Engine.

### Checking internal connectivity and resource stats
To verify if the Wazuh Indexer can communicate correctly with the Wazuh Engine and check memory/thread-pool usage, run the following command:

```bash
curl -X GET "https://localhost:9200/_plugins/_wazuh/_common/stats?pretty"
```

The response provides status details for the following core utilities:

1. **Socket Connection:** Status of the Unix Domain Socket at `/var/ossec/queue/indexer/conn`.
2. **Schema Cache:** Hit/Miss ratio for JSON validation schemas.
3. **Thread Pool:** Current load and queue depth for background serialization tasks.



---

## Standardized Logging and Error Codes
The plugin enforces a uniform logging format via the `WazuhLogger`. When troubleshooting issues in any Wazuh plugin, you should look for the `[wazuh-common]` prefix in the Wazuh Indexer logs.

### Common Error Reference
If you encounter errors in the logs, refer to this table for common utility codes:

| Error Code | Category | Meaning | Action |
|---|---|---|---|
| `W1001` | Socket | Connection refused | Verify that the Wazuh Engine service is active and the socket file exists. |
| `W1002` | Validation | Schema mismatch | The data received does not match the internal Wazuh JSON schema. |
| `W1005` | Security | Sanitization failure | The `DataMasker` could not process a sensitive field. Check regex patterns. |



---

## Managing permissions on common-utils via RBAC
Access to the Common Utils diagnostic API is governed by the Wazuh Indexer’s role-based access control (RBAC) system. This means that users must have the appropriate roles assigned to them in order to perform health checks and diagnostic monitoring. The roles can be managed through the Wazuh Dashboard **Index Management -> Security -> Roles** section. 

The following permission is available for the Common Utils plugin:

```
1. cluster:admin/wazuh/common/stats/get
```

### Predefined Roles
There is a predefined role that can be used to manage permissions:
- `wazuh_common_monitor`: Includes permission 1.

More information on how to modify and map roles on the Wazuh Indexer can be found in the [Wazuh Indexer documentation](https://documentation.wazuh.com/current/user-manual/user-administration/rbac.html).
