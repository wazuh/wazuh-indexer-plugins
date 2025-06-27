## `wazuh-states-fim-registry-values` index data model

### Fields summary

The fields are based on:
- [Global Queries](https://github.com/wazuh/wazuh/issues/27898) (included in 4.13.0).
- [States Persistence](https://github.com/wazuh/wazuh/issues/29840#issuecomment-2914305496) (included in 5.0.0)

Based on ECS:

- [Agent Fields](https://www.elastic.co/guide/en/ecs/current/ecs-agent.html).
- [Registry Fields](https://www.elastic.co/docs/reference/ecs/ecs-registry).

The detail of the fields can be found in csv file [States FIM registries Fields](fields.csv).

### Transition table


| Field Name        | Type   | Description                                         | Destination Field         | Custom |
| ----------------- | ------ | :-------------------------------------------------- | ------------------------- | ------ |
| agent_id          | string | Unique identifier of the agent, e.g., "001".        | agent.id                  |        |
| agent_ip          | string | IP address of the agent.                            | agent.host.ip             | TRUE   |
| agent_name        | string | Name assigned to the agent.                         | agent.name                |        |
| agent_version     | string | Version of the agent software, e.g., "v4.10.2".     | agent.version             |        |
| arch/architecture | string | Registry architecture type, e.g., "[x86]", "[x64]". | agent.host.architecture   | TRUE   |
| cluster_name      | string | Wazuh cluster name                                  | wazuh.cluster.name        | TRUE   |
| cluster_node      | string | Wazuh cluster node                                  | wazuh.cluster.node        | TRUE   |
| architecture      | string | Architecture associated with the entity             | registry.architecture     | TRUE   |
| hash_md5          | string | MD5 hash of the file or registry value content.     | registry.data.hash.md5    | TRUE   |
| hash_sha1         | string | SHA-1 hash of the file or registry value content.   | registry.data.hash.sha1   | TRUE   |
| hash_sha256       | string | SHA-256 hash of the file or registry value content. | registry.data.hash.sha256 | TRUE   |
| hive              | string | Abbreviated name for the hive.                      | registry.hive             |        |
| key               | string | Hive-relative path of keys                          | registry.key              |        |
| path              | string | Absolute file path or full registry key path.       | registry.path             |        |
| schema_version    | string | Wazuh schema version                                | wazuh.schema.version      | TRUE   |
| size              | long   | Size of the file or registry value (in bytes).      | registry.size             | TRUE   |
| name/value        | string | Name of the registry value.                         | registry.value            |        |
| value_type        | string | Type of the registry value, e.g., "REG_SZ".         | registry.data.type        |        |
| checksum          | string | SHA1 hash of the file.                              | checksum.hash.sha1        | TRUE   |
