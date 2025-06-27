## `wazuh-states-fim-registry-keys` index data model

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
| architecture      | string | Registry architecture type, e.g., "[x86]", "[x64]". | agent.host.architecture   | TRUE   |
| cluster_name      | string | Wazuh cluster name                                  | wazuh.cluster.name        | TRUE   |
| cluster_node      | string | Wazuh cluster node                                  | wazuh.cluster.node        | TRUE   |
| architecture      | string | Architecture associated with the entity             | registry.architecture     | TRUE   |
| gid               | string | Group ID associated with the entity.                | registry.gid              | TRUE   |
| group_name/group  | string | Name of the group that owns the entity.             | registry.group            | TRUE   |
| hive              | string | Abbreviated name for the hive.                      | registry.hive             |        |
| key               | string | Hive-relative path of keys                          | registry.key              |        |
| mtime             | long   | Last modified timestamp of the entity.              | registry.mtime            | TRUE   |
| path              | string | Absolute file path or full registry key path.       | registry.path             |        |
| schema_version    | string | Wazuh schema version                                | wazuh.schema.version      | TRUE   |
| uid               | string | User ID associated with the entity.                 | registry.uid              | TRUE   |
| user_name/owner   | string | Name of the owner of the entity (user).             | registry.owner            | TRUE   |
| permissions/perm  | string | Permissions associated with the registry key.       | registry.permissions      | TRUE   |
| checksum          | string | SHA1 hash of the file.                              | checksum.hash.sha1        | TRUE   |
