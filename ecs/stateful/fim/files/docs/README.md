## `wazuh-states-fim-files` index data model

### Fields summary

The fields are based on:
- [Global Queries](https://github.com/wazuh/wazuh/issues/27898) (included in 4.13.0).
- [States Persistence](https://github.com/wazuh/wazuh/issues/29840#issuecomment-2914305496) (included in 5.0.0)

Based on ECS:

- [Agent Fields](https://www.elastic.co/guide/en/ecs/current/ecs-agent.html).
- [File Fields](https://www.elastic.co/guide/en/ecs/current/ecs-file.html).

The detail of the fields can be found in csv file [States FIM files Fields](fields.csv).

### Transition table

| Field Name       | Type   | Description                                         | Destination Field             | Custom |
| ---------------- | ------ | --------------------------------------------------- | ----------------------------- | ------ |
| agent_id         | string | Unique identifier of the agent, e.g., "001".        | wazuh.agent.id                |        |
| agent_ip         | string | IP address of the agent.                            | wazuh.agent.host.ip           | TRUE   |
| agent_name       | string | Name assigned to the agent.                         | wazuh.agent.name              |        |
| agent_version    | string | Version of the agent software, e.g., "v4.10.2".     | wazuh.agent.version           |        |
| architecture     | string | Registry architecture type, e.g., "[x86]", "[x64]". | wazuh.agent.host.architecture | TRUE   |
| cluster_name     | string | Wazuh cluster name                                  | wazuh.cluster.name            | TRUE   |
| cluster_node     | string | Wazuh cluster node                                  | wazuh.cluster.node            | TRUE   |
| gid              | string | Group ID associated with the entity.                | file.gid                      |        |
| group_name/group | string | Name of the group that owns the entity.             | file.group                    |        |
| hash_md5         | string | MD5 hash of the file or registry value content.     | file.hash.md5                 |        |
| hash_sha1        | string | SHA-1 hash of the file or registry value content.   | file.hash.sha1                |        |
| hash_sha256      | string | SHA-256 hash of the file or registry value content. | file.hash.sha256              |        |
| inode            | long   | Inode number (only applicable for file events).     | file.inode                    |        |
| mtime            | long   | Last modified timestamp of the entity.              | file.mtime                    |        |
| path             | string | Absolute file path or full registry key path.       | file.path                     |        |
| schema_version   | string | Wazuh schema version                                | wazuh.schema.version          | TRUE   |
| size             | long   | Size of the file or registry value (in bytes).      | file.size                     |        |
| timestamp        | long   | Timestamp when the event was generated.             | timestamp                     |        |
| uid              | string | User ID associated with the entity.                 | file.uid                      |        |
| user_name/owner  | string | Name of the owner of the entity (user).             | file.owner                    |        |
| checksum         | string | SHA1 hash of the file.                              | checksum.hash.sha1            | TRUE   |
| attributes       | string | List of attributes related to the file.             | file.attributes               |        |
| dev/device       | string | Device that is the source of the file.              | file.device                   |        |
| perm/permissions | string | List of permissions related to the file.            | file.permissions              | TRUE   |

