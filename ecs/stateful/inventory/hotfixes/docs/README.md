## `wazuh-states-inventory-hotfixes` index data model

### Fields summary

The fields are based on:

- [Global Queries](https://github.com/wazuh/wazuh/issues/27898) (included in 4.13.0).
- [States Persistence](https://github.com/wazuh/wazuh/issues/29840#issuecomment-2937251736) (included in 5.0.0)

Based on ECS:

- [Agent Fields](https://www.elastic.co/guide/en/ecs/current/ecs-agent.html).

The detail of the fields can be found in csv file [States inventory hotfixes Fields](fields.csv).

### Transition table

| Field Name     | Type    | Description                                                    | Destination Field             | Custom |
| -------------- | ------- | -------------------------------------------------------------- | ----------------------------- | ------ |
| agent_id       | string  | Unique ID of the agent.                                        | wazuh.agent.id                | FALSE  |
| agent_ip       | string  | IP address of the agent.                                       | wazuh.agent.host.ip           | TRUE   |
| agent_name     | string  | Name of the agent.                                             | wazuh.agent.name              | FALSE  |
| agent_version  | string  | Agent version.                                                 | wazuh.agent.version           | FALSE  |
| arch           | string  | Registry architecture type, e.g., "[x86]", "[x64]".            | wazuh.agent.host.architecture | TRUE   |
| agent_ip       | string  | IP address of the agent.                                       | wazuh.agent.host.ip           | TRUE   |
| agent_id       | string  | Unique identifier of the agent, e.g., "001".                   | wazuh.agent.id                | FALSE  |
| agent_name     | string  | Name assigned to the agent.                                    | wazuh.agent.name              | FALSE  |
| agent_version  | string  | Version of the agent software, e.g., "v4.10.2".                | wazuh.agent.version           | FALSE  |
| hotfix         | string  | Name or identifier of the applied hotfix.                      | package.hotfix.name           | TRUE   |
| cluster_name   | string  | Wazuh cluster name                                             | wazuh.cluster.name            | TRUE   |
| cluster_node   | string  | Wazuh cluster node                                             | wazuh.cluster.node            | TRUE   |
| schema_version | string  | Wazuh schema version                                           | wazuh.schema.version          | TRUE   |
| checksum       | keyword | SHA1 hash used as checksum of the data collected by the agent. | checksum.hash.sha1            | TRUE   |
