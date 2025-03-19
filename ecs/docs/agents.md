## `agents` index data model

### Fields summary

The fields are based on https://github.com/wazuh/wazuh/issues/23396#issuecomment-2176402993

Based on ECS [Agent Fields](https://www.elastic.co/guide/en/ecs/current/ecs-agent.html).

|     | Field                | Type    | Description                                                            | Example                            |
| --- |----------------------| ------- | ---------------------------------------------------------------------- | ---------------------------------- |
|     | `agent.id`           | keyword | Unique identifier of this agent.                                       | `8a4f500d`                         |
|     | `agent.name`         | keyword | Custom name of the agent.                                              | `foo`                              |
| \*  | `agent.groups`       | keyword | List of groups the agent belong to.                                    | `["group1", "group2"]`             |
| \*  | `agent.key`          | keyword | The registration key of the agent.                                     | `BfDbq0PpcLl9iWatJjY1shGvuQ4KXyOR` |
|     | `agent.type`         | keyword | Type of agent.                                                         | `endpoint`                         |
|     | `agent.version`      | keyword | Version of the agent.                                                  | `6.0.0-rc2`                        |
| \*  | `agent.is_connected` | boolean | Agents' interpreted connection status depending on `agent.last_login`. |                                    |
| \*  | `agent.last_login`   | date    | The last time the agent logged in.                                     | `11/11/2024 00:00:00`              |
|     | `agent.host.ip`      | ip      | Host IP addresses. Note: this field should contain an array of values. | `["192.168.56.11", "10.54.27.1"]`  |
|     | `agent.host.os.full` | keyword | Operating system name, including the version or code name.             | `Mac OS Mojave`                    |

\* Custom field.

### ECS mapping

```yml
---
name: agent
fields:
  base:
    fields:
      tags: []
  agent:
    fields:
      id: {}
      name: {}
      type: {}
      version: {}
      groups: {}
      key: {}
      last_login: {}
      status: {}
      host:
        fields: "*"
```

```yml
---
- name: agent
  title: Wazuh Agents
  short: Wazuh Inc. custom fields.
  type: group
  group: 2
  fields:
    - name: groups
      type: keyword
      level: custom
      description: >
        List of groups the agent belong to.
    - name: key
      type: keyword
      level: custom
      description: >
        The registration key of the agent.
    - name: last_login
      type: date
      level: custom
      description: >
        The last time the agent logged in.
    - name: status
      type: keyword
      level: custom
      description: >
        Agents' interpreted connection status depending on `agent.last_login`.
      allowed_values:
        - name: active
          description: Active agent status
        - name: disconnected
          description: Disconnected agent status
```

### Index settings

```json
{
  "index_patterns": ["wazuh-agents*"],
  "priority": 1,
  "template": {
    "settings": {
      "index": {
        "number_of_shards": "1",
        "number_of_replicas": "0",
        "refresh_interval": "5s",
        "query.default_field": [
          "agent.id",
          "agent.groups",
          "agent.name",
          "agent.type",
          "agent.version",
          "agent.name",
          "agent.host.os.full",
          "agent.host.ip"
        ]
      }
    }
  }
}
```
