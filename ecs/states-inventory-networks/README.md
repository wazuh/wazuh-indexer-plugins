| Field Name     | Type   | Description                                                      | Destination Field    | Custom |
| -------------- | ------ | ---------------------------------------------------------------- | -------------------- | ------ |
| agent_id       | string | Unique ID of the agent.                                          | agent.id             | FALSE  |
| agent_ip       | string | IP address of the agent.                                         | agent.host.ip        | TRUE   |
| agent_name     | string | Name of the agent.                                               | agent.name           | FALSE  |
| agent_version  | string | Agent version.                                                   | agent.version        | FALSE  |
| iface          | string | Network interface name.                                          | interface.name       | FALSE  |
| proto          | long   | Protocol type (e.g., IPv4, IPv6).                                | network.type         | FALSE  |
| address        | string | Assigned IP address.                                             | network.ip           | FALSE  |
| netmask        | string | Subnet mask of the interface.                                    | network.netmask      | TRUE   |
| broadcast      | string | Broadcast address.                                               | network.broadcast    | TRUE   |
| metric         | string | Interface metric for routing decisions.                          | network.metric       | TRUE   |
| dhcp           | bool   | Indicates whether DHCP is enabled (yes/no).                      | network.dhcp         | TRUE   |
| operation      | string | Type of operation performed (e.g., INSERTED, MODIFIED, DELETED). | operation.name       | TRUE   |
| cluster_name   | string | Wazuh cluster name                                               | wazuh.cluster.name   | TRUE   |
| cluster_node   | string | Wazuh cluster node                                               | wazuh.cluster.node   | TRUE   |
| schema_version | string | Wazuh schema version                                             | wazuh.schema.version | TRUE   |
