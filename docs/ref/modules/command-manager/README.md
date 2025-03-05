# Command Manager

```mermaid
flowchart TD

subgraph Agents
    Endpoints
    Clouds
    Other_sources
end

subgraph Indexer["Indexer cluster"]
    subgraph Data_states["Data streams"]
        commands_stream["Orders stream"]
    end

    subgraph indexer_modules["Indexer modules"]
        commands_manager["Commands manager"]
        content_manager["Content manager"]
    end
end

subgraph Wazuh1["Server 1"]
    comms_api["Comms API"]
    engine["Engine"]
    management_api["Management API"]
    server["Server"]
end

subgraph Dashboard
    subgraph Dashboard1["Dashboard"]
    end
end

subgraph lb["Load Balancer"]
    lb_node["Per request"]
end


Agents -- 3.a) /poll_commands --> lb
lb -- 3.a) /poll_commands --> comms_api

content_manager -- 1.a) /send_commands --> commands_manager
management_api -- 1.a) /send_commands --> commands_manager
commands_manager -- 1.b) /index --> commands_stream

server -- 2.a) /get_commands --> commands_stream
server -- 2.b) /send_commands --> comms_api
server -- 2.b) /send_commands --> engine

users["Wazuh users"] --> Dashboard
Dashboard -- HTTP --> Indexer

style Data_states fill:#abc2eb
style indexer_modules fill:#abc2eb
```

The [Command Manager plugin](https://github.com/wazuh/wazuh-indexer/issues/349) appears for the first time in Wazuh 5.0.0.

The plugin is one of the pillars of the agent commands mechanism. Wazuh Agents can receive orders anytime to change their behavior, for example, restarting, changing its group or run a program on the monitored system. The Command Manager plugin receives these commands, prepares them and sends them to the Wazuh Server for their delivery to the destination Agent. The processed commands are stored in an index for their consulting and management of their lifecycle, and eventually removed from the index when completed or past due. The document ID is sent from end to end, so the result of the order can be set by the Wazuh Server.

**Key Concepts:**
- **Command:** the raw command as received by the POST /commands endpoint.
- **Order:** processed command, as stored in the index. A subset of this information is sent to the Wazuh Server.

**Key Features:**
- The plugin exposes a Rest API with a single endpoint that listens for POST requests.
- The plugin extends the Job Scheduler plugin via its SPI. The job periodically looks for orders in “pending” state and sends them to the Management API of the Wazuh Server.
- The plugin introduces an HTTP Rest client using the Apache HTTP Client library to send the orders to the Wazuh Server.
- The plugin reads the Wazuh Server information from the key store. This information is considered sensitive as it contains the public IP address of the server and the access credentials.
- The plugin uploads the “commands” index template to the cluster when the first command is received.