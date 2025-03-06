# Architecture

## Command manager context diagram

```mermaid
graph TD
    subgraph Command_Manager["Command Manager"]
        API["Commands API"]
        Controller["Commands Controller"]
        Processor["Commands Expansion"]
        Storage["Commands Index Storage"]
        CommandsIndex[(commands index)]
        AgentsIndex[(agents index)]
        Scheduler["Job Scheduler Task"]
    end

    Actor("Actor") -- POST /commands --> API

    API --> Controller
    Controller --> Processor
    Processor --> Storage
    Storage -- write --> CommandsIndex
    Processor -- read --> AgentsIndex
    Scheduler -- read-write--> CommandsIndex

    subgraph Server["Server"]
        direction TB
        ManagementAPI["Management API"]
    end

    ManagementAPI -- read --> CommandsIndex
```

## Commands API

Status: Completed

Documentation TBD.

Issue: [https://github.com/wazuh/wazuh-indexer-plugins/issues/69](https://github.com/wazuh/wazuh-indexer-plugins/issues/69)

Input JSON:

```json
{
  "commands": [
    {
      "action": {
        "name": "restart",
        "args": {},
        "version": "5.0.0"
      },
      "source": "Users/Services",
      "user": "Management API",
      "timeout": 100,
      "target": {
        "id": "d5b250c4-dfa1-4d94-827f-9f99210dbe6c",
        "type": "agent"
      }
    }
  ]
}
```
**Important:** The `action.name` attribute must always appear before `action.args` in the JSON. This is necessary because the validation of `action.args` depends on the value of `action.name`.

```mermaid
classDiagram
    HTTPclient <|-- CTIclient
    HTTPclient <|-- CommandManagerClient

    class HTTPclient{
        <<abstract>>
        +request(method, payload, callback)
    }
    class CTIclient{
        -int apiUrl
        +getConsumerInfo()
        +getContextChanges()
    }
    class CommandManagerClient{
        -int apiUrl
        +postCommand()
    }
```

## Commands expansion

Status: Completed
Documentation  TBD
Issue: [https://github.com/wazuh/wazuh-indexer-plugins/issues/88](https://github.com/wazuh/wazuh-indexer-plugins/issues/88)

## Orders storage

Status: Completed
Documentation TBD.
Issue: [https://github.com/wazuh/wazuh-indexer-plugins/issues/42](https://github.com/wazuh/wazuh-indexer-plugins/issues/42)

## The Job Scheduler task

Status: Completed
Documentation TBD.
Issue: [https://github.com/wazuh/wazuh-indexer-plugins/issues/87](https://github.com/wazuh/wazuh-indexer-plugins/issues/87)

## Configuration and key store management

Status: Completed
Documentation TBD.
Issue: [https://github.com/wazuh/wazuh-indexer-plugins/issues/95](https://github.com/wazuh/wazuh-indexer-plugins/issues/95 )

## Orders sending

Status: Completed
Issue: [https://github.com/wazuh/wazuh-indexer-plugins/issues/89](https://github.com/wazuh/wazuh-indexer-plugins/issues/89)
Output JSON:

```json
{
    "orders": [
        {
            "action": {
              "name": "restart",
              "args": {},
              "version": "5.0.0"
            },
            "source": "Users/Services",
            "document_id": "A8-62pMBBmC6Jrvqj9kW",
            "user": "Management API",
            "target": {
                "id": "d5b250c4-dfa1-4d94-827f-9f99210dbe6c",
                "type": "agent"
            }
        }
    ]
}
```
