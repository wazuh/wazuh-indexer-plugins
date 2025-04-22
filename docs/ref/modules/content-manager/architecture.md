# Architecture

## Use case: sync content from CTI to Indexer

Wazuh Indexer will store threat intelligence content such as CVE definitions or rules in indices for its distribution to the Servers (Engine).

### CVEs context

In the case of CVEs, the new content is fetched periodically by the Content Manager from the CTI API (**1**). Following a successful update of the content (**2**), the Content Manager generates a command (**3**) (**4**) to notify about new content being available. Ultimately, the Server's periodic search for new commands reads the notification about the new content (**5**) and notifies the Engine (**6**), that updates its CVE content with the latest copy in the Indexer's CVE index (**7**).

```mermaid
    flowchart TD

    subgraph cti["CTI"]
    end

    subgraph Indexer["Indexer cluster"]

        subgraph Data_streams["Data stream"]
            alerts_stream["Alerts stream"]
            commands_stream["Commands stream"]
        end

        subgraph Plugins["Modules"]
            content_manager["Content manager"]
            command_manager["Command manager"]
        end

        subgraph Data_states["Content"]
            states["CVE data"]
        end
    end

    subgraph Wazuh1["Server 1"]
        engine["Engine / VD"]
        server["Server"]
    end

    content_manager -- 1- /check_updates <--> cti

    content_manager -- 2- /update_content --> states

    content_manager -- 3- /process_updates --> command_manager
    command_manager -- 4- stores --> commands_stream
    server -- 5- /pulls --> commands_stream
    server -- 6- /update_content --> engine
    engine -- 7- /pulls --> states

    style Data_states fill:#abc2eb
    style Data_streams fill:#abc2eb
    style Plugins fill:#abc2eb
```

### Ruleset context

In the case of the ruleset, the new content is fetched periodically by the Content Manager from the CTI API (**1**). Following a successful update of the content (**2**), the Content Manager generates a command (**3**) (**4**) to notify about new content being available. Ultimately, the Server's periodic search for new commands reads the notification about the new content (**5**) and notifies the Engine (**6**), that updates its ruleset content (**7**).

```mermaid
    flowchart TD

    subgraph Indexer["Indexer cluster"]

        subgraph Data_streams["Data stream"]
            commands_stream["Commands stream"]
        end

        subgraph Data_states["Content"]
            states["Ruleset data"]
        end
        subgraph Plugins["Modules"]
            content_manager["Content manager"]
            command_manager["Command manager"]
        end
    end

    subgraph Wazuh1["Server 1"]
        engine["Engine"]
        server["Server"]
    end

    subgraph cti["CTI"]
    end

    content_manager -- 1- check_updates --> cti
    content_manager -- 2- /update_content --> states
    content_manager -- 3- /process_updates --> command_manager
    command_manager -- 4- stores --> commands_stream
    server -- 5- pulls --> commands_stream
    server -- 6- /update_content --> engine
    engine -- 7- requests_policy --> content_manager

    style Data_streams fill:#abc2eb
    style Data_states fill:#abc2eb
    style Plugins fill:#abc2eb
```

## Use case: save user-made content to Indexer

Wazuh Indexer will store user-made content, such as custom rules, in indices for its distribution to the Servers (Engine).

Users may create new content by interacting with the Management API (**1a**) or UI (**1b**). In any case, the new content arrives to the Content Manager API (**2a**) (**2b**). The Content Manager validates the data (**3**), and stores it on the appropriate index (**4**) in case of being valid. Ultimately, the Content Manager generates a command (**5**)  (**6**) To notify about new content being available.

```mermaid
    flowchart TD
    subgraph Dashboard["Dashboard"]
    end

    subgraph Indexer["Indexer cluster"]
        subgraph Data_states["Content"]
            states["Ruleset data"]
        end

        subgraph Plugins["Modules"]
            subgraph content_manager["Content manager"]
                subgraph indexer_engine["Engine"]
                end

                subgraph content_manager_api["Content manager API"]
                end
            end
            command_manager["Command manager"]
        end

        subgraph Data_streams["Data stream"]
            commands_stream["Commands stream"]
        end
    end

    subgraph Wazuh1["Server 1"]
        engine["Engine"]
        management_api["Management API"]
        server["Server"]
    end

    subgraph users["Users"]
    end

    users -- 1b- /test_policy --> Dashboard
    users -- 1a- /test_policy --> management_api
    management_api -- 2a- /update_test_policy --> content_manager
    Dashboard -- 2b- /update_test_policy --> content_manager
    content_manager_api -- 3- /validate_test_policy --> indexer_engine
    content_manager -- 4- /update_test_policy --> states
    content_manager -- 5- /process_updates --> command_manager
    command_manager -- 6- /stores --> commands_stream

    style Data_states fill:#abc2eb
    style Data_streams fill:#abc2eb
    style Plugins fill:#abc2eb
```
## Content update process

The update process of the Content Manager compares the offset values for the consumer

To update the content, the Content Manager uses the CTI client to fetch the changes. It then processes the data and transforms it into create, update or delete operations to the content index. When the update is completed, it generates a command for the Command Manager using the API.

The Content Updater module is the orchestrator of the update process, delegating the fetching and indexing operations to other modules.

The update process is as follows:

1. The Content Updater module compares the "offsets" in the `wazuh-context` index. If these values differ, it means that the version of the content in the Indexer and in CTI are different.
2. If the content is outdated, it requests the CTI API for the newest changes, which are in JSON patch format. For performance purposes, these changes are obtained in chunks.
3. Each of these chunks are applied to the content one by one. If the operation fails, the update process is interrupted and a recovery from a snapshot is required.
4. The update continues until the offsets are equal.
5. Once completed, the update is committed by updating the offset in the `wazuh-context` index and generating a command for the Command Manager notifying about the update's success.

```mermaid
---
title: Content Manager offset-based update mechanism
---
flowchart TD
    ContextIndex1@{ shape: lin-cyl, label: "Index storage" }
    ContextIndex2@{ shape: lin-cyl, label: "Index storage" }
    CTI_API@{ shape: lin-cyl, label: "CTI API" }
    CM_API@{ shape: lin-cyl, label: "Command Manager API" }

    subgraph ContentIndex["[apply change]"]
        direction LR
        OperationType --> Create
        OperationType --> Update
        OperationType --> Delete
        Create -.-> CVE_Index
        Delete -.-> CVE_Index
        Update -.-> CVE_Index

        OperationType@{ shape: hex, label: "Check operation" }

        Create["Create"]
        Delete["Delete"]
        Update["Update"]

        CVE_Index@{ shape: lin-cyl, label: "Index storage" }
    end

    subgraph ContentUpdater["Content update process"]
        Start@{ shape: circle, label: "Start" }
        End@{ shape: dbl-circ, label: "Stop" }
        GetConsumerInfo["Get consumer info"]
        CompareOffsets@{ shape: hex, label: "Compare offsets" }
        IsOutdated@{ shape: diamond, label: "Is outdated?" }
        GetChanges["Get changes"]
        ApplyChange@{ shape: subproc, label: "apply change" }
        IsLastOffset@{ shape: diamond, label: "Is last offset?"}
        UpdateOffset["Update offset"]
        GenerateCommand["Generate command"]
    end

    %% Flow
    Start --> GetConsumerInfo
    GetConsumerInfo --> CompareOffsets
    GetConsumerInfo -.read.-> ContextIndex1
    CompareOffsets --> IsOutdated
    IsOutdated -- No --> End
    IsOutdated -- Yes --> GetChanges
    GetChanges -.GET.-> CTI_API
    GetChanges --> ApplyChange
    ApplyChange --> IsLastOffset
    IsLastOffset -- No --> GetChanges
    IsLastOffset -- Yes --> UpdateOffset
    UpdateOffset --> GenerateCommand --> End
    UpdateOffset -.write.-> ContextIndex2
    GenerateCommand -.POST.-> CM_API

    style ContentUpdater fill:#abc2eb
    style ContentIndex fill:#abc2eb
```
