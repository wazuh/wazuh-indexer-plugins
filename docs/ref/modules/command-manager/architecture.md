# Architecture

1. Sync content from CTI to Indexer

    - Ruleset.

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

2. Save user-made content to Indexer

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