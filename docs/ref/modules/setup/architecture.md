# Architecture

## Design

The plugin implements the [ClusterPlugin](https://github.com/opensearch-project/OpenSearch/blob/2.13.0/server/src/main/java/org/opensearch/plugins/ClusterPlugin.java) interface in order to be able to hook into the node’s lifecycle overriding the `onNodeStarted()` method. The logic for the creation of the index templates and the indices is encapsulated in the `WazuhIndices` class. The `onNodeStarted()` method invokes the `WazuhIndices::initialize()` method, which handles everything.

By design, the plugin will overwrite any existing index template under the same name.

## JavaDoc

The plugin is documented using JavaDoc. You can compile the documentation using the Gradle task for that purpose. The generated JavaDoc is in the **build/docs** folder.

```bash
./gradlew javadoc
```

## Indices

Refer to the [docs](https://github.com/wazuh/wazuh-indexer-plugins/tree/main/ecs) for complete definitions of the indices. The indices inherit the settings and mappings defined in the [index templates](https://github.com/wazuh/wazuh-indexer-plugins/tree/main/plugins/setup/src/main/resources).

## Sequence diagram

> **Note** Calls to `Client` are asynchronous.


```mermaid
sequenceDiagram
    actor Node
    participant SetupPlugin
    participant WazuhIndices
    participant Client
    Node->>SetupPlugin: plugin.onNodeStarted()
    activate SetupPlugin
    Note over Node,SetupPlugin: Invoked on Node::start()

    
    activate WazuhIndices
    SetupPlugin->>WazuhIndices: initialize()


    Note over SetupPlugin,WazuhIndices: Create index templates and indices
    loop i..n templates
        WazuhIndices-)Client: templateExists(i)
        Client--)WazuhIndices: response
        alt template i does not exist
            WazuhIndices-)Client: putTemplate(i)
            Client--)WazuhIndices: response
        end
    end
    loop i..n indices
        WazuhIndices-)Client: indexExists(i)
        Client--)WazuhIndices: response
        alt index i does not exist
            WazuhIndices-)Client: putIndex(i)
            Client--)WazuhIndices: response
        end
    end
    deactivate WazuhIndices
    deactivate SetupPlugin
```

## Class diagram

```mermaid
---
title: Wazuh Indexer setup plugin
---
classDiagram
    direction LR
    SetupPlugin"1"-->WazuhIndices
    WazuhIndices"1"-->Client
    <<service>> Client

    SetupPlugin : -WazuhIndices indices
    SetupPlugin : +createComponents()
    SetupPlugin : +onNodeStarted()

    WazuhIndices : -Client client
    WazuhIndices : -ClusterService clusterService
    WazuhIndices : +WazuhIndices(Client client, ClusterService clusterService)
    WazuhIndices : +putTemplate(String template) void
    WazuhIndices : +putIndex(String index) void
    WazuhIndices : +indexExists(String index) bool
    WazuhIndices : +templateExists(String template) bool
    WazuhIndices : +initialize() void
```
