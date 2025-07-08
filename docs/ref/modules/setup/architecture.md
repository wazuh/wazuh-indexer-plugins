# Architecture

## Design

The plugin implements the [ClusterPlugin](https://github.com/opensearch-project/OpenSearch/blob/3.1.0/server/src/main/java/org/opensearch/plugins/ClusterPlugin.java) interface in order to be able to hook into the node’s lifecycle overriding the `onNodeStarted()` method.

The `SetupPlugin` class holds the list of indices to create. The logic for the creation of the index templates and the indices is encapsulated in the `Index` abstract class. Each subclass can override this logic if necessary. The `SetupPlugin::onNodeStarted()` method invokes the `Index::initialize()` method, effectively creating every index in the list.

By design, the plugin will overwrite any existing index template under the same name.

### Retry mechanism

The plugin features a retry mechanism to handle transient faults. In case of a temporal failure (timeouts or similar) during the initialization of the indices, the task is retried after a given amount of time (backoff). If two consecutive faults occur during the initialization of the same index, the initialization process is halted, and the node is shut down. Proper logging is in place to notify administrators before the shutdown occurs.

The backoff time is configurable. Head to [Configuration Files](/ref/configuration/configuration-files.md#initialization-plugin-settings) for more information.

## Class diagram

```mermaid
---
title: Wazuh Indexer setup plugin
---
classDiagram
    %% Classes
    class IndexInitializer
    <<interface>> IndexInitializer
    class Index
    <<abstract>> Index
    class IndexStateManagement
    class WazuhIndex
    <<abstract>> WazuhIndex
    class StateIndex
    class StreamIndex

    %% Relations
    IndexInitializer <|-- Index : implements
    Index <|-- IndexStateManagement
    Index <|-- WazuhIndex
    WazuhIndex <|-- StateIndex
    WazuhIndex <|-- StreamIndex

    %% Schemas
    class IndexInitializer {
        +createIndex(String index) void
        +createTemplate(String template) void
    }
    class Index {
        Client client
        ClusterService clusterService
        IndexUtils utils
        String index
        String template
        +Index(String index, String template)
        +setClient(Client client) IndexInitializer
        +setClusterService(ClusterService clusterService) IndexInitializer
        +setIndexUtils(IndexUtils utils) IndexInitializer
        +indexExists(String indexName) bool
        +initialize() void
        +createIndex(String index) void
        +createTemplate(String template) void
        %% initialize() podría reemplazarse por createIndex() y createTemplate()
    }
    class IndexStateManagement {
        -List~String~ policies
        +initialize() void
        -createPolicies() void
        -indexPolicy(String policy) void
    }
    class WazuhIndex {
    }
    class StreamIndex {
        -String alias
        +StreamIndex(String index, String template, String alias)
        +createIndex(String index)
    }
    class StateIndex {
    }
```

## Sequence diagram

> **Note** Calls to `Client` are asynchronous.


```mermaid
sequenceDiagram
    actor Node
    participant SetupPlugin
    participant Index
    participant Client
    Node->>SetupPlugin: plugin.onNodeStarted()
    activate SetupPlugin
    Note over Node,SetupPlugin: Invoked on Node::start()

    activate Index
    loop i..n indices
        SetupPlugin->>Index: i.initialize()


        Index-)Client: createTemplate(i)
        Client--)Index: response

        Index-)Client: indexExists(i)
        Client--)Index: response
        alt index i does not exist
            Index-)Client: createIndex(i)
            Client--)Index: response
        end
    end

    deactivate Index
    deactivate SetupPlugin
```

## Wazuh Common Schema

Refer to the [docs](https://github.com/wazuh/wazuh-indexer-plugins/tree/main/ecs) for complete definitions of the indices. The indices inherit the settings and mappings defined in the [index templates](https://github.com/wazuh/wazuh-indexer-plugins/tree/main/plugins/setup/src/main/resources).

## JavaDoc

The plugin is documented using JavaDoc. You can compile the documentation using the Gradle task for that purpose. The generated JavaDoc is in the **build/docs** folder.

```bash
./gradlew javadoc
```
