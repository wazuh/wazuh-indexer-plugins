# Wazuh Indexer Content Manager Plugin — Development Guide

This document describes how to extend and configure the Wazuh Indexer Content Manager plugin, which is responsible for managing and synchronizing security content from the Wazuh CTI API.

---

## 📋 Overview

The Content Manager plugin handles:
- **Authentication:** Manages subscriptions and tokens with the CTI Console.
- **Job Scheduling:** Periodically checks for updates using the OpenSearch Job Scheduler.
- **Content Synchronization:** Keeps local indices in sync with the Wazuh CTI Catalog.
- **Security Analytics Integration:** Pushes ingestion rules and detectors to the Security Analytics engine for immediate activation.
- **Snapshot Initialization:** Downloads and indexes full content via zip snapshots.
- **Incremental Updates:** Applies JSON Patch operations based on offsets.
- **Context management:** Maintains synchronization state.

The plugin manages several indices:
- `.cti-consumers`: Stores consumer information and synchronization state.
- `.wazuh-content-manager-jobs`: Stores job scheduler metadata.
- Content Indices: Indices for specific content types (e.g., `.cti-rules`, `.cti-decoders`).

---

## 🔧 Plugin Architecture

### Main Components

```mermaid
classDiagram
    class ContentManagerPlugin {
        +createComponents()
        +getRestHandlers()
        +onNodeStarted()
    }

    class RestLayer {
        +RestGetSubscriptionAction
        +RestPostSubscriptionAction
        +RestDeleteSubscriptionAction
        +RestPostUpdateAction
    }

    class CtiConsole {
        +manageAuthentication()
    }

    class ContentJobRunner {
        +registerExecutor()
    }

    class CatalogSyncJob {
        +execute()
        +performSynchronization()
    }

    class UnifiedConsumerSynchronizer {
        +synchronize()
        -onSyncComplete()
    }

    class ConsumerService {
        <<interface>>
        +getLocalConsumer()
        +getRemoteConsumer()
    }

    class SnapshotServiceImpl {
        +initialize(remoteConsumer)
    }

    class UpdateServiceImpl {
        +update(currentOffset, remoteOffset)
    }

    class SecurityAnalyticsService {
        <<interface>>
        +upsertRule(doc)
        +upsertIntegration(doc)
        +upsertDetector(doc)
    }


    %% Plugin Initialization
    ContentManagerPlugin --> CtiConsole : Initializes
    ContentManagerPlugin --> RestLayer : Registers
    ContentManagerPlugin --> CatalogSyncJob : Schedules
    ContentManagerPlugin --> ContentJobRunner : Registers Jobs


    %% REST Interactions
    RestLayer --> CtiConsole : Uses
    RestLayer --> CatalogSyncJob : Triggers manually

    %% Job Dependencies
    CatalogSyncJob --> UnifiedConsumerSynchronizer : Delegates
    UnifiedConsumerSynchronizer --> ConsumerService : Checks State
    UnifiedConsumerSynchronizer ..> SnapshotServiceImpl : (if offset == 0)
    UnifiedConsumerSynchronizer ..> UpdateServiceImpl : (if offset < remote)

    %% SAP Interactions
    SnapshotServiceImpl --> SecurityAnalyticsService : Upserts Content
    UpdateServiceImpl --> SecurityAnalyticsService : Upserts Content
    UnifiedConsumerSynchronizer --> SecurityAnalyticsService : Upserts Detectors
```

#### 1. **ContentManagerPlugin**
Main class located at: `/plugins/content-manager/src/main/java/com/wazuh/contentmanager/ContentManagerPlugin.java`

This is the entry point of the plugin:
- Registers REST handlers for subscription and update management.
- Initializes the `CatalogSyncJob` and schedules it via the OpenSearch Job Scheduler.
- Initializes the `CtiConsole` for authentication management.

#### 2. **CatalogSyncJob**
Located at: `/plugins/content-manager/src/main/java/com/wazuh/contentmanager/jobscheduler/jobs/CatalogSyncJob.java`

This class acts as the orchestrator (`JobExecutor`). It is responsible for:
- Executing the content synchronization logic via the `UnifiedConsumerSynchronizer`.
- Managing concurrency using semaphores to prevent overlapping jobs.

#### 3. **Services**
The logic is split into specialized services:

##### 3.1 **ConsumerService**
Located at: `/plugins/content-manager/src/main/java/com/wazuh/contentmanager/cti/catalog/service/ConsumerServiceImpl.java`

Retrieves `LocalConsumer` state from `.cti-consumers` and `RemoteConsumer` state from the CTI API.

##### 3.2 **SnapshotService**
Located at: `/plugins/content-manager/src/main/java/com/wazuh/contentmanager/cti/catalog/service/SnapshotServiceImpl.java`

Handles downloading zip snapshots, unzipping, parsing JSON files, and bulk indexing content.
It supports multiple content types (rules, decoders, etc.) and indexes them into their respective indices.

##### 3.3 **UpdateService**
Located at: `/plugins/content-manager/src/main/java/com/wazuh/contentmanager/cti/catalog/service/UpdateServiceImpl.java`

Fetches specific changes (offsets) from the CTI API and applies them using JSON Patch (`Operation` class).
It ensures that any modified content is immediately propagated to the Security Analytics plugin.

##### 3.4 **SecurityAnalyticsService**
Interface defining the bridge to the Security Analytics Plugin (SAP).

Responsible for:
- `upsertRule(doc)`: Registering detection rules.
- `upsertIntegration(doc)`: Registering integration definitions.
- `upsertDetector(doc)`: Activating detectors based on integration rules.
- `deleteRule(id)`: Deletes a rule using the id of the rule.
- `deleteIntegration(id)`: Deletes a integration using the id.
- `deleteDetector(id)`: Deletes a detector using the id.

##### 3.5 **AuthService**
Located at: `/plugins/content-manager/src/main/java/com/wazuh/contentmanager/cti/console/service/AuthServiceImpl.java`

Manages the exchange of device codes for permanent access tokens.

#### 4. **Indices Management**

##### 4.1 **ConsumersIndex**
Located at: `/plugins/content-manager/src/main/java/com/wazuh/contentmanager/cti/catalog/index/ConsumersIndex.java`

Wraps operations for the `.cti-consumers` index.

##### 4.2 **ContentIndex**
Located at: `/plugins/content-manager/src/main/java/com/wazuh/contentmanager/cti/catalog/index/ContentIndex.java`

Manages operations for content indices.

---

## ⚙️ Configuration Settings

The plugin is configured through the `PluginSettings` class. Settings can be defined in `opensearch.yml`:

| Setting                                              | Default                            | Description                                                                  |
| ---------------------------------------------------- | ---------------------------------- | ---------------------------------------------------------------------------- |
| `plugins.content_manager.cti.api`                    | `https://cti-pre.wazuh.com/api/v1` | Base URL for the Wazuh CTI API.                                              |
| `plugins.content_manager.catalog.sync_interval`      | `60`                               | Interval (in minutes) for the periodic synchronization job.                  |
| `plugins.content_manager.max_items_per_bulk`         | `25`                               | Maximum number of documents per bulk request during snapshot initialization. |
| `plugins.content_manager.max_concurrent_bulks`       | `5`                                | Maximum number of concurrent bulk requests.                                  |
| `plugins.content_manager.client.timeout`             | `10`                               | Timeout (in seconds) for HTTP and Indexing operations.                       |
| `plugins.content_manager.catalog.update_on_start`    | `true`                             | Triggers a content update when the plugin starts.                            |
| `plugins.content_manager.catalog.update_on_schedule` | `true`                             | Enables or disables the periodic content update job.                         |
| `plugins.content_manager.catalog.content.context`    | `development_0.0.3`                | Unified Context identifier for the CTI content.                              |
| `plugins.content_manager.catalog.content.consumer`   | `development_0.0.3_test`           | Unified Consumer identifier for the CTI content.                             |

---

## 🔄 How Content Synchronization Works

```mermaid
sequenceDiagram
    participant Scheduler as JobScheduler/RestAction
    participant SyncJob as CatalogSyncJob
    participant Synchronizer as UnifiedConsumerSynchronizer
    participant ConsumerSvc as ConsumerService
    participant CTI as External CTI API
    participant Snapshot as SnapshotService
    participant Update as UpdateService
    participant Indices as Content Indices
    participant Processors as Processors (Rule/Integration/Detector)
    participant SAP as SecurityAnalyticsPlugin

    Scheduler->>SyncJob: Trigger Execution
    activate SyncJob

    SyncJob->>Synchronizer: synchronize()

    Synchronizer->>ConsumerSvc: getLocalConsumer() / getRemoteConsumer()
    ConsumerSvc->>CTI: Fetch Metadata
    ConsumerSvc-->>Synchronizer: Offsets & Metadata

    alt Local Offset == 0 (Initialization)
        Synchronizer->>Snapshot: initialize(remoteConsumer)
        Snapshot->>CTI: Download Snapshot ZIP
        Snapshot->>Indices: Bulk Index Content (Rules/Integrations/etc.)
        Snapshot-->>Synchronizer: Done
    else Local Offset < Remote Offset (Update)
        Synchronizer->>Update: update(localOffset, remoteOffset)
        Update->>CTI: Fetch Changes
        Update->>Indices: Apply JSON Patches
        Update-->>Synchronizer: Done
    end

    opt Changes Applied (onSyncComplete)
        Synchronizer->>Indices: Refresh Indices

        Note right of Synchronizer: Sync Local Indices to SAP

        Synchronizer->>Processors: IntegrationProcessor.process()
        Processors->>Indices: Search Integrations
        loop For each Integration
            Processors->>SAP: WIndexIntegrationAction
        end

        Synchronizer->>Processors: RuleProcessor.process()
        Processors->>Indices: Search Rules
        loop For each Rule
            Processors->>SAP: WIndexRuleAction
        end

        Synchronizer->>Processors: DetectorProcessor.process()
        Processors->>Indices: Search Integrations (for Detectors)
        loop For each Integration
            Processors->>SAP: WIndexDetectorAction
        end

        Synchronizer->>Synchronizer: calculatePolicyHash()
    end

    deactivate SyncJob
```

### 1. **Initialization Phase**

When the plugin starts on a cluster manager node:

1. Creates the `.cti-consumers` index if it doesn't exist
2. Checks the consumer's local_offset:
   - **If local_offset = 0**: Downloads and indexes a snapshot
   - **If local_offset > 0**: Proceeds with incremental updates
3.  **SAP Registration:** Iterates through each indexed item and invokes the `SecurityAnalyticsService` to perform an `upsertRule` or `upsertIntegration`, ensuring all content is registered for active detection.

### 2. **Update Phase**

When `local_offset > 0` and `local_offset < remote_offset`:

1.  **Fetch Changes:** Fetches changes in batches.
2.  **Apply Patch:** Applies JSON Patch operations (add, update, delete).
3.  **SAP Sync:** Pushes the specific changes to `SecurityAnalyticsService` to update the SAP.
4.  **Offset Update:** Updates the local_offset after successful application.

### 3. **Post-Synchronization Phase**

After changes are applied, the synchronizer performs maintenance:

1.  **Refresh:** Refreshes indices to ensure data is searchable.
2.  **Update Detectors:**
    * Searches for Integration Rules in the local index.
    * Iterates through them and calls `upsertDetector` on the SAP.
3.  **Integrity Check (`hashPolicy`):**
    * Calculates SHA-256 hashes for Rules, Decoders, and Policies to ensure local data integrity matches the source.

### 4. **Error Handling**

If a critical error occurs or data corruption is detected, the system resets `local_offset` to 0, triggering a snapshot re-initialization on the next run.

---

## 📡 REST API

This API is formally defined in OpenAPI specification ([openapi.yml](https://github.com/wazuh/wazuh-indexer-plugins/blob/main/plugins/content-manager/openapi.yml)).

### User Generate Content Management Endpoints

#### Logtest

The Indexer acts as a middleman between the UI and the Engine. The Indexer's `POST /logtest` endpoints accepts the payload and sends it to the engine exactly as provided. No validation is performed. If the engine responds, the Indexer returns it as the response for its endpoint call. If the engine does not respond, a 500 error is returned.

<div class="warning">

A testing policy needs to be loaded in the Engine for the logtest to be executed successfully. Load a policy via the policy promotion endpoint.
</div>

**Diagrams**

```mermaid
---
title: Logtest execution - Sequence diagram
---
sequenceDiagram
    actor User
    participant UI
    participant Indexer
    participant Engine

    User->>UI: run logtest

    UI->>Indexer: POST /logtest
    Indexer->>Engine: POST /logtest
    Engine-->>Indexer: response
    Indexer-->>UI: response
```

```mermaid
---
title: Logtest execution - Flowchart
---
flowchart LR
    UI-- request -->Indexer
    subgraph indexer_node [Indexer node]
    Indexer-->Engine

    Engine -.-> Indexer
    end
    Indexer -. response .-> UI
```

#### Decoders

The Content Manager provides REST API endpoints for managing decoders in the draft space. Decoders are validated against the Wazuh engine before being stored.

<div class="warning">

A testing policy needs to be loaded in the Engine for the decoders to be executed successfully. Load a policy via the policy promotion endpoint.
</div>

**Diagrams**

```mermaid
---
title: Decoder creation - Sequence diagram
---
sequenceDiagram
    actor User
    participant UI
    participant Indexer
    participant Engine
    participant DecoderIndex as .cti-decoders
    participant IntegrationIndex as .cti-integrations

    User->>UI: create decoder
    UI->>Indexer: POST /_plugins/_content_manager/decoders
    Indexer->>Indexer: Generate UUID, prefix with d_
    Indexer->>Engine: POST /content/validate/resource
    Engine-->>Indexer: validation response
    Indexer->>DecoderIndex: Index decoder (draft space)
    Indexer->>IntegrationIndex: Update integration (add decoder reference)
    Indexer-->>UI: response
    UI-->>User: decoder created
```

```mermaid
---
title: Decoder update - Sequence diagram
---
sequenceDiagram
    actor User
    participant UI
    participant Indexer
    participant Engine
    participant DecoderIndex as .cti-decoders

    User->>UI: update decoder
    UI->>Indexer: PUT /_plugins/_content_manager/decoders/{decoder_id}
    Indexer->>DecoderIndex: Check if decoder exists
    DecoderIndex-->>Indexer: exists
    Indexer->>Engine: POST /content/validate/resource
    Engine-->>Indexer: validation response
    Indexer->>DecoderIndex: Update decoder
    Indexer-->>UI: response
    UI-->>User: decoder updated
```

```mermaid
---
title: Decoder deletion - Sequence diagram
---
sequenceDiagram
    actor User
    participant UI
    participant Indexer
    participant DecoderIndex as .cti-decoders
    participant IntegrationIndex as .cti-integrations

    User->>UI: delete decoder
    UI->>Indexer: DELETE /_plugins/_content_manager/decoders/{decoder_id}
    Indexer->>DecoderIndex: Check if decoder exists
    DecoderIndex-->>Indexer: exists
    Indexer->>IntegrationIndex: Update integrations (remove decoder reference)
    Indexer->>DecoderIndex: Delete decoder
    Indexer-->>UI: response
    UI-->>User: decoder deleted
```

#### Draft Policy Management

The indexer's draft policy management endpoint allows the user to update the Draft-Space policy stored in the Wazuh Indexer.


**Diagrams**

```mermaid
---
title: Draft Policy Update - Flowchart
---
flowchart TD
    UI[UI] -->|PUT /policy<br/>JSON payload| Indexer

    subgraph indexer_node [Indexer node]
        Indexer -->|Route request| RestPutPolicyAction

        RestPutPolicyAction -->|1. Validate request| V1{Has content?<br/>Engine available?}
        V1 -->|No| Error1[Return 400/500 error]
        V1 -->|Yes| Parse[2. Parse JSON to Policy object]

        Parse -->|Success| V2{3. Validate Policy<br/>fields}
        Parse -->|Fail| Error2[Return 400 error:<br/>Invalid JSON]

        V2 -->|Field is null| Error3[Return 400 error:<br/>Field cannot be null]
        V2 -->|All fields valid| Store[4. Store Policy]

        Store -->|Find/generate ID| ContentIndex[ContentIndex.create]
        ContentIndex -->|Index to| DraftIndex[(.cti-policies.draft)]
        DraftIndex -->|Success| Success[Return 200 OK<br/>with Policy object]

        Error1 --> Response
        Error2 --> Response
        Error3 --> Response
        Success --> Response
    end

    Response[Response] -.->|HTTP response| UI
```

#### Policy Schema

The `.cti-policies` index stores policy configurations that define how the Wazuh Engine processes events. Each indexed document has the following structure:

**Top-level fields:**

| Field      | Type   | Description                                     |
| ---------- | ------ | ----------------------------------------------- |
| `document` | object | Contains the policy configuration fields        |
| `hash`     | object | Contains the policy content hash (`sha256`)     |
| `space`    | object | Contains the space information (`name`, `hash`) |

**Fields within `document` object:**

| Field           | Type    | Description                                                                           |
| --------------- | ------- | ------------------------------------------------------------------------------------- |
| `id`            | keyword | Unique identifier for the policy document                                             |
| `title`         | keyword | Human-readable name for the policy                                                    |
| `date`          | date    | Creation timestamp                                                                    |
| `modified`      | date    | Last modification timestamp                                                           |
| `root_decoder`  | keyword | Identifier of the root decoder to use for event processing                            |
| `integrations`  | keyword | Array of integration IDs that define which content modules are active                 |
| `filters`       | keyword | Array of filter UUIDs for user-generated filtering rules                              |
| `enrichments`   | keyword | Array of enrichment types (e.g., `"file"`, `"domain-name"`, `"ip"`, `"url"`, `"geo"`) |
| `author`        | keyword | Policy author identifier                                                              |
| `description`   | text    | Brief description of the policy purpose                                               |
| `documentation` | keyword | Link or reference to detailed documentation                                           |
| `references`    | keyword | Array of external reference URLs                                                      |

**Example Policy Document:**

```json
{
  "document": {
    "id": "policy-123",
    "title": "Production Policy",
    "root_decoder": "decoder/core/0",
    "integrations": [
      "integration/wazuh-core/0",
      "integration/wazuh-fim/0"
    ],
    "filters": [
      "5c1df6b6-1458-4b2e-9001-96f67a8b12c8",
      "f61133f5-90b9-49ed-b1d5-0b88cb04355e"
    ],
    "enrichments": ["file", "domain-name", "ip", "url", "geo"],
    "author": "security-team",
    "description": "Production environment policy with file and network enrichments",
    "documentation": "https://docs.wazuh.com/policies/production",
    "references": ["https://example.com/security-policy"]
  },
  "hash": {
    "sha256": "abc123..."
  },
  "space": {
    "name": "draft",
    "hash": {
      "sha256": "xyz789..."
    }
  }
}
```

## 🔍 Debugging

### Check Consumer Status

```bash
GET /.cti-consumers/_search
{
  "query": {
    "match_all": {}
  }
}
```

### Check Content Index

```bash
GET /.cti-rules/_search
{
  "size": 10
}
```

### Monitor Plugin Logs

Look for entries from `ContentManagerPlugin`, `CatalogSyncJob`, `SnapshotServiceImpl`  and `UpdateServiceImpl` in the OpenSearch logs.

```bash
tail -f logs/opensearch.log | grep -E "ContentManager|CatalogSyncJob|SnapshotServiceImpl|UpdateServiceImpl"
```

---

## 📌 Important Notes

- The plugin only runs on **cluster manager nodes**
- CTI API must be accessible for content synchronization
- Offset-based synchronization ensures no content is missed

---
## 🧪 Testing

The plugin includes integration tests defined in the `tests/content-manager` directory. These tests cover various scenarios for managing integrations, decoders, rules, and KVDBs through the REST API.

#### 01 - Integrations: Create Integration (9 scenarios)
| # | Scenario |
|---|----------|
| 1 | Successfully create an integration |
| 2 | Create an integration with the same title as an existing integration |
| 3 | Create an integration with missing title |
| 4 | Create an integration with missing author |
| 5 | Create an integration with missing category |
| 6 | Create an integration with an explicit id in the resource |
| 7 | Create an integration with missing resource object |
| 8 | Create an integration with empty body |
| 9 | Create an integration without authentication |

#### 01 - Integrations: Update Integration (8 scenarios)
| # | Scenario |
|---|----------|
| 1 | Successfully update an integration |
| 2 | Update an integration changing its title to a title that already exists in draft space |
| 3 | Update an integration with missing required fields |
| 4 | Update an integration that does not exist |
| 5 | Update an integration with an invalid UUID |
| 6 | Update an integration with an id in the request body |
| 7 | Update an integration attempting to add/remove dependency lists |
| 8 | Update an integration without authentication |

#### 01 - Integrations: Delete Integration (7 scenarios)
| # | Scenario |
|---|----------|
| 1 | Successfully delete an integration with no attached resources |
| 2 | Delete an integration that has attached resources |
| 3 | Delete an integration that does not exist |
| 4 | Delete an integration with an invalid UUID |
| 5 | Delete an integration without providing an ID |
| 6 | Delete an integration not in draft space |
| 7 | Delete an integration without authentication |

#### 02 - Decoders: Create Decoder (7 scenarios)
| # | Scenario |
|---|----------|
| 1 | Successfully create a decoder |
| 2 | Create a decoder without an integration reference |
| 3 | Create a decoder with an explicit id in the resource |
| 4 | Create a decoder with an integration not in draft space |
| 5 | Create a decoder with missing resource object |
| 6 | Create a decoder with empty body |
| 7 | Create a decoder without authentication |

#### 02 - Decoders: Update Decoder (7 scenarios)
| # | Scenario |
|---|----------|
| 1 | Successfully update a decoder |
| 2 | Update a decoder that does not exist |
| 3 | Update a decoder with an invalid UUID |
| 4 | Update a decoder not in draft space |
| 5 | Update a decoder with missing resource object |
| 6 | Update a decoder with empty body |
| 7 | Update a decoder without authentication |

#### 02 - Decoders: Delete Decoder (7 scenarios)
| # | Scenario |
|---|----------|
| 1 | Successfully delete a decoder |
| 2 | Delete a decoder that does not exist |
| 3 | Delete a decoder with an invalid UUID |
| 4 | Delete a decoder not in draft space |
| 5 | Delete a decoder without providing an ID |
| 6 | Delete a decoder without authentication |
| 7 | Verify decoder is removed from index after deletion |

#### 03 - Rules: Create Rule (7 scenarios)
| # | Scenario |
|---|----------|
| 1 | Successfully create a rule |
| 2 | Create a rule with missing title |
| 3 | Create a rule without an integration reference |
| 4 | Create a rule with an explicit id in the resource |
| 5 | Create a rule with an integration not in draft space |
| 6 | Create a rule with empty body |
| 7 | Create a rule without authentication |

#### 03 - Rules: Update Rule (7 scenarios)
| # | Scenario |
|---|----------|
| 1 | Successfully update a rule |
| 2 | Update a rule with missing title |
| 3 | Update a rule that does not exist |
| 4 | Update a rule with an invalid UUID |
| 5 | Update a rule not in draft space |
| 6 | Update a rule with empty body |
| 7 | Update a rule without authentication |

#### 03 - Rules: Delete Rule (7 scenarios)
| # | Scenario |
|---|----------|
| 1 | Successfully delete a rule |
| 2 | Delete a rule that does not exist |
| 3 | Delete a rule with an invalid UUID |
| 4 | Delete a rule not in draft space |
| 5 | Delete a rule without providing an ID |
| 6 | Delete a rule without authentication |
| 7 | Verify rule is removed from index after deletion |

#### 04 - KVDBs: Create KVDB (9 scenarios)
| # | Scenario |
|---|----------|
| 1 | Successfully create a KVDB |
| 2 | Create a KVDB with missing title |
| 3 | Create a KVDB with missing author |
| 4 | Create a KVDB with missing content |
| 5 | Create a KVDB without an integration reference |
| 6 | Create a KVDB with an explicit id in the resource |
| 7 | Create a KVDB with an integration not in draft space |
| 8 | Create a KVDB with empty body |
| 9 | Create a KVDB without authentication |

#### 04 - KVDBs: Update KVDB (7 scenarios)
| # | Scenario |
|---|----------|
| 1 | Successfully update a KVDB |
| 2 | Update a KVDB with missing required fields |
| 3 | Update a KVDB that does not exist |
| 4 | Update a KVDB with an invalid UUID |
| 5 | Update a KVDB not in draft space |
| 6 | Update a KVDB with empty body |
| 7 | Update a KVDB without authentication |

#### 04 - KVDBs: Delete KVDB (7 scenarios)
| # | Scenario |
|---|----------|
| 1 | Successfully delete a KVDB |
| 2 | Delete a KVDB that does not exist |
| 3 | Delete a KVDB with an invalid UUID |
| 4 | Delete a KVDB not in draft space |
| 5 | Delete a KVDB without providing an ID |
| 6 | Delete a KVDB without authentication |
| 7 | Verify KVDB is removed from index after deletion |

#### 05 - Policy: Policy Initialization (6 scenarios)
| # | Scenario |
|---|----------|
| 1 | The ".cti-policies" index exists |
| 2 | Exactly four policy documents exist (one per space) |
| 3 | Standard policy has a different document ID than draft/test/custom |
| 4 | Draft, test, and custom policies start with empty integrations and root_decoder |
| 5 | Each policy document contains the expected structure |
| 6 | Each policy has a valid SHA-256 hash |

#### 05 - Policy: Update Draft Policy (12 scenarios)
| # | Scenario |
|---|----------|
| 1 | Successfully update the draft policy |
| 2 | Update policy with missing type field |
| 3 | Update policy with wrong type value |
| 4 | Update policy with missing resource object |
| 5 | Update policy with missing required fields in resource |
| 6 | Update policy attempting to add an integration to the list |
| 7 | Update policy attempting to remove an integration from the list |
| 8 | Update policy with reordered integrations list (allowed) |
| 9 | Update policy with empty body |
| 10 | Update policy without authentication |
| 11 | Verify policy changes are NOT reflected in test space until promotion |
| 12 | Verify policy changes are reflected in test space after promotion |

#### 06 - Log Test (4 scenarios)
| # | Scenario |
|---|----------|
| 1 | Successfully test a log event |
| 2 | Send log test with empty body |
| 3 | Send log test with invalid JSON |
| 4 | Send log test without authentication |

#### 07 - Promote: Preview Promotion (7 scenarios)
| # | Scenario |
|---|----------|
| 1 | Preview promotion from draft to test |
| 2 | Preview promotion from test to custom |
| 3 | Preview promotion with missing space parameter |
| 4 | Preview promotion with empty space parameter |
| 5 | Preview promotion with invalid space value |
| 6 | Preview promotion from custom (not allowed) |
| 7 | Preview promotion without authentication |

#### 07 - Promote: Execute Promotion (18 scenarios)
| # | Scenario |
|---|----------|
| 1 | Successfully promote from draft to test |
| 2 | Verify resources exist in test space after draft to test promotion |
| 3 | Verify promoted resources exist in both draft and test spaces |
| 4 | Verify test space hash is regenerated after draft to test promotion |
| 5 | Verify promoted resource hashes match between draft and test spaces |
| 6 | Verify deleting a decoder in draft does not affect promoted test space |
| 7 | Successfully promote from test to custom |
| 8 | Verify resources exist in custom space after test to custom promotion |
| 9 | Verify promoted resources exist in both test and custom spaces |
| 10 | Verify custom space hash is regenerated after test to custom promotion |
| 11 | Verify promoted resource hashes match between test and custom spaces |
| 12 | Promote from custom (not allowed) |
| 13 | Promote with invalid space |
| 14 | Promote with missing changes object |
| 15 | Promote with incomplete changes (missing required resource arrays) |
| 16 | Promote with non-update operation on policy |
| 17 | Promote with empty body |
| 18 | Promote without authentication |


---

## 🔗 Related Documentation

- [Setup Plugin Guide](./setup.md)
- [OpenSearch Plugin Development](https://docs.opensearch.org/3.3/install-and-configure/plugins/)
