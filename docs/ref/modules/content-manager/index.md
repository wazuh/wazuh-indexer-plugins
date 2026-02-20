# Content Manager

The Content Manager is a Wazuh Indexer plugin responsible for managing detection content — rules, decoders, integrations, key-value databases (KVDBs), and Indicators of Compromise (IoCs). It synchronizes content from the Wazuh Cyber Threat Intelligence (CTI) API, provides a REST API for user-generated content, and communicates with the Wazuh Engine to activate changes.

## CTI Synchronization

The Content Manager periodically synchronizes content from the Wazuh CTI API. Two content contexts are managed:

- **Catalog context** (`development_0.0.3`): Contains detection rules, decoders, integrations, KVDBs, and the routing policy.
- **IoC context** (`ioc_provider`): Contains Indicators of Compromise for threat detection.

Each context has an associated **consumer** that tracks synchronization state (current offset, snapshot URL) in the `.cti-consumers` index.

### Snapshot Initialization

On first run (when the local offset is `0`), the Content Manager performs a full snapshot initialization:

1. Fetches the latest snapshot URL from the CTI API.
2. Downloads and extracts the ZIP archive.
3. Indexes the content into the appropriate system indices using bulk operations.
4. Records the snapshot offset in `.cti-consumers`.

### Incremental Updates

When the local offset is behind the remote offset, the Content Manager fetches changes in batches (up to 1000 per request) and applies create, update, and delete operations to the content indices. The local offset is updated after each successful batch.

### Sync Schedule

By default, synchronization runs:
- **On plugin startup** (`plugins.content_manager.catalog.update_on_start: true`)
- **Periodically** every 60 minutes (`plugins.content_manager.catalog.sync_interval: 60`)

The periodic job is registered with the OpenSearch Job Scheduler and tracked in the `.wazuh-content-manager-jobs` index.

## User-Generated Content

The Content Manager provides a full CUD REST API for creating custom detection content:

- **Rules**: Custom detection rules associated with an integration.
- **Decoders**: Custom log decoders associated with an integration.
- **Integrations**: Logical groupings of related rules, decoders, and KVDBs.
- **KVDBs**: Key-value databases used by rules and decoders for lookups.

User-generated content is stored in the **draft space** and is separate from the CTI-managed **standard space**. This separation ensures that user customizations never conflict with upstream CTI content.

See the [API Reference](api.md) for endpoint details.

## Content Spaces

The Content Manager organizes content into spaces:

| Space | Description |
|---|---|
| **Standard** | Read-only content synced from the CTI API. This is the baseline detection content. |
| **Draft** | Writable space for user-generated content. CUD operations target this space. |
| **Test** | Used for logtest operations and content validation before final promotion. |
| **Custom** | The final space for user content. Content promoted to this space is used by the Wazuh Engine (via the manager package) to actively decode and process logs. |

Content flows through spaces in a promotion chain: **Draft → Test → Custom**. The Standard space exists independently as the upstream CTI baseline. Each space maintains its own copies of rules, decoders, integrations, KVDBs, filters, and the routing policy within the system indices.

## Policy Management

The routing **policy** defines how the Wazuh Engine processes incoming events — which integrations are active and in what order. The Content Manager provides an API to update the draft policy:

```bash
curl -sk -u admin:admin -X PUT \
  "https://192.168.56.6:9200/_plugins/_content_manager/policy" \
  -H 'Content-Type: application/json' \
  -d '{"resource": { ... }}'
```

Policy changes are applied to the draft space and take effect after promotion.

## Promotion Workflow

The promotion workflow moves content through the space chain (**Draft → Test → Custom**):

1. **Preview changes**: `GET /_plugins/_content_manager/promote?space=draft` returns a diff of what will change (additions, updates, deletions for each content type).
2. **Execute promotion**: `POST /_plugins/_content_manager/promote` promotes the content from the source space to the next space in the chain.

The promotion chain works as follows:
- **Draft → Test**: Content is promoted for validation and logtest operations.
- **Test → Custom**: Once validated, content is promoted to the Custom space where it becomes active — the Wazuh Engine (via the manager package) uses this space to decode and process logs in production.

During promotion, the Content Manager:
- Sends updated content to the Engine
- Validates the configuration
- Triggers a configuration reload
- Updates the target space to reflect the promoted content

## Engine Communication

The Content Manager communicates with the Wazuh Engine through a Unix domain socket located at:

```
/usr/share/wazuh-indexer/engine/sockets/engine-api.sock
```

This socket is used for:

- **Logtest**: Sends a log event to the Engine for analysis and returns the decoded/matched result.
- **Content validation**: Validates rules and decoders before promotion.
- **Configuration reload**: Signals the Engine to reload its configuration after promotion.

## System Indices

The Content Manager uses the following system indices:

| Index | Description |
|---|---|
| `.cti-consumers` | Synchronization state for each CTI context/consumer pair (offsets, snapshot URLs) |
| `.cti-rules` | Detection rules (both CTI-synced and user-generated, across all spaces) |
| `.cti-decoders` | Log decoders |
| `.cti-integrations` | Integration definitions |
| `.cti-kvdbs` | Key-value databases |
| `.cti-policies` | Routing policies |
| `.cti-iocs` | Indicators of Compromise |
| `.engine-filters` | Engine filters (routing filters for event classification) |
| `.wazuh-content-manager-jobs` | Job Scheduler metadata for the periodic sync job |

## CTI Subscription

To synchronize content from the CTI API, the Wazuh Indexer requires a valid subscription token. The subscription is managed through the REST API:

1. **Register** a subscription with a device code obtained from the Wazuh CTI Console.
2. The Content Manager stores the token and uses it for all CTI API requests.
3. Without a valid subscription, sync operations return a `Token not found` error.

See [Subscription Management](api.md#get-cti-subscription) in the API Reference.
