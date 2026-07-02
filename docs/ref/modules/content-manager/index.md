# Content Manager

The Content Manager is a Wazuh Indexer plugin responsible for managing detection content — rules, decoders, integrations, key-value databases (KVDBs), and Indicators of Compromise (IoCs). It synchronizes content from the Wazuh Cyber Threat Intelligence (CTI) API, provides a REST API for user-generated content, and communicates with the Wazuh Engine to activate changes.

It also includes the **Update check system**, which communicates with the CTI **Update check API** once per day to let Wazuh determine whether a newer Wazuh version is available for the deployment.

Update check components are:

- **Update check API** (CTI)
- **Update check system** (Wazuh Indexer)
- **Update check UI** (Wazuh Dashboard)

## Content synchronization

The Content Manager periodically synchronizes content from the Wazuh CTI API. Three catalog consumers are managed:

- **Catalog context**: contains detection rules, decoders, integrations, KVDBs, and the routing policy.
- **IoC context**: contains Indicators of Compromise (IoC) for threat detection.
- **CVE context**: contains Common Vulnerabilities and Exposures (CVE) data, stored in the hidden `.wazuh-threatintel-vulnerabilities` index. CVE documents do not have a space and are not subject to removals from CTI.

Each catalog type has an associated consumer state document in `.wazuh-cti-consumers`, keyed by consumer type (for example, `cti:catalog:consumer:ruleset`).

### Snapshot initialization

On first run (when the local offset is `0`), the Content Manager performs snapshot initialization:

1. If a custom catalog URL is configured, it first attempts remote snapshot initialization using that consumer.
2. If remote initialization fails, it falls back to the local packaged snapshot when available.
3. If no custom catalog URL is configured, it initializes from the local packaged snapshot.
4. It indexes content into the appropriate system indices using bulk operations and updates `.wazuh-cti-consumers` offsets.

### Incremental updates

When the local offset is behind the remote offset, the Content Manager fetches changes in batches (up to 1000 per request) and applies creation, update, and removal operations to the content indices. The local offset is updated after each successful batch.

If the local offset is ahead of the remote offset (e.g., consumer was changed), or if the update fails, the Content Manager resets to the latest snapshot to realign with the CTI API.

### Sync schedule

By default, synchronization runs:
- **On plugin startup** (`plugins.content_manager.catalog.update_on_start: true`)
- **Periodically** every 60 minutes (`plugins.content_manager.catalog.sync_interval: 60`)

The periodic job is registered with the OpenSearch Job Scheduler and tracked in the `.wazuh-content-manager-jobs` index.

## Update check service

When `plugins.content_manager.telemetry.enabled` is `true` (default), the Content Manager schedules a daily update check heartbeat job.

- **Frequency:** every 24 hours (with an immediate first ping as soon as the job is registered)
- **Scheduler document ID:** `wazuh-telemetry-ping-job`
- **Endpoint:** CTI `/ping`
- **Data sent:** cluster UUID and deployed Wazuh version (through headers)

This information is used to detect update availability and surface notifications through the Wazuh Dashboard.

## User-generated content

The Content Manager provides a full CUD (create, update, delete) REST API for creating custom detection content:

- **Rules**: custom detection rules associated with an integration.
- **Decoders**: custom log decoders associated with an integration.
- **Integrations**: logical groupings of related rules, decoders, and KVDBs.
- **KVDBs**: key-value databases used by rules and decoders for lookups.

User-generated content is stored in the **draft space** and is separate from the CTI-managed **standard space**. This separation ensures that user customizations never conflict with upstream CTI content.

See the [API reference](api.md) for endpoint details.

## Content spaces

The Content Manager organizes content into spaces:

| Space        | Description                                                                                                                                                 |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Standard** | Read-only content synced from the CTI API. This is the baseline detection content.                                                                          |
| **Draft**    | Writable space for user-generated content. CUD operations target this space.                                                                                |
| **Test**     | Used for logtest operations and content validation before final promotion.                                                                                  |
| **Custom**   | The final space for user content. Content promoted to this space is used by the Wazuh Engine (via the manager package) to actively decode and process logs. |

Content flows through spaces in a promotion chain: **Draft → Test → Custom**. The Standard space exists independently as the upstream CTI baseline. Each space maintains its own copies of rules, decoders, integrations, KVDBs, filters, and the routing policy within the system indices.

## Policy management

The routing **policy** defines how the Wazuh Engine processes incoming events — which integrations are active and in what order. The Content Manager provides an API to update the draft policy:

```bash
curl -sk -u admin:admin -X PUT \
  "https://127.0.0.1:9200/_plugins/_content_manager/policy" \
  -H 'Content-Type: application/json' \
  -d '{"resource": { ... }}'
```

Policy changes are applied to the draft space and take effect after promotion.

## Promotion workflow

The promotion workflow moves content through the space chain (**Draft → Test → Custom**):

1. **Preview changes**: `GET /_plugins/_content_manager/promote?space=draft` returns a diff of what will change (additions, updates, deletions for each content type).
2. **Execute promotion**: `POST /_plugins/_content_manager/promote` promotes the content from the source space to the next space in the chain.

The promotion chain works as follows:
- **Draft → Test**: content is promoted for validation and logtest operations.
- **Test → Custom**: once validated, content is promoted to the Custom space where it becomes active — the Wazuh Engine (via the manager package) uses this space to decode and process logs in production.

During promotion, the Content Manager:
- Sends updated content to the Engine
- Validates the configuration
- Triggers a configuration reload
- Updates the target space to reflect the promoted content

## Engine communication

The Content Manager communicates with the Wazuh Engine through a Unix domain socket located at:

```
/usr/share/wazuh-indexer/engine/sockets/engine-api.sock
```

This socket is used for:

- **Logtest**: sends a log event to the Engine for analysis and returns the decoded/matched result.
- **Content validation**: validates rules and decoders before promotion.
- **Configuration reload**: signals the Engine to reload its configuration after promotion.

## System indices

The Content Manager uses the following system indices:

| Index                                | Description                                                                                          |
| -------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `.wazuh-cti-consumers`                | Synchronization state for each CTI consumer type (`type`, `resource`, `is_public`, offsets, status)   |
| `.wazuh-internal-state`               | Persisted CTI access token (hidden, single document)                                                  |
| `wazuh-threatintel-rules`             | Detection rules (both CTI-synced and user-generated, across all spaces)                               |
| `wazuh-threatintel-decoders`          | Log decoders                                                                                           |
| `wazuh-threatintel-integrations`      | Integration definitions                                                                               |
| `wazuh-threatintel-kvdbs`             | Key-value databases                                                                                    |
| `wazuh-threatintel-policies`          | Routing policies                                                                                       |
| `wazuh-threatintel-enrichments`       | Indicators of Compromise (IoC)                                                                         |
| `.wazuh-threatintel-vulnerabilities`  | Common Vulnerabilities and Exposures (CVE) data from CTI — hidden, no spaces, offset-tracked           |
| `wazuh-threatintel-filters`           | Engine filters (routing filters for event classification)                                             |
| `.wazuh-content-manager-jobs`         | Job Scheduler metadata for periodic sync and update check jobs                                        |

For the alias-backed blue/green storage details and the exact hidden/alias status of each index, see the [development guide's system indices table](../../../dev/plugins/content-manager.md#system-indices).

## Wazuh Cloud subscription

To synchronize content from the CTI API, the Wazuh Indexer requires a valid CTI access token. The token is registered via the REST API:

1. **Store credentials** by sending the CTI access token via `POST /_plugins/_content_manager/subscription`. The token is persisted in the `.wazuh-internal-state` hidden index and loaded into memory.
2. The Content Manager uses the in-memory token for all CTI API requests.
3. Without a registered token, sync operations return a `404 Token not found` error.

See [Subscription management](api.md#store-cti-credentials) in the API reference.

### Pre-registration with Wazuh Cloud

<!-- ANCHOR: deploy-key -->

The Content Manager supports pre-registration of the Wazuh instance with Wazuh Cloud using the `DEPLOY_KEY` environment variable. If this variable is set at startup, the Content Manager automatically registers the token as if it were sent through the REST API, enabling immediate synchronization with the CTI API without manual intervention. Snapshots bundled with the package are removed in favor of fetching the latest content directly from the CTI API using the provided token. This streamlines the setup process for new deployments and ensures that they start with the most up-to-date detection content from their subscription plan.

<!-- ANCHOR_END: deploy-key -->
