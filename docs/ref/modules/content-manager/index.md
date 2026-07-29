# Content Manager

The Content Manager is a Wazuh Indexer plugin responsible for managing detection content — rules, decoders, integrations, key-value databases (KVDBs), and Indicators of Compromise (IoCs). It synchronizes content from the Wazuh Cyber Threat Intelligence (CTI) API, provides a REST API for user-generated content, and communicates with the Wazuh Engine to activate changes.

It also includes the **Update check system**, which communicates with the CTI **Update check API** once per day to let Wazuh determine whether a newer Wazuh version is available for the deployment.

Update check components are:

- **Update check API** (CTI)
- **Update check system** (Wazuh Indexer)
- **Update check UI** (Wazuh Dashboard)

## Content synchronization

The Content Manager synchronizes three categories of detection content from the Wazuh CTI API, each updated independently:

- **Catalog content** — detection rules, decoders, integrations, key-value databases (KVDBs), and the routing policy.
- **IoC feed** — Indicators of Compromise (IoC) for threat detection enrichment.
- **CVE feed** — Common Vulnerabilities and Exposures (CVE) data for vulnerability detection. CVE entries are only added or updated, never removed.

On first start, the plugin initializes from a snapshot. If a custom CTI catalog URL is configured, it downloads the snapshot from that source; otherwise it uses the snapshot bundled with the Wazuh Indexer package, so detection content is available immediately even without network access.

Once initialized, the plugin keeps content current automatically. A sync check runs at startup and again on a regular schedule — every 60 minutes by default. Each check fetches only the changes since the last sync: new or updated resources are added, removed resources are deleted. If the local content cannot be reconciled with the remote state, the plugin recovers by re-downloading the latest snapshot.

Both behaviors are configurable in `opensearch.yml`:

- **`plugins.content_manager.catalog.update_on_start`** (Boolean, default `true`) — whether to check for updates when the plugin starts.
- **`plugins.content_manager.catalog.sync_interval`** (Integer, default `60`) — how often periodic sync runs, in minutes.

When telemetry is enabled (the default), the plugin also sends a daily heartbeat to the Wazuh CTI service with the cluster UUID and the deployed Wazuh version. This powers the update notification shown in the Wazuh Dashboard when a newer release is available. To opt out, set `plugins.content_manager.telemetry.enabled` to `false`.

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
