# Architecture

## Design

The plugin hooks into the node's startup lifecycle and creates every required index template, index, and data stream before the node is considered ready to serve Wazuh data. By design, the plugin overwrites any existing index template under the same name, so template changes shipped in a new version take effect automatically on restart.

Before it creates them, the plugin reads its configuration file, `setup.yml`, which can override some index settings of the templates and replace the ISM policies. The file is read at every initialization, so the templates always hold the bundled definitions plus the overrides the file has at that moment. See [Customization](customization.md).

### Retry mechanism

The plugin features a retry mechanism to handle transient faults. In case of a temporal failure (timeouts or similar) during the initialization of the indices, the task is retried after a given amount of time (back-off). If two consecutive faults occur during the initialization of the same index, the initialization process is halted, and the node is shut down. Proper logging is in place to notify administrators before the shutdown occurs.

The back-off time is configurable. Head to [Configuration](./configuration.md) for more information.

### Readiness marker

The plugin persists its initialization state in the hidden `.wazuh-setup-status` index, in the document with id `setup-status`. Other plugins (currently Content Manager) read this marker to defer their own startup work until Setup has finished creating its indices and every index is at the shipped schema version, avoiding races where a dependent index template doesn't exist yet or an index is still being upgraded.

The marker transitions once per boot:

| Value     | Meaning                                                                                                                                                                          |
| --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `running` | Index initialization is in progress (set at the start of index initialization, overwriting any marker left over from a previous boot), or at least one index still needs a schema upgrade (see [Schema versions](#schema-versions)). |
| `ready`   | All index templates, indices and data streams have been created successfully, and every index is at the shipped schema version.                                                  |
| `failed`  | Index initialization could not complete: the configuration file is invalid, or an unhandled exception was thrown while initializing one of the indices or while detecting the schema version of one of them. The log names the key, the file or the index. |

Writing the marker is best-effort: a failure to persist it is logged but never interrupts node startup.

### Alias-backed indices

The stateful indices and the threat intel content indices are not addressed by their own name. For each of them the plugin creates a concrete index named `<name>-a` and a write alias named `<name>` pointing at it. The Wazuh server, the dashboard and the API read and write through `<name>` and never address the concrete index. The alias makes a rebuild a plain operation: the data is rebuilt into the spare `<name>-b` slot while `<name>-a` keeps serving, and the alias is switched in one atomic step. The slots alternate on each rebuild, so the plugin leaves an existing alias alone whichever slot it points at.

A concrete index at the alias name cannot coexist with the alias. For the content indices it can only come from a write that reached the name before the alias existed, which OpenSearch auto-created with dynamic mappings; it is deleted and its content downloaded again. For the stateful indices it is not expected at all: the plugin creates the alias before any writer can reach the name, and the user the Wazuh server writes with cannot create indices. An empty one is deleted so the alias can take the name. One that holds documents is kept, since it is the state of every agent and nothing re-sends it, and the initialization fails naming it; the marker is set to `failed` until the index is deleted or reindexed by hand.

### Schema versions

Every index template carries two release numbers in its `mappings._meta`: `schema_version`, the release that last changed the template, and `compat_version`, the oldest `schema_version` whose indices can still be upgraded in place. A release number is the release version with one digit for the major and two for each of the minor and the patch, so 5.0.0 is `50000` and 5.2.1 is `50201`. An index inherits the `_meta` of the template it is created from, so its own `schema_version` says which template it was built with.

A stored template only applies to indices created afterwards. After a package upgrade the existing indices keep the mappings and settings of the previous version, so at every initialization, after the templates are written and the indices created, the plugin compares the `schema_version` of every index it manages against the shipped template and classifies it:

| Status             | Condition                                                   | Meaning                                                               |
| ------------------ | ----------------------------------------------------------- | --------------------------------------------------------------------- |
| `up_to_date`       | installed version equals the shipped `schema_version`       | Nothing to do. An index newer than the shipped template (a downgrade, which is not supported) is reported the same way and left alone. |
| `upgrade_in_place` | installed version is at least the shipped `compat_version`  | The shipped mappings and dynamic settings can be applied to the index. |
| `rebuild_required` | installed version is below the shipped `compat_version`, or the index carries no version (`0`) | The index must be rebuilt from the shipped template.                  |

The installed version is read from the live index: the index itself, the write index of a data stream, or the write index behind a content alias. Detection reads version metadata only; it never compares the live mappings or settings against the shipped files.

The result is stored in `.wazuh-setup-status`, one document per managed index, with the index name as document id:

```json
{
  "index": "wazuh-states-sca",
  "installed": 50000,
  "shipped": 50300,
  "compat": 50200,
  "status": "upgrade_in_place",
  "step": "mappings_updated",
  "updated_at": "2026-11-17T10:00:00Z"
}
```

`step` is the last step an upgrade in progress completed; it is absent when no upgrade is in progress. Detection keeps the step of an index that is still pending, so an upgrade interrupted by a restart resumes where it stopped, and drops it once the index is up to date. Each index that is not up to date is also reported in the log, with its installed and shipped versions and its status.

The marker is set to `ready` only when every record is `up_to_date`; while any index is pending it stays `running`. The ISM configuration index (`.opendistro-ism-config`) has no record: the ISM plugin versions that mapping itself. The `.wazuh-setup-status` index is the one exception to "a stored template only applies to indices created afterwards": it holds the records of the running version, so the plugin pushes the shipped mappings to it on every boot before writing them.

### Replica configuration

During the node initialization, the plugin checks for the presence of the `cluster.default_number_of_replicas` setting in the node configuration. If this setting is defined, the plugin automatically updates the cluster's persistent settings with this value. This ensures that the default number of replicas is consistently applied across the cluster as defined in the configuration file.

The packaged configuration sets `cluster.default_number_of_replicas` to `0`, so that a single node stays green. The Wazuh indices set `index.auto_expand_replicas: 0-1` instead: no replica on a single node, and one replica as soon as a second node joins, so the cluster can lose a node without losing a primary. To use another range or a fixed number of replicas, override it in `setup.yml`, as described in [Customization](customization.md#index-template-settings).

Two plugins create internal indices with a fixed replica count and no auto-expand option: Index State Management, for its history indices (`.opendistro-ism-managed-index-history-*`), and the security plugin, for the backing indices of the `security-auditlogs` data stream (`.ds-security-auditlogs-*`). The setup plugin creates these indices with `index.auto_expand_replicas: 0-1` too.

### Write durability of the stream indices

By default, an index syncs every write to disk before it acknowledges it. Three stream families set `index.translog.durability: async` instead:

- `wazuh-events-v5-<category>`
- `wazuh-events-raw-v5`
- `wazuh-findings-v5-<category>`

These streams acknowledge a write once every copy of the shard has it, and sync it to disk in the background every 5 seconds, the default of `index.translog.sync_interval`. The active responses, metrics and AI assistant sessions streams, and every stateful index, keep the default, `request`. Active responses keep it because a lost request would never be executed.

The sync on every request limits how fast these streams accept data. With the large batches the Wazuh Manager sends, the indexer accepts about as many events per second either way, but with `async` it keeps up with a sustained load that otherwise makes it fall behind. Small batches gain the most, and the findings are written in small batches.

#### What a stop can lose

- **A normal stop or restart loses nothing.** When the service is stopped or restarted, including during an upgrade, the indexer writes every index to disk before it exits.
- **An abrupt stop can lose up to the last 5 seconds of acknowledged writes** to these streams on that node. An abrupt stop is a killed process, a power cut, or a host that crashes or freezes.
- **A replica on another node covers the loss of one node.** The copy on the node that keeps running still has the writes, so they are lost only if every copy stops abruptly within the same 5 seconds. A single-node deployment has no second copy, so it is the most exposed.
- **A stop that is cut short is an abrupt stop.** The packages let the service take as long as it needs to stop. Container platforms kill the process when their stop timeout expires, 10 seconds by default in Docker and 30 seconds in Kubernetes. On a node with many indices, raise it (`stop_grace_period` in Docker Compose, `terminationGracePeriodSeconds` in Kubernetes).

A lost write is not sent again, because its sender received the acknowledgement. Besides the missing events and findings, an abrupt stop has one more effect: **detection skips new events.** After the node starts again, the detection rules skip as many new events of each affected stream as the stream lost. Findings created from the lost events can remain, pointing to events that no longer exist.

#### Changing the durability

To make a stream sync every write before acknowledging it again, override the setting in the plugin's configuration file, `setup.yml`:

```yaml
# The three stream families that default to async
templates.streams.events.settings.index.translog.durability: request
templates.streams.raw.settings.index.translog.durability: request
templates.streams.findings.settings.index.translog.durability: request
```

`templates.streams.*.settings.index.translog.durability: request` does the same for every stream at once. The same key with `async` turns it on for a stream that defaults to `request`. See [Customization](customization.md) for the file and for when a change takes effect.

The file changes the index templates, so the backing indices created from then on. `index.translog.durability` is a dynamic index setting, so the backing indices that exist are changed with the settings API:

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X PUT "https://127.0.0.1:9200/wazuh-events-v5-*,wazuh-events-raw-v5,wazuh-findings-v5-*/_settings" \
  -H 'Content-Type: application/json' \
  -d '{"index.translog.durability": "request"}'
```

Do both. The request alone does not last: a backing index created by a later rollover takes the value of its index template again. Editing the index template does not keep it either, because the plugin writes its templates again at every restart.

To check the value of each backing index:

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X GET "https://127.0.0.1:9200/wazuh-events-v5-*,wazuh-events-raw-v5,wazuh-findings-v5-*/_settings/index.translog.durability?flat_settings=true&pretty"
```

## Wazuh Common Schema

Refer to the [docs](https://github.com/wazuh/wazuh-indexer-plugins/tree/main/wcs) for complete definitions of the indices. The indices inherit the settings and mappings defined in the index templates.

### Event stream templates

All event categories share a single base template. One index template per category is generated dynamically at deployment time from this shared base. Specialized streams (raw, active-responses) use their own dedicated template files.

The WCS field definitions are organized under `wcs/stateless/events/`:

```
wcs/stateless/events/
├── findings/   # Fields for findings events
├── main/       # Shared fields for all event categories
└── raw/        # Fields for raw (unprocessed) events
```

For the underlying class structure and implementation details, see the [development guide](../../../dev/plugins/setup.md).
