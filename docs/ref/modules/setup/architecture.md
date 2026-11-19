# Architecture

## Design

The plugin hooks into the node's startup lifecycle and creates every required index template, index, and data stream before the node is considered ready to serve Wazuh data. By design, the plugin overwrites any existing index template under the same name, so template changes shipped in a new version take effect automatically on restart.

### Retry mechanism

The plugin features a retry mechanism to handle transient faults. In case of a temporal failure (timeouts or similar) during the initialization of the indices, the task is retried after a given amount of time (back-off). If two consecutive faults occur during the initialization of the same index, the initialization process is halted, and the node is shut down. Proper logging is in place to notify administrators before the shutdown occurs.

The back-off time is configurable. Head to [Configuration](./configuration.md) for more information.

### Readiness marker

The plugin persists its initialization state in the hidden, single-document `.wazuh-setup-status` index. Other plugins (currently Content Manager) read this marker to defer their own startup work until Setup has finished creating its indices, avoiding races where a dependent index template doesn't exist yet.

The marker transitions once per boot:

| Value     | Meaning                                                                                                                                                                          |
| --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `running` | Index initialization is in progress (set at the start of index initialization, overwriting any marker left over from a previous boot).                                          |
| `ready`   | All index templates, indices and data streams have been created successfully.                                                                                                    |
| `failed`  | Index initialization could not complete (an unhandled exception was thrown while initializing one of the indices).                                                               |

Writing the marker is best-effort: a failure to persist it is logged but never interrupts node startup.

### Replica configuration

During the node initialization, the plugin checks for the presence of the `cluster.default_number_of_replicas` setting in the node configuration. If this setting is defined, the plugin automatically updates the cluster's persistent settings with this value. This ensures that the default number of replicas is consistently applied across the cluster as defined in the configuration file.

The packaged configuration sets `cluster.default_number_of_replicas` to `0`, so that a single node stays green. The Wazuh indices set `index.auto_expand_replicas: 0-1` instead: no replica on a single node, and one replica as soon as a second node joins, so the cluster can lose a node without losing a primary.

Two plugins create internal indices with a fixed replica count and no auto-expand option: Index State Management, for its history indices (`.opendistro-ism-managed-index-history-*`), and the security plugin, for the backing indices of the `security-auditlogs` data stream (`.ds-security-auditlogs-*`). The setup plugin creates these indices with `index.auto_expand_replicas: 0-1` too.

### Write durability of the stream indices

By default, an index syncs every write to disk before it acknowledges it. Four stream families set `index.translog.durability: async` instead:

- `wazuh-events-v5-<category>`
- `wazuh-events-raw-v5`
- `wazuh-findings-v5-<category>`
- `wazuh-active-responses`

These streams acknowledge a write once every copy of the shard has it, and sync it to disk in the background every 5 seconds, the default of `index.translog.sync_interval`. The metrics and AI assistant sessions streams, and every stateful index, keep the default, `request`.

The sync on every request limits how fast these streams accept data. With the large batches the Wazuh Manager sends, the indexer accepts about as many events per second either way, but with `async` it keeps up with a sustained load that otherwise makes it fall behind. Small batches gain the most, and the findings are written in small batches.

#### What a stop can lose

- **A normal stop or restart loses nothing.** When the service is stopped or restarted, including during an upgrade, the indexer writes every index to disk before it exits.
- **An abrupt stop can lose up to the last 5 seconds of acknowledged writes** to these streams on that node. An abrupt stop is a killed process, a power cut, or a host that crashes or freezes.
- **A replica on another node covers the loss of one node.** The copy on the node that keeps running still has the writes, so they are lost only if every copy stops abruptly within the same 5 seconds. A single-node deployment has no second copy, so it is the most exposed.
- **A stop that is cut short is an abrupt stop.** The packages let the service take as long as it needs to stop. Container platforms kill the process when their stop timeout expires, 10 seconds by default in Docker and 30 seconds in Kubernetes. On a node with many indices, raise it (`stop_grace_period` in Docker Compose, `terminationGracePeriodSeconds` in Kubernetes).

A lost write is not sent again, because its sender received the acknowledgement. Besides the missing events and findings, an abrupt stop has two more effects:

- **Detection skips new events.** After the node starts again, the detection rules skip as many new events of each affected stream as the stream lost. Findings created from the lost events can remain, pointing to events that no longer exist.
- **Active responses can be missed.** A lost active response request that the Wazuh Manager had not retrieved yet is never executed.

#### Changing the durability

`index.translog.durability` is a dynamic index setting. To make these streams sync every write before acknowledging it again:

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X PUT "https://127.0.0.1:9200/wazuh-events-v5-*,wazuh-events-raw-v5,wazuh-findings-v5-*,wazuh-active-responses/_settings" \
  -H 'Content-Type: application/json' \
  -d '{"index.translog.durability": "request"}'
```

The request changes the backing indices that exist. A backing index created by a later rollover takes the value of its index template again, so the change does not outlive the rollover. Editing the index template does not keep it either, because the plugin overwrites its templates at every restart.

To check the value of each backing index:

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X GET "https://127.0.0.1:9200/wazuh-events-v5-*,wazuh-events-raw-v5,wazuh-findings-v5-*,wazuh-active-responses/_settings/index.translog.durability?flat_settings=true&pretty"
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
