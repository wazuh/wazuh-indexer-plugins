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

## Wazuh Common Schema

Refer to the [docs](https://github.com/wazuh/wazuh-indexer-plugins/tree/main/wcs) for complete definitions of the indices. The indices inherit the settings and mappings defined in the index templates.

### Event stream templates

All event categories share a single base template. One index template per category is generated dynamically at deployment time from this shared base. Specialized streams (raw, unclassified, active-responses) use their own dedicated template files.

The WCS field definitions are organized under `wcs/stateless/events/`:

```
wcs/stateless/events/
├── main/          # Shared fields for all event categories
├── raw/           # Fields for raw (unprocessed) events
└── unclassified/  # Fields for uncategorized events
```

For the underlying class structure and implementation details, see the [development guide](../../../dev/plugins/setup.md).
