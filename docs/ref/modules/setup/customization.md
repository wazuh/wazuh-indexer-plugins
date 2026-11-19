# Customization

The Setup plugin creates the index templates, the indices and the Index State Management (ISM) policies of Wazuh from definitions bundled in the plugin. Their defaults suit a single-node deployment. The configuration file `setup.yml` changes the index settings and the retention policies without duplicating templates or policies, so a deployment with several nodes can start already configured.

Two things can be customized:

- **Index template settings**: shards, replicas, refresh interval, codec and translog durability of the indices the plugin creates.
- **ISM policies**: each default policy can be replaced by an editable policy file.

## The configuration directory

The plugin installs its configuration directory next to `opensearch.yml`:

| Installation | Directory |
| --- | --- |
| DEB and RPM packages | `/etc/wazuh-indexer/wazuh-indexer-setup/` |
| Tarball | `<installation directory>/config/wazuh-indexer-setup/` |
| Docker image | `/usr/share/wazuh-indexer/config/wazuh-indexer-setup/` |

The directory holds these files:

- **`setup.yml`** — the overrides of the index template settings and one switch per ISM policy. It lists every key, commented out, with its default and its valid values, after a few examples.
- **`<policy-id>.json`** — an editable copy of each default ISM policy. The plugin uses it instead of the default policy while its switch is on.
- **`README.md`** — a summary of this page.

As installed, `setup.yml` changes nothing: the plugin behaves as if the file did not exist until a key is uncommented. The same applies if the file is deleted.

### Using the file

The file is its own reference: there is no key to write by hand. To change a setting:

1. Find its key in the file, or pick one of the examples at the top of the file.
2. Remove the `#` in front of the key and set its value. The valid values are on the same line, after the default.
3. Restart the Wazuh indexer, as described in [When changes take effect](#when-changes-take-effect).

Each template has a block like this one:

```yaml
# events: indices wazuh-events-v5*
#templates.streams.events.settings.index.number_of_shards: 1          # 1 to 1024
#templates.streams.events.settings.index.number_of_replicas: 0        # 0 or more, used only when auto_expand_replicas is false
#templates.streams.events.settings.index.auto_expand_replicas: "0-1"  # "<min>-<max>", "<min>-all" or false
#templates.streams.events.settings.index.refresh_interval: 2s         # a time value such as 5s or 1m, or -1
#templates.streams.events.settings.index.codec: zstd                  # default, best_compression, zstd or zstd_no_dict
#templates.streams.events.settings.index.translog.durability: async   # request or async
```

A key can be set only once. The examples repeat keys of the lists, so uncomment a key in one place: if it is uncommented twice, the initialization fails and the error names the key.

In the packages the files belong to `root:wazuh-indexer` with mode `640`, in a directory with mode `750`.

### Package upgrades

A package upgrade replaces a `setup.yml` or a policy file that was not edited, and keeps one that was. When a new version of the package also changes a file that was edited, for example because a default changed:

- **RPM** keeps the edited file and saves the new one beside it as `<file>.rpmnew`.
- **DEB** asks which one to keep. In an unattended upgrade, pass `--force-confdef --force-confold` to `dpkg` to keep the edited file: the new one is saved beside it as `<file>.dpkg-dist`. Without a terminal and without those options, `dpkg` stops at that file with an error.

Compare the saved file with yours to see what changed. The plugin only reads `setup.yml` and the `<policy-id>.json` files, so the saved copies have no effect.

The upgrade restarts the indexer when it was running, so the plugin reads the files again.

## Index template settings

A key has this format:

```
templates.<group>.<name>.settings.<setting>
```

- `<group>` is `streams`, `states` or `content`.
- `<name>` is the name of a template of that group, as listed in [Default values](#default-values).
- `<setting>` is one of the [supported settings](#supported-settings).

For example, this gives three primary shards to every events data stream and makes one stateful index refresh every 30 seconds:

```yaml
templates.streams.events.settings.index.number_of_shards: 3
templates.states.inventory-services.settings.index.refresh_interval: 30s
```

One template can serve several indices. The `events` template serves every `wazuh-events-v5-<category>` data stream and the `findings` template every `wazuh-findings-v5-<category>` data stream, so their keys apply to all the categories. A setting cannot be changed for a single category.

### Groups and precedence

`<name>` can be `*` to cover every template of a group, and `templates.*.*` covers every template:

```yaml
# Every template
templates.*.*.settings.index.auto_expand_replicas: "0-2"
# Every stream template
templates.streams.*.settings.index.refresh_interval: 10s
# One template
templates.streams.events.settings.index.refresh_interval: 5s
```

When several keys set the same setting for a template, the most specific one wins: the key with the template name, then the key of its group, then the key for every template. In the example, the events streams refresh every 5 seconds and the other streams every 10 seconds.

A template name always needs its group: `templates.*.events` is not a valid key.

The keys can also be written as nested YAML. In that form, quote the `*`:

```yaml
templates:
  streams:
    "*":
      settings:
        index:
          refresh_interval: 10s
```

### Supported settings

- **`index.number_of_shards`** (Integer, range 1–1024) — number of primary shards of each index. It cannot be changed on an index that exists.
- **`index.number_of_replicas`** (Integer, 0 or more) — number of copies of each primary shard. It has no effect unless `index.auto_expand_replicas` is `false`.
- **`index.auto_expand_replicas`** (`"<min>-<max>"`, `"<min>-all"` or `false`) — range the number of replicas follows as data nodes join and leave. `false` uses `index.number_of_replicas`.
- **`index.refresh_interval`** (Time value such as `5s` or `1m`, or `-1`) — how often new documents become searchable. `-1` disables the periodic refresh.
- **`index.codec`** (`default`, `best_compression`, `zstd` or `zstd_no_dict`) — compression of the stored data. It can only be changed on an index while the index is closed.
- **`index.translog.durability`** (`request` or `async`) — whether every write is synced to disk before it is acknowledged. See [Write durability of the stream indices](architecture.md#write-durability-of-the-stream-indices) for what `async` trades.

Write the values of `index.codec` and `index.translog.durability` exactly as listed, in lower case. Another spelling, such as `ZSTD`, is rejected as an invalid value.

Any other setting is rejected as an unknown key.

Every default template sets `index.auto_expand_replicas: 0-1`, which takes precedence over the replica count: the index has no replica on a single node and one replica as soon as a second node joins. To use a fixed number of replicas, set `index.auto_expand_replicas: false` together with `index.number_of_replicas`. If only the replica count is overridden, the plugin logs a warning that names the template, because the override has no effect.

### Content indices

The Content Manager rebuilds a content index when the source of its content changes. The rebuilt index takes `index.number_of_replicas`, `index.auto_expand_replicas` and `index.codec` from the Content Manager, not from `setup.yml`. The other three settings are kept.

### Default values

These are the defaults of the bundled templates. The `setup.yml` installed with the plugin lists the same values, one commented key per template and setting, and is always in step with the installed version.

#### `streams`

| Template | Indices | Shards | Replicas | Auto-expand | Refresh interval | Codec | Translog durability |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `active-responses` | `wazuh-active-responses` | `1` | `0` | `0-1` | `5s` | `zstd` | `request` |
| `ai-assistant-sessions` | `wazuh-ai-assistant-sessions` | `1` | `0` | `0-1` | `1s` | `zstd` | `request` |
| `events` | `wazuh-events-v5-<category>` | `1` | `0` | `0-1` | `2s` | `zstd` | `async` |
| `findings` | `wazuh-findings-v5-<category>` | `1` | `0` | `0-1` | `2s` | `zstd` | `async` |
| `metrics-agents` | `wazuh-metrics-agents` | `1` | `0` | `0-1` | `5s` | `zstd` | `request` |
| `metrics-comms` | `wazuh-metrics-comms-v4` | `1` | `0` | `0-1` | `5s` | `zstd` | `request` |
| `metrics-normalization` | `wazuh-metrics-normalization` | `1` | `0` | `0-1` | `5s` | `zstd` | `request` |
| `raw` | `wazuh-events-raw-v5` | `1` | `0` | `0-1` | `5s` | `zstd` | `async` |

#### `states`

| Template | Indices | Shards | Replicas | Auto-expand | Refresh interval | Codec | Translog durability |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `agent-config` | `wazuh-agent-config` | `1` | `0` | `0-1` | `5s` | `default` | `request` |
| `agent-stats` | `wazuh-agent-stats` | `1` | `0` | `0-1` | `5s` | `default` | `request` |
| `fim-files` | `wazuh-states-fim-files` | `1` | `0` | `0-1` | `2s` | `zstd` | `request` |
| `fim-registry-keys` | `wazuh-states-fim-registry-keys` | `1` | `0` | `0-1` | `2s` | `zstd` | `request` |
| `fim-registry-values` | `wazuh-states-fim-registry-values` | `1` | `0` | `0-1` | `2s` | `zstd` | `request` |
| `inventory-browser-extensions` | `wazuh-states-inventory-browser-extensions` | `1` | `0` | `0-1` | `2s` | `zstd` | `request` |
| `inventory-groups` | `wazuh-states-inventory-groups` | `1` | `0` | `0-1` | `2s` | `zstd` | `request` |
| `inventory-hardware` | `wazuh-states-inventory-hardware` | `1` | `0` | `0-1` | `2s` | `zstd` | `request` |
| `inventory-hotfixes` | `wazuh-states-inventory-hotfixes` | `1` | `0` | `0-1` | `2s` | `zstd` | `request` |
| `inventory-interfaces` | `wazuh-states-inventory-interfaces` | `1` | `0` | `0-1` | `2s` | `zstd` | `request` |
| `inventory-networks` | `wazuh-states-inventory-networks` | `1` | `0` | `0-1` | `2s` | `zstd` | `request` |
| `inventory-packages` | `wazuh-states-inventory-packages` | `1` | `0` | `0-1` | `2s` | `zstd` | `request` |
| `inventory-ports` | `wazuh-states-inventory-ports` | `1` | `0` | `0-1` | `2s` | `zstd` | `request` |
| `inventory-processes` | `wazuh-states-inventory-processes` | `1` | `0` | `0-1` | `2s` | `zstd` | `request` |
| `inventory-protocols` | `wazuh-states-inventory-protocols` | `1` | `0` | `0-1` | `2s` | `zstd` | `request` |
| `inventory-services` | `wazuh-states-inventory-services` | `1` | `0` | `0-1` | `2s` | `zstd` | `request` |
| `inventory-system` | `wazuh-states-inventory-system` | `1` | `0` | `0-1` | `2s` | `zstd` | `request` |
| `inventory-users` | `wazuh-states-inventory-users` | `1` | `0` | `0-1` | `2s` | `zstd` | `request` |
| `sca` | `wazuh-states-sca` | `1` | `0` | `0-1` | `5s` | `zstd` | `request` |
| `vulnerabilities` | `wazuh-states-vulnerabilities` | `1` | `0` | `0-1` | `2s` | `zstd` | `request` |

#### `content`

| Template | Indices | Shards | Replicas | Auto-expand | Refresh interval | Codec | Translog durability |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `decoders` | `wazuh-threatintel-decoders` | `1` | `0` | `0-1` | `1s` | `zstd` | `request` |
| `filters` | `wazuh-threatintel-filters` | `1` | `0` | `0-1` | `5s` | `zstd` | `request` |
| `integrations` | `wazuh-threatintel-integrations` | `1` | `0` | `0-1` | `1s` | `zstd` | `request` |
| `ioc` | `wazuh-threatintel-enrichments` | `1` | `0` | `0-1` | `2s` | `zstd` | `request` |
| `kvdbs` | `wazuh-threatintel-kvdbs` | `1` | `0` | `0-1` | `1s` | `zstd` | `request` |
| `policies` | `wazuh-threatintel-policies` | `1` | `0` | `0-1` | `1s` | `zstd` | `request` |
| `rules` | `wazuh-threatintel-rules` | `1` | `0` | `0-1` | `1s` | `zstd` | `request` |
| `vulnerabilities` | `.wazuh-threatintel-vulnerabilities` | `1` | `0` | `0-1` | `1s` | `zstd` | `request` |

## ISM policies

Each default policy has a switch:

```
policies.<policy-id>.custom
```

- `false`, the default: the plugin stores its default policy.
- `true`: the plugin stores the policy of the file `<policy-id>.json` of the configuration directory instead, under the same policy id.

There is only one policy per id in the cluster, so nothing else changes: the indices and data streams are managed by the same policy id either way. Every index created after the switch is turned on, including the backing indices that a rollover creates, runs the policy of the file.

To change a policy:

1. Edit `<policy-id>.json`. Change the states, actions and conditions as needed, and set `last_updated_time` to the current time in milliseconds (`date +%s%3N`), which is how you tell later which version an index runs.
2. Set `policies.<policy-id>.custom: true` in `setup.yml`.
3. Restart as described in [When changes take effect](#when-changes-take-effect).

[Retention](retention.md#changing-a-policy) has a worked example, and explains how to move the indices that already exist onto the new policy.

Keep these fields of a policy file as they are:

- `policy_id` must be the id of the default policy, which is also the name of the file. Otherwise the initialization fails.
- `last_updated_time` must be present, and never in the future: ISM applies a policy only to the indices created after that time. A time in the future, here or in an `ism_template` entry, fails the initialization.
- The file holds only the `policy` object, and the object only the fields a policy has: `policy_id`, `description`, `last_updated_time`, `schema_version`, `error_notification`, `default_state`, `states`, `ism_template` and `user`. Any other field fails the initialization, for example the `_id` and `_seq_no` of a policy copied from the ISM API.
- `ism_template` holds the index patterns ISM uses to attach the policy to the backing indices that a rollover creates. With other patterns those indices are left without a policy, and nothing deletes them.

A policy read from its file no longer receives the changes that a new version makes to the default policy. The plugin logs a warning for each one at every initialization.

Setting the switch back to `false` restores the default policy under the same id at the next initialization.

The policy stored in the cluster is written again from the default or from the file at every initialization. An edit made through the ISM API or the dashboard is lost at the next restart: edit the policy file instead.

The plugin reads the configuration directory each time it initializes the cluster, which happens when a node that has just started is elected cluster manager. Nothing from a previous read is kept: the files are the only source.

- **Single node:** a restart of the indexer applies the change.
- **Several nodes:** copy the same `setup.yml` and policy files to every cluster-manager-eligible node, then restart those nodes one at a time, the elected cluster manager last. The node elected after that restart reads its own copy of the files, so a node with different files would apply different settings.

What a change reaches:

| Change | Index templates | Indices that exist | Indices created later |
| --- | --- | --- | --- |
| A key is added or changed | Updated at the next initialization | Unchanged | Take the new value |
| A key is commented out again | Back to the default | Unchanged | Take the default |
| A switch is set to `true` | Unchanged | Keep the policy version they run | Run the policy of the file |
| A policy file is edited | Unchanged | Keep the policy version they run | Run the edited policy |
| A switch is set back to `false` | Unchanged | Keep the policy version they run | Run the default policy |

A data stream takes the new template settings at its next rollover, which creates its next backing index.

At each initialization the plugin logs the file it read and its SHA-256, one line per override, and one line per replaced policy with the SHA-256 of its file:

```
[INFO ][c.w.s.SetupPlugin] [node-1] Setup configuration file [/etc/wazuh-indexer/wazuh-indexer-setup/setup.yml], sha256 [2451…e2cc]: 2 index template setting override(s), 1 replaced ISM policy(ies).
[INFO ][c.w.s.SetupPlugin] [node-1] Index template setting override: [templates.streams.events.settings.index.number_of_shards] = [3]
[INFO ][c.w.s.SetupPlugin] [node-1] Index template setting override: [templates.streams.events.settings.index.auto_expand_replicas] = [0-2]
[INFO ][c.w.s.SetupPlugin] [node-1] ISM policy [stream-events-policy] is replaced by the policy in [/etc/wazuh-indexer/wazuh-indexer-setup/stream-events-policy.json], sha256 [7d1e…a90c].
[WARN ][c.w.s.SetupPlugin] [node-1] ISM policy [stream-events-policy] no longer follows the default policy: changes a new version makes to the default one do not reach [/etc/wazuh-indexer/wazuh-indexer-setup/stream-events-policy.json].
```

Compare the SHA-256 values across the nodes to check that they hold the same files.

If an index exists and does not have the value of an override, the plugin also logs a warning that names the index and the setting, as a reminder that the override only reaches new indices:

```
[WARN ][c.w.s.i.Index] [node-1] Index [.ds-wazuh-events-v5-security-000001] exists with [index.number_of_shards] = [1]. The override [3] applies only to indices created from now on.
```

## Applying a change to the indices that exist

- **Replicas, refresh interval and translog durability** can be changed on an index that exists with the settings API. Use the same value as in `setup.yml`, so that the indices created later match:

  ```bash
  curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X PUT "https://127.0.0.1:9200/wazuh-events-v5-*/_settings" \
    -H 'Content-Type: application/json' \
    -d '{"index.auto_expand_replicas": "0-2"}'
  ```

- **Shards and codec of a data stream** apply from its next backing index. To get it now, roll the stream over. The previous backing indices keep their settings until their policy deletes them:

  ```bash
  curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X POST "https://127.0.0.1:9200/wazuh-events-v5-security/_rollover"
  ```

- **Shards and codec of a stateful index** need a new index: [reindex](https://docs.opensearch.org/3.6/api-reference/document-apis/reindex/) the existing one into an index created after the change.
- **A policy** reaches the indices that exist through `change_policy`, as described in [Retention](retention.md#changing-a-policy).

## Invalid configuration

The plugin checks the whole configuration before it creates anything. The initialization stops if:

- `setup.yml` is not valid YAML,
- a key is unknown: a group, a template name, a setting or a policy id that does not exist,
- a value has the wrong type or is out of range,
- the policy file of a switch set to `true` is missing, is not valid JSON, does not keep the id of the default policy, holds a field a policy does not have, or has no `last_updated_time` or one in the future.

No index template, index, data stream or policy is created or updated, the [setup status](architecture.md#readiness-marker) is `failed`, and the error in the indexer log names the key or the file:

```
[ERROR][c.w.s.SetupPlugin] [node-1] Setup initialization failed: [templates.streams.events.settings.index.number_of_shards] in [/etc/wazuh-indexer/wazuh-indexer-setup/setup.yml]: invalid value: Failed to parse value [three] for setting [index.number_of_shards]
```

The indexer itself keeps running. The Content Manager waits for the setup status and does not start its work while it is `failed`. Fix the file and restart the node.

To read the status:

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD "https://127.0.0.1:9200/.wazuh-setup-status/_doc/setup-status?filter_path=_source"
```

## Examples

### Three-node cluster

With three data nodes, this `setup.yml` spreads each events data stream over the three nodes and keeps two replicas of every shard:

```yaml
templates.streams.events.settings.index.number_of_shards: 3
templates.streams.events.settings.index.auto_expand_replicas: "0-2"
```

Copy it to the three nodes before their first start. Each backing index of `wazuh-events-v5-<category>` then has three primary shards and, once the three nodes have joined, two replicas of each. Every node holds a copy of every shard, so losing a node loses no events.

- Applied before the first start, nothing else is needed.
- Applied to a running cluster, restart the nodes as described in [When changes take effect](#when-changes-take-effect). Then change the replicas of the existing backing indices with the settings API and roll the streams over to get the three shards, as shown in [Applying a change to the indices that exist](#applying-a-change-to-the-indices-that-exist).
- The default policies roll an index over at 20 GB per primary shard, so a backing index with three shards rolls over at about 60 GB. See [Disk sizing](retention.md#disk-sizing).
- More shards cost memory on every node. The eight events categories with three shards and two replicas are 72 shards for each generation of backing indices.

To check the result:

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD "https://127.0.0.1:9200/_cat/shards/wazuh-events-v5-*?v&h=index,shard,prirep,state,node"
```

### Docker

Mount the files over the ones of the image. A file that is not mounted keeps the content the image ships:

```yaml
services:
  wazuh.indexer:
    volumes:
      - ./config/wazuh_indexer/setup.yml:/usr/share/wazuh-indexer/config/wazuh-indexer-setup/setup.yml
      - ./config/wazuh_indexer/stream-events-policy.json:/usr/share/wazuh-indexer/config/wazuh-indexer-setup/stream-events-policy.json
```

The files must be readable by the user the indexer runs as in the container.

### Kubernetes

Keep the files in a ConfigMap and mount each one with `subPath`, so the rest of the directory stays as the image ships it:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: wazuh-indexer-setup
data:
  setup.yml: |
    templates.streams.events.settings.index.number_of_shards: 3
    templates.streams.events.settings.index.auto_expand_replicas: "0-2"
```

In the indexer StatefulSet:

```yaml
volumes:
  - name: setup-config
    configMap:
      name: wazuh-indexer-setup
containers:
  - name: wazuh-indexer
    volumeMounts:
      - name: setup-config
        mountPath: /usr/share/wazuh-indexer/config/wazuh-indexer-setup/setup.yml
        subPath: setup.yml
```

A change to the ConfigMap needs a restart of the indexer pods, as any other change to the file.

## Related

- [Configuration](configuration.md): the settings of the plugin in `opensearch.yml`.
- [Retention](retention.md): what the default policies do, and how to change one.
- [Architecture](architecture.md): how the plugin initializes the cluster.
