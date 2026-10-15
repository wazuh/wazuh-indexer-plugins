# Offline content updates

Air-gapped deployments cannot reach Wazuh CTI, so they cannot download content changes as they are published. Instead, they are updated with full snapshots of the content: you download the latest snapshots on a machine with internet access, copy them to the Wazuh Indexer nodes, and request an offline update.

Incremental changes cannot be applied offline. Each offline update replaces the content of a consumer with the snapshot you provide, so the content is as recent as the snapshot. Wazuh CTI decides when new snapshots are published.

The Wazuh Indexer packages include a snapshot of each consumer, so a new installation already has content. Use this procedure to update it later.

## Before you start

Disable every task that needs an internet connection, as described in [Offline configuration](configuration.md#offline-configuration--disabling-automatic-updates).

On-demand updates must be enabled. They are by default; check that `plugins.content_manager.catalog.update_on_demand` is not set to `false`.

## 1. Download the snapshots

The snapshots directory of each node holds a `manifest.json` file. Its `resource` field gives the Wazuh CTI address of each consumer:

```bash
cat /usr/share/wazuh-indexer/plugins/wazuh-indexer-content-manager/snapshots/manifest.json
```

On a machine with internet access, ask Wazuh CTI for the link to the latest snapshot of each consumer, and download it under the name the Content Manager expects:

| Consumer | `manifest.json` key | File name |
|---|---|---|
| Ruleset | `ruleset.zip` | `ruleset.zip` |
| IoCs | `iocs.zip` | `iocs.zip` |
| Vulnerabilities | `vulnerabilities.zip` | `vulnerabilities.zip` |

For example, for the vulnerabilities feed:

```bash
RESOURCE="<resource of vulnerabilities.zip in manifest.json>"
LINK=$(curl -s "$RESOURCE" | jq -r '.data.last_snapshot_link')
curl -s -o vulnerabilities.zip "$LINK"
```

The response of the first request also gives `last_snapshot_offset` and `last_snapshot_at`, the offset and date of that snapshot. Keep the offset to check the result in step 4.

You only need to download the consumers you want to update.

## 2. Copy the snapshots to every node

Copy the files to the snapshots directory of **every** Wazuh Indexer node, and give them to the `wazuh-indexer` user:

```bash
D=/usr/share/wazuh-indexer/plugins/wazuh-indexer-content-manager/snapshots
cp vulnerabilities.zip "$D/"
chown wazuh-indexer:wazuh-indexer "$D/vulnerabilities.zip"
chmod 640 "$D/vulnerabilities.zip"
```

The update runs on the node that receives the request in step 3, so that node must have the files. Copy them to the other nodes as well: each node keeps the last snapshot it loaded as a fallback, and a node that never received the new files would fall back to older content.

Do not change `manifest.json` or the `*.stable.zip` files in the same directory.

## 3. Request an offline update

Send the request to any node that has the new files:

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X POST \
  "https://127.0.0.1:9200/_plugins/_content_manager/update?offline=true"
```

```json
{
  "message": "The update request has been accepted for processing.",
  "status": 202
}
```

The update runs in the background. Every consumer with a snapshot file on that node is rebuilt from it, whatever content it had before. Consumers without a file are left as they are. Wazuh CTI is not contacted.

If the node has no snapshot file to load, the request is rejected and nothing changes:

```json
{
  "message": "No snapshot file to load in [plugins/wazuh-indexer-content-manager/snapshots] on node [node-1]. Place the new snapshot files in that directory, on every node, before requesting an offline update.",
  "status": 400
}
```

If another update is running, the request is answered with `409`. Wait for it to end and send the request again.

## 4. Check the result

Each consumer reports `running` while it loads and `ready` once it is done:

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD \
  "https://127.0.0.1:9200/.wazuh-cti-consumers/_search?filter_path=hits.hits._source.type,hits.hits._source.status,hits.hits._source.local_offset"
```

Once a consumer is `ready`, its `local_offset` is the offset of the snapshot you loaded, the `last_snapshot_offset` from step 1.

Its `remote_offset` shows the same value: offline, the snapshot is the latest content the deployment knows of.

The node log shows two lines per consumer rebuilt:

```
Offline update: rebuilding consumer [cti:catalog:consumer:vulnerabilities] from local snapshot [vulnerabilities.zip] (local offset 1077533).
Offline update: consumer [cti:catalog:consumer:vulnerabilities] rebuilt from its local snapshot, now at offset 1077535.
```

If a file cannot be loaded, for example because it is damaged, the log shows `could not be rebuilt from local snapshot [...]; its current content was kept.` and the consumer keeps its previous content.

After the update, each node renames the file to `<name>.stable.zip` (for example `vulnerabilities.stable.zip`), replacing the previous one. That file is the fallback the node reloads from if the content ever needs to be rebuilt. The directory then holds no file waiting to be loaded until you copy new ones.

## Considerations

- **Duration.** Loading the vulnerabilities feed takes a few minutes, the IoCs about a minute and the ruleset under a minute, depending on the hardware.
- **Content during the update.** The snapshot loads into hidden staging indices and the content switches to it in one step once it has loaded, the same [blue/green swap](architecture.md#plan-change-handling-bluegreen-swap) used for plan changes. The previous content stays available until then.
- **Disk space.** While a consumer is rebuilt, its previous and new content are both stored. Make sure the nodes have room for a second copy of the largest feed you update.
- **User content.** Decoders, rules, integrations and other resources in the draft, test and custom spaces are carried over to the rebuilt ruleset. Only the standard content changes, and Ruleset Management integrations and rules that are no longer in it are removed.
- **Older snapshots.** The update loads whatever snapshot you provide, so you can also return to an earlier one.
