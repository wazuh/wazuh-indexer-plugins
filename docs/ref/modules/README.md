# Modules

The following section provides information about the Wazuh indexer plugins and instructions on how to manage them within a Wazuh instance.

After installing wazuh indexer, all installed plugins can be verified using `/usr/share/wazuh-indexer/bin/opensearch-plugin list`.

Or using the next API call:
```console
curl -XGET https://<your-ip>:9200/_cat/plugins?v -u <user>:<password> --insecure
```

> After manually installing/uninstalling any plugin a restart on the indexer might be needed in order to percieve the changes on the API.

## Plugins
- [Setup plugin](setup/README.md)
