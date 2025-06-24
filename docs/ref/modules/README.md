# Modules

In the next section you will find the information concerning the wazuh indexer plugins and how to manipulate them in your wazuh instance.

After installing wazuh indexer, you can verify the installed plugins using the API:
```console
curl -XGET https://<your-ip>:9200/_cat/plugins?v -u <user>:<password> --insecure
```

> After manually installing/uninstalling any plugin you might need to restart the indexer in order to percieve the changes on the API.

## Plugins
- [Setup plugin](/ref/modules/setup/README.md)
