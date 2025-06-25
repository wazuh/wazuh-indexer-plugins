# Setup plugin development

## Create new index

1. Create an index template for the `/plugins/setup/src/main/resources`, following the same pattern given by the other templates:

```json
{
  "index_patterns": ["<pattern>"],
  "mappings": {
    "date_detection": ...,
    "dynamic": ...,
    "properties": {
  },
  "order": 1,
  "settings": {
    "index": {
      "number_of_shards": 1,
      "number_of_replicas": 1
    }
  }
}
```

1. Add an entry with the name of the template and the index in the `/plugins/setup/src/main/java/com/wazuh/setup/index` folder, following the same pattern as the others:

```console
this.indexTemplates.put(
    "<index-template-...>",
    List.of("<index>")
);
```

> To verify the content has been created correctly you can build the plugin, deploy wazuh indexer with it and access to the existing templates and indices via the API using `GET _index_template/` and `GET <indexer-IP>:9200/_cat/indices` (with `curl` or the developper tool from dashboard).

## Create new ISM policy

1. Edit the index template and add the following line inside the settings block:
  ```json
  "plugins.index_state_management.rollover_alias": "<index-name>"
  ```

1. Create ISM policy, more information at [OpenSearch Policies](https://docs.opensearch.org/docs/latest/im-plugin/ism/policies/):

    ```json
    {
      "policy": {
        "policy_id": "<index-name>-rollover-policy",
        "description": ...,
        "last_updated_time": ...,
        "schema_version": 21,
        "error_notification": null,
        "default_state": "rollover",
        "states": [
          {
            "name": "rollover",
            "actions": [
              {
                "retry": {
                  "count": 3,
                  "backoff": "exponential",
                  "delay": "1m"
                },
                "rollover": {
                  "min_doc_count": 200000000,
                  "min_index_age": "7d",
                  "min_primary_shard_size": "25gb"
                }
              }
            ],
            "transitions": []
          }
        ],
        "ism_template": [
          {
            "index_patterns": [
              "wazuh-<pattern1>-*", "wazuh-<pattern2>-*"
            ],
            "priority": ...,
            "last_updated_time": ...
          }
        ],
        "user": {
          "name": "admin",
          "backend_roles": [
            "admin"
          ],
          "roles": [
            "own_index",
            "all_access"
          ],
          "custom_attribute_names": [],
          "user_requested_tenant": null
        }
      }
    }
    ```

1. Add the policy on code at `plugins/setup/src/main/java/com/wazuh/setup/index/IndexStateManagement.java`:

    ```console
    // ISM policies names (filename without extension)
    static final String <index>_ROLLOVER_POLICY = "<index-name>-rollover-policy";

    ...

     /**
     * Constructor.
     *
     * @param index index name.
     * @param template index template name.
     */
    public IndexStateManagement(String index, String template) {
        super(index, template);
        this.policies = new ArrayList<>();

        // Add ISM policies to be created
        this.policies.add(<index>_ROLLOVER_POLICY);
    }
    ```
