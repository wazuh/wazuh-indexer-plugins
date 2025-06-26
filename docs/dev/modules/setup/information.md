# Setup plugin development

## Create new index

1. Create an index template for the `/plugins/setup/src/main/resources`, following the same pattern given by the other templates:

    ```json
    {
      "index_patterns": ["<pattern>"],
      "mappings": {
        "date_detection": false,
        "dynamic": "strict",
        "properties": {
          <custom mappings and fields>
        }
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

1. Add an entry with the name of the template and the index in the `/plugins/setup/src/main/java/com/wazuh/setup/index/WazuhIndices.java` constructor, following the same pattern as the others:

    ```java
    /**
     * Constructor
     *
     * @param client Client
     * @param clusterService object containing the cluster service
     */
    public WazuhIndices(Client client, ClusterService clusterService) {

      // ...

      // Create Index Templates - Indices map
      this.indexTemplates.put(
          "<index-template-...>",
          List.of("<index>")
      );

      //...
    }
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
        "description": "<policy-description>",
        "last_updated_time": <Unix-epoch-milisecond-timestamp>,
        "schema_version": 21,
        "error_notification": null,
        "default_state": "rollover",
        "states": [
          {
            "name": "rollover",
            "actions": [
              {
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
              "wazuh-<pattern1>-*" [, "wazuh-<pattern2>-*"]
            ],
            "priority": <priority-int>,
            "last_updated_time": <Unix-epoch-milisecond-timestamp>
          }
        ]
      }
    }
    ```

1. Add the new policy to the setup plugin code at `plugins/setup/src/main/java/com/wazuh/setup/index/IndexStateManagement.java`:

    ```java
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
