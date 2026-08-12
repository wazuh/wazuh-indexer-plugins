## `wazuh-agent-stats` index data model

### Fields summary

The fields are based on:

- [Collect and index agent statistics](https://github.com/wazuh/wazuh/issues/38024).

This index stores the most recent statistics reported by each agent through the `/stats` endpoint. The document id is the agent id, so every push replaces the previous report and no history is kept. This is why the index is a regular index and not a data stream: a data stream forbids the stable document id the replacement relies on.

Unlike other state indices, the mappings use `"dynamic": "true"` instead of `strict`.
Known configuration fields are mapped explicitly, while any field not present in the
mapping is added to the mapping dynamically as it is reported. This lets new agent
settings be indexed without an index-template change and without rejecting the document.

The detail of the fields can be found in csv file [Agent stats Fields](fields.csv).
