## `wazuh-agent-config` index data model

### Fields summary

The fields are based on:

- [Collect and index agent configuration](https://github.com/wazuh/wazuh/issues/37702).

This index stores the most recent configuration reported by each agent through the
`/config` endpoint. Every time an agent sends its configuration, the existing document
is overwritten, so no configuration history is kept.

The agent configuration is stored under `wazuh.agent.configuration`:

- `wazuh.agent.configuration.modules` lists the modules present in the reported
  configuration.
- `wazuh.agent.configuration.content.<module>.*` holds the settings of each Wazuh
  agent module (`agent`, `fim`, `logcollector`, `syscollector`, `sca`, cloud
  integrations, etc.).

Unlike other state indices, the mappings use `"dynamic": "true"` instead of `strict`.
Known configuration fields are mapped explicitly, while any field not present in the
mapping is added to the mapping dynamically as it is reported. This lets new agent
settings be indexed without an index-template change and without rejecting the document.

The detail of the fields can be found in csv file [Agent config Fields](fields.csv).
