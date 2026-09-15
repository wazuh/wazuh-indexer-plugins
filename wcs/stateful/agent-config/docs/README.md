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

The mappings use `"dynamic": "strict_allow_templates"`. Known configuration options are
mapped explicitly, and an option that is not in the mapping is only accepted when it
matches one of the `dynamic_templates`, which cover `wazuh.agent.configuration.content.*`
and assign the type from the reported value (object, boolean, long, double, or `keyword`
for everything else). This lets a new agent setting be indexed without an index-template
change, while anything reported outside `wazuh.agent.configuration.content` is rejected
instead of silently added to the mapping shared by the whole fleet.

The detail of the fields can be found in csv file [Agent config Fields](fields.csv).
