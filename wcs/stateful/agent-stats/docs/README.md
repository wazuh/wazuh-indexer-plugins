## `wazuh-agent-stats` index data model

### Fields summary

The fields are based on:

- [Collect and index agent statistics](https://github.com/wazuh/wazuh/issues/38024).

This index stores the most recent statistics reported by each agent through the `/stats` endpoint. The document id is the agent id, so every push replaces the previous report and no history is kept. This is why the index is a regular index and not a data stream: a data stream forbids the stable document id the replacement relies on.

The mappings use `"dynamic": "strict_allow_templates"`. Known counters are mapped
explicitly, and a counter that is not in the mapping is only accepted when it matches one
of the `dynamic_templates`, which cover `wazuh.agent.statistics.*` and assign the type
from the reported value (object, boolean, long, double, or `keyword` for everything
else). This lets a new agent counter be indexed without an index-template change, while
anything reported outside `wazuh.agent.statistics` is rejected instead of silently added
to the mapping shared by the whole fleet.

The detail of the fields can be found in csv file [Agent stats Fields](fields.csv).
