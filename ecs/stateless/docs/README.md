## `wazuh-alerts-5.x` time series index

The `wazuh-alerts-*` indices store events received from monitored endpoints that trigger alerts when they match a detection rule.

This is a time-based (stateless) index. The `wazuh-archives-5.x` index uses the same mappings and settings. The template is generated programatically off the `wazuh-alerts-5.x` index.

### Fields summary

For this stage, we are using all the fields of the ECS. Dynamic mode is temporarily set to `false` to avoid the creation of new fields while allowing the indexing of events containing fields not in the schema. These fields can be retrieved from the original event (`_source`).

- [ECS main mappings](https://github.com/elastic/ecs/blob/v8.11.0/schemas/subsets/main.yml)

The detail of the fields can be found in csv file [Stateless Fields](fields.csv).