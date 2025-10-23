## `wazuh-events-v5-access-management` time series index

The `wazuh-events-v5-access-management` indices store events received from monitored endpoints through the relevant integrations.

This is a time-based (stateless) index. The index includes the WCS fields and the fields of the corresponding access-management integrations.

### Fields summary

For this stage, we are using all the fields of the WCS. Dynamic mode is temporarily set to `false` to avoid the creation of new fields while allowing the indexing of events containing fields not in the schema. These fields can be retrieved from the original event (`_source`).

- [WCS main mappings](../../stateless/docs/fields.csv)

The detail of the fields can be found in csv file [Stateless Access Management Fields](fields.csv).

### Integrations:

The **access-management** log category provides specialized fields for processing events in the Wazuh security platform coming from these integrations:
- 