## `wazuh-events-v5-cloud-services-main` time series index

The `wazuh-events-v5-cloud-services-main` indices store events received from monitored endpoints through the relevant integrations.

This is a time-based (stateless) index. The index includes the WCS fields and the fields of the corresponding cloud-services-main integrations.

### Fields summary

For this stage, we are using all the fields of the WCS. Dynamic mode is temporarily set to `false` to avoid the creation of new fields while allowing the indexing of events containing fields not in the schema. These fields can be retrieved from the original event (`_source`).

- [WCS main mappings](../../stateless/docs/fields.csv)

The detail of the fields can be found in csv file [Stateless Cloud-Services-Main Fields](fields.csv).

### Integrations:

The **cloud-services-main** log category provides specialized fields for processing events in the Wazuh security platform coming from these integrations:
- cisco-umbrella
