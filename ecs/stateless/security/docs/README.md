## `wazuh-events-v5-security` time series index

The `wazuh-events-v5-security` indices store events received from monitored endpoints through the relevant integrations.

This is a time-based (stateless) index. The index includes the WCS fields and the fields of the corresponding security integrations.

### Fields summary

For this stage, we are using all the fields of the WCS. Dynamic mode is temporarily set to `false` to avoid the creation of new fields while allowing the indexing of events containing fields not in the schema. These fields can be retrieved from the original event (`_source`).

- [WCS main mappings](../../main/docs/fields.csv)

The detail of the fields can be found in csv file [Stateless Security Fields](fields.csv).

### Integrations:

The **security** log category provides specialized fields for processing events in the Wazuh security platform coming from these integrations:
- modsecurity
- snort
- suricata
- zeek
