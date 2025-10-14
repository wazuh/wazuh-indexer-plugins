## `wazuh-events-5.x-aws-logs` time series index

The `wazuh-events-*` indices store events received from monitored endpoints through the aws-logs integration.

This is a time-based (stateless) index. The index includes the WCS fields and the fields of the corresponding aws-logs integration.

### Fields summary

For this stage, we are using all the fields of the WCS. Dynamic mode is temporarily set to `false` to avoid the creation of new fields while allowing the indexing of events containing fields not in the schema. These fields can be retrieved from the original event (`_source`).

- [WCS main mappings](../../stateless/docs/fields.csv)

The detail of the fields can be found in csv file [Stateless Aws-Logs Fields](fields.csv).

### Integration: aws-logs

This integration belongs to the **aws** log family and provides specialized fields for processing aws-logs events in the Wazuh security platform.
