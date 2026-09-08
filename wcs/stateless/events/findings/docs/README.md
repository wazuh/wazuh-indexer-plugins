## `wazuh-findings-v5` index data model

### Fields summary

Stateless index storing security findings. It reuses the full set of WCS fields defined in the [base stateless template](../../main/docs/README.md).

The detail of the fields can be found in the csv file [Fields](fields.csv).

### Data stream

- **Index pattern:** `wazuh-findings-v5*`
- **ISM policy:** `stream-findings-policy` — rolls over on size/doc count and deletes indices older than 90 days.
