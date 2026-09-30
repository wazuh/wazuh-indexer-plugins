## `wazuh-events-raw-v5` index data model

### Fields summary

Stateless index holding raw, unparsed events as received, before decoding. Each document keeps the original event text in `event.original` plus the Wazuh agent/cluster/protocol metadata under `wazuh.*` 

The detail of the fields can be found in the csv file [Fields](fields.csv).

### Data stream

- **Index pattern:** `wazuh-events-raw-v5*`
- **ISM policy:** `stream-raw-events-policy` — rolls over at 20 GB per primary shard (or 200M docs) and deletes rolled-over indices once they reach 10 minutes of age. Retention is the greater of the two, so raw events are not bounded in time on a low-volume deployment.
