## `security-auditlogs` index data model

### Fields summary

The fields describe the audit events the security plugin writes when `plugins.security.audit.type` is `internal_opensearch_data_stream` and `plugins.security.audit.config.data_stream.name` is `security-auditlogs`, as the packaged `opensearch.yml` sets. Added by:

- [Packaged config doesn't store audit logs](https://github.com/wazuh/wazuh-indexer/issues/2040).

The security plugin sets the field names, so they don't follow ECS. The template maps the fields below and keeps any other field in `_source` only (`dynamic: false`). The request headers and URL parameters are `flat_object` fields: the client chooses their names, so they never become fields of the mapping.

The detail of the fields can be found in the csv file [Fields](fields.csv).

### Data stream

- **Index pattern:** `security-auditlogs*`
- **Template priority:** 1. The security plugin puts its own template for the same data stream at priority 0 on every node start, and that put fails if another matching template has the same priority.
- **ISM policy:** `security-auditlogs-policy` rolls over backing indices monthly (or earlier at 20 GB per primary shard) and deletes rolled-over indices once they reach 90 days of age.
