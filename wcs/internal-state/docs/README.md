## `.wazuh-internal-state` index data model

### Fields summary

Wazuh Common Schema (WCS) field set describing the Wazuh Indexer's own internal, state. Added by:

- [Create AI assistant index as part of setup initialization](https://github.com/wazuh/wazuh-indexer-plugins/pull/1424).

The detail of the fields can be found in the csv file [Fields](fields.csv).

### Index

- **Index pattern:** `.wazuh-internal-state*`
- Hidden system index.

### Field table

| Field | Type | Level | Description |
|-------|------|-------|-------------|
| `access_token` | keyword | custom | Encrypted CTI access token used by the Content Manager plugin. |
| `updated_at` | date | custom | When this document was last written, stamped by the indexer. |
| `name` | keyword | custom | Name given to the provider configuration. *(provider docs)* |
| `type` | keyword | custom | Provider implementation to use. *(provider docs)* |
| `base_url` | keyword | custom | Base URL of the provider's API. *(provider docs)* |
| `model` | keyword | custom | Model to request from the provider. *(provider docs)* |
| `api_key` | keyword | custom | Encrypted API key used to authenticate against the provider. *(provider docs)* |
| `is_default` | boolean | custom | Whether this provider is the one used by default. *(provider docs)* |
| `privacy_default_on` | boolean | custom | Whether privacy mode is enabled by default for new conversations. *(settings doc)* |
| `privacy_default_per_provider` | object | custom | Per-provider override of the default privacy mode. *(settings doc)* |
| `user_can_override` | boolean | custom | Whether users may override the default privacy setting. *(settings doc)* |
| `field_policy.field` | keyword | custom | Fully qualified name of the event field this policy entry applies to. *(settings doc)* |
| `field_policy.action` | keyword | custom | Whether the field is sent to the AI provider verbatim (`allow`) or anonymized first (`anonymize`). *(settings doc)* |
| `field_policy.kind` | keyword | custom | What kind of data is being anonymized (e.g. `HOST`, `IP`). Only set on `anonymize` entries. *(settings doc)* |
