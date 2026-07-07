# Permissions

This page lists the permissions registered by the Wazuh Indexer plugins that are referenced by the [default roles](./access-control.md). Content Manager permission names are **action groups** (defined in `action_groups.yml`) that resolve to the actual `cluster:admin/content_manager/*` transport actions registered by the plugin; the Setup and Security Analytics entries are raw cluster actions.

### Setup plugin permissions

- `cluster:admin/setup/settings/update` — update the Wazuh settings (`PUT /_plugins/_setup/settings`)

### Content Manager plugin permissions

Each resource exposes `create`, `update` and `delete`, plus a `*` action group that aggregates the three:

- `plugin:content_manager/integration/{create,update,delete}` (and `plugin:content_manager/integration/*`)
- `plugin:content_manager/decoder/{create,update,delete}` (and `plugin:content_manager/decoder/*`)
- `plugin:content_manager/rule/{create,update,delete}` (and `plugin:content_manager/rule/*`)
- `plugin:content_manager/kvdb/{create,update,delete}` (and `plugin:content_manager/kvdb/*`)
- `plugin:content_manager/filter/{create,update,delete}` (and `plugin:content_manager/filter/*`)

Other Content Manager permissions:

- `plugin:content_manager/policy/update` — create/update a policy (`PUT /_plugins/_content_manager/policy/{space}`)
- `plugin:content_manager/update` — trigger an on-demand CTI catalog sync (`POST /_plugins/_content_manager/update`)
- `plugin:content_manager/subscription/get` — read the CTI subscription
- `plugin:content_manager/subscription/post` — create/update the CTI subscription
- `plugin:content_manager/subscription/delete` — delete the CTI subscription
- `plugin:content_manager/promote/get` — preview a promotion diff
- `plugin:content_manager/promote/post` — execute a space promotion (and `plugin:content_manager/promote/*`)
- `plugin:content_manager/logtest`, `plugin:content_manager/logtest/detection`, `plugin:content_manager/logtest/normalization` (and `plugin:content_manager/logtest/*`)
- `plugin:content_manager/space/delete` — delete a space
- `plugin:content_manager/version/check` — check the catalog version

### Security Analytics plugin permissions

Wazuh custom actions:

- `cluster:admin/wazuh/securityanalytics/detector/write`
- `cluster:admin/wazuh/securityanalytics/detector/delete`
- `cluster:admin/wazuh/securityanalytics/logtype/write`
- `cluster:admin/wazuh/securityanalytics/logtype/delete`
- `cluster:admin/wazuh/securityanalytics/rule/write`
- `cluster:admin/wazuh/securityanalytics/rule/delete`
- `cluster:admin/wazuh/securityanalytics/rule/custom/write`
- `cluster:admin/wazuh/securityanalytics/rule/custom/delete`
- `cluster:admin/wazuh/securityanalytics/rules/evaluate`
- `cluster:admin/wazuh/securityanalytics/space/delete`

The default roles also grant the upstream OpenSearch Security Analytics actions (`cluster:admin/opensearch/securityanalytics/*`) — the full `/*` set for `wazuh_admin` and `wazuh_demo`, and the read-only (`/get`, `/search`) subset for `wazuh_readonly`.
