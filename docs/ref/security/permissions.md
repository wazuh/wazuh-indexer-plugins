## Permissions

### Setup plugin permissions

- plugin:wazuh/settings/write

### Content Manager plugin permissions

- plugin:content_manager/decoder/create
- plugin:content_manager/decoder/delete
- plugin:content_manager/decoder/update
- plugin:content_manager/logtest
- plugin:content_manager/logtest/detection
- plugin:content_manager/logtest/normalization
- plugin:content_manager/filter/create
- plugin:content_manager/filter/delete
- plugin:content_manager/filter/update
- plugin:content_manager/integration/create
- plugin:content_manager/integration/delete
- plugin:content_manager/integration/update
- plugin:content_manager/kvdb/create
- plugin:content_manager/kvdb/delete
- plugin:content_manager/kvdb/update
- plugin:content_manager/policy/update
- plugin:content_manager/promote/execute
- plugin:content_manager/promote/preview
- plugin:content_manager/rule/create
- plugin:content_manager/rule/delete
- plugin:content_manager/rule/update
- plugin:content_manager/space/delete
- plugin:content_manager/subscription/delete
- plugin:content_manager/subscription/get
- plugin:content_manager/subscription/create
- plugin:content_manager/subscription/update
- plugin:content_manager/version_check


### Security Analytics plugin permissions

- cluster:admin/wazuh/securityanalytics/detector/delete
- cluster:admin/wazuh/securityanalytics/detector/write
- cluster:admin/wazuh/securityanalytics/logtype/delete
- cluster:admin/wazuh/securityanalytics/logtype/write
- cluster:admin/wazuh/securityanalytics/rule/custom/delete
- cluster:admin/wazuh/securityanalytics/rule/custom/write
- cluster:admin/wazuh/securityanalytics/rule/delete
- cluster:admin/wazuh/securityanalytics/rule/write
- cluster:admin/wazuh/securityanalytics/rules/evaluate
- cluster:admin/wazuh/securityanalytics/space/delete
- plugin:security_analytics/findings/_update