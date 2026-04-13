# Wazuh Common Schema

The Wazuh Common Schema (WCS) is a standardized structure for organizing and categorizing security event data collected by Wazuh. It is designed to facilitate data analysis, correlation, and reporting across different data sources and types.

### Categorization

The Wazuh Common Schema categorizes events into several key areas to streamline data management and analysis.

All event categories share a single base index template (`events.json`). At deployment time, the setup plugin dynamically generates one index template per category from this shared base, setting the appropriate `index_patterns` and `rollover_alias` for each. This means only one template file exists in the repository, but each category gets its own index template in the cluster.

The index mappings and settings for subcategories take precedence over those from the main category. In OpenSearch, index templates are applied in order of their "priority" value: templates with a lower priority are applied first, and those with a higher priority are applied afterward, allowing them to override previous settings. This means the index template for the main category is applied first (priority=1), and then the subcategory template (priority=10) is applied on top of it, so subcategory-specific settings override the main category defaults.

To list all deployed event templates:

```
GET /_index_template/wazuh-events-*
```

#### Categories

The **Key** column is the canonical identifier used throughout the system — in data stream names, integrations, rules, decoders, and the Security Analytics plugin. Use it exactly as shown when creating or referencing any of these resources.

| Name              | Key                 | Example log types                                |
| ----------------- | ------------------- | ------------------------------------------------ |
| Access Management | `access-management` | `ad_ldap`, `apache_access`, `okta`               |
| Applications      | `applications`      | `github`, `gworkspace`, `m365`                   |
| Cloud Services    | `cloud-services`    | `azure`, `cloudtrail`, `s3`                      |
| Network Activity  | `network-activity`  | `dns`, `network`, `vpcflow`                      |
| Security          | `security`          | `waf`                                            |
| System Activity   | `system-activity`   | `linux`, `windows`, `others_macos`               |
| Other             | `other`             | `others_application`, `others_apt`, `others_web` |
| Unclassified      | `unclassified`      | Events that could not be categorized             |

> **Note:** `unclassified` is a catch-all for events that could not be assigned to any other category. It is managed automatically by the pipeline and should not be used as a target category when creating new integrations or rules.

### Data Streams

Each category maps to a dedicated data stream following the pattern `wazuh-events-v5-{key}`:

**Events**
```
wazuh-events-v5-access-management
wazuh-events-v5-applications
wazuh-events-v5-cloud-services
wazuh-events-v5-network-activity
wazuh-events-v5-other
wazuh-events-v5-security
wazuh-events-v5-system-activity
wazuh-events-v5-unclassified
```

**Findings**
```
wazuh-findings-v5-access-management
wazuh-findings-v5-applications
wazuh-findings-v5-cloud-services
wazuh-findings-v5-network-activity
wazuh-findings-v5-other
wazuh-findings-v5-security
wazuh-findings-v5-system-activity
wazuh-findings-v5-unclassified
```

Check [Stream indices](./index.md#stream-indices) for details.