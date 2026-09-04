# Wazuh Common Schema

The Wazuh Common Schema (WCS) is a standardized structure for organizing and categorizing security event data collected by Wazuh. It is designed to facilitate data analysis, correlation, and reporting across different data sources and types.

This page documents the event category taxonomy shared by the stateless event and finding data streams. WCS also covers stateful inventory indices (see [Indices](./index.md#indices) above), the metrics streams, and the content and CVE indices owned by the Content Manager plugin (see [Content Manager](../content-manager/index.md#system-indices)) — those aren't repeated here.

### Categorization

The Wazuh Common Schema categorizes events into several key areas to streamline data management and analysis.

All event categories share a single base index template (`events.json`), and the same applies to findings categories with their own shared base (`findings.json`). At deployment time, the setup plugin generates one index template per category from the applicable shared base, overriding only two fields: `index_patterns` (set to `wazuh-events-v5-<category>*` or `wazuh-findings-v5-<category>*`) and, where present in the base template's settings, `rollover_alias` (set to the category's index name). The mappings are copied through unchanged — every category's index template has identical mappings, since they all originate from the same base template. This means only one template file exists per stream family in the repository, but each category still gets its own index template registered in the cluster.

To list all deployed event templates:

```
GET /_index_template/wazuh-events-*
```

#### Categories

The **Key** column is the canonical identifier used throughout the system — in data stream names, integrations, rules, decoders, and the Ruleset Management plugin. Use it exactly as shown when creating or referencing any of these resources.

| Name              | Key                 | Example log types                                |
| ----------------- | ------------------- | ------------------------------------------------ |
| Access Management | `access-management` | `ad_ldap`, `apache_access`, `okta`               |
| Applications      | `applications`      | `github`, `gworkspace`, `m365`                   |
| Cloud Services    | `cloud-services`    | `azure`, `cloudtrail`, `s3`                      |
| Network Activity  | `network-activity`  | `dns`, `network`, `vpcflow`                      |
| Security          | `security`          | `waf`                                            |
| System Activity   | `system-activity`   | `linux`, `windows`, `others_macos`               |
| Other             | `other`             | `others_application`, `others_apt`, `others_web` |
| Unclassified      | `unclassified`      | |

### Data streams

Each category maps to a dedicated data stream following the pattern `wazuh-events-v5-{key}`:

#### Events
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

#### Findings
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