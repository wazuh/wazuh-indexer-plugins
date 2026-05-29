# Release notes

## Highlights

- New "[Setup][setup-plugin]" initialization plugin.
  - Creation of Wazuh indices, index templates and ISM policies on startup [#425](https://github.com/wazuh/wazuh-indexer-plugins/issues/425).
  - Data streams by default for time-series indices.
  - Adds ISM policies for data streams automatic rollover and removal based on age and size [#466](https://github.com/wazuh/wazuh-indexer-plugins/issues/466).
  - Adds metrics data streams [#34711](https://github.com/wazuh/wazuh/issues/34711).
  - Some Wazuh settings now reside in the Indexer, and can be managed using the Settings API in the Setup plugin [#833](https://github.com/wazuh/wazuh-indexer-plugins/issues/833).
- New "[Content Manager][content-manager-plugin]" plugin.
  - Official threat intel content management for Wazuh CTI (ruleset, vulnerabilities feed, IoC feed).
  - Custom content management for user-defined threat intel resources (rules, decoders, ...).
  - Scheduled automatic updates by default.
  - Supports for manual updates.
  - Implements a log test feature split into normalization (decoders) and detection (rules) phases.
  - Implements a REST API for content management, log testing, manual updates, and other operations.
- Fork of OpenSearch's Security Analytics plugin. [[1][fork-security-analytics]]
  - Threat Detection migrated to from the Wazuh Server to the Wazuh Indexer Security Analytics plugin.
  - Extended Sigma rules syntax [#47](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/47)
  - Per-space support for Log Types and Rules [#37](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/37)
  - Per-space threat detectors [#117](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/117)
  - Rules parser improvements: 
    - Case-insensitive Sigma operators [#182](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/182)
    - Add `exists` Sigma modifiers [#173](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/173)
    - Add support for IPv6 addresses in Sigma rules
  - Dynamic event field referencing in findings [#181](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/181)
- Fork of OpenSearch's Reporting plugin. [[2][fork-reporting]]
- Fork of OpenSearch's Notifications plugin. [[3][fork-notifications]]
  - Webhooks for Slack, Jira, PagerDuty and Shuffle created by default.
  - Dedicated monitor for Active Response [#8](https://github.com/wazuh/wazuh-indexer-alerting/issues/8).
- Fork of OpenSearch's Alerting plugin. [[4][fork-alerting]]
  - Dedicated monitor for Active Response [#8](https://github.com/wazuh/wazuh-indexer-alerting/issues/8).
- Fork of OpenSearch's Common Utils repository. [[5][fork-common-utils]]
  - Dedicated monitor for Active Response [#8](https://github.com/wazuh/wazuh-indexer-alerting/issues/8).
- Built-in Wazuh Engine.
    - Validation of user-defined threat intel content.
    - Engine enrichment. Add IoC content management, GeoIP enrichment, and engine filters for event pre-processing [#33493](https://github.com/wazuh/wazuh/issues/33493)
- New `mdBook` documentation [(#254)](https://github.com/wazuh/wazuh-indexer-plugins/issues/254.)
- Reworked Wazuh Indexer packages and build scripts.
  - Wazuh Indexer packages now work for Systemd, SysV and initd service managers [#602](https://github.com/wazuh/wazuh-indexer/issues/602).
  - Snapshots for ruleset, vulnerabilities feed and IoC feed are now included in Wazuh Indexer packages.
- New set of default users and roles [#1538](https://github.com/wazuh/wazuh-indexer/issues/1538)
- Reworked and extended Wazuh Common Schema.
- Active Response has been migrated to the Wazuh Indexer.

## Breaking changes

- Wazuh Indexer 4.x can not be upgraded to 5.x. A new installation of Wazuh Indexer 5.x is required.
- Multi-tenancy disabled by default [#1080](https://github.com/wazuh/wazuh-indexer/issues/1080)
- Remove Performance Analyzer plugin from Wazuh Indexer packages [#891](https://github.com/wazuh/wazuh-indexer/issues/891)
- Filebeat is no longer used to forward events from the Wazuh server to the Wazuh indexer — replaced by the built-in indexer connector.
- Upgrade to OpenSearch 3.0 [#874](https://github.com/wazuh/wazuh-indexer/issues/874)
  - Replace and remove deprecated settings — configurations carried over from 4.x are no longer valid [#475](https://github.com/wazuh/wazuh-indexer-plugins/issues/475)
  - Update to JDK 25 [#1341](https://github.com/wazuh/wazuh-indexer/issues/1341)
- Migration of the Wazuh Common Schema from the `wazuh-indexer` repository to the `wazuh-indexer-plugins` repository. Folder renamed to `wcs` [#879](https://github.com/wazuh/wazuh-indexer-plugins/issues/879)


<!-- Links -->
[setup-plugin]: https://wazuh.github.io/wazuh-indexer-plugins/ref/modules/setup/index.html
[content-manager-plugin]: https://wazuh.github.io/wazuh-indexer-plugins/ref/modules/content-manager/index.html
[fork-security-analytics]: https://github.com/wazuh/wazuh-indexer-security-analytics/issues/1
[fork-reporting]: https://github.com/wazuh/wazuh-indexer-reporting/issues/1
[fork-notifications]: https://github.com/wazuh/wazuh-indexer-notifications/issues/2
[fork-alerting]: https://github.com/wazuh/wazuh-indexer-alerting/issues/1
[fork-common-utils]: https://github.com/wazuh/wazuh-indexer-common-utils/issues/1