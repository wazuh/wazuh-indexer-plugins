# Release notes

## Highlights

- New initialization plugin
- New Content Manager plugin
- Fork of OpenSearch's Security Analytics plugin
- Fork of OpenSearch's Reporting plugin
- Fork of OpenSearch's Notifications plugin
- Fork of OpenSearch's Alerting plugin
- Fork of OpenSearch's Common Utils repository
- Built-in Wazuh Engine.
- Threat Detection migrated to from the Wazuh Server to the Wazuh Indexer
- Reworked Wazuh Indexer packages and build scripts
- Content download from Wazuh CTI (ruleset, vulnerabilites feed, IoC feed)
  - Scheduled automatic updates
  - Manual updates
- New documentation
- Default notification channels
- New set of default users and roles
- Active Response
- Some Wazuh settings now reside in the Indexer, and can be manages using the Settings API in the Setup plugin.
- Reworked and extended Wazuh Common Schema

- Redesign the indexer initialization plugin to manage the full lifecycle of Wazuh indices, templates, and ISM policies on startup [#425](https://github.com/wazuh/wazuh-indexer-plugins/issues/425)
- Add ISM rollover policy for stateless indices to automatically rotate based on size, age, and document count [#466](https://github.com/wazuh/wazuh-indexer-plugins/issues/466)
- Implement Content Manager REST API with scheduled updates, hash-of-hashes validation, and IoC delivery [#3525](https://github.com/wazuh/internal-devel-requests/issues/3525)
- Engine enrichment. Add IoC content management, GeoIP enrichment, and engine filters for event pre-processing [#33493](https://github.com/wazuh/wazuh/issues/33493)
- Add metrics data streams and a telemetry ping job to collect platform usage and health data [#34711](https://github.com/wazuh/wazuh/issues/34711)
- Registration-based content download. Implement token exchange service and catalog plans. [#4743](https://github.com/wazuh/internal-devel-requests/issues/4743)


## Breaking changes

- Filebeat is no longer used to forward events from the Wazuh server to the Wazuh indexer — replaced by the built-in indexer connector [#2600](https://github.com/wazuh/internal-devel-requests/issues/2600)
- Replace time-series indices with data streams — index lifecycle and storage management changes [#650](https://github.com/wazuh/wazuh-indexer-plugins/issues/650)
- Replace and remove deprecated settings — configurations carried over from 4.x are no longer valid [#475](https://github.com/wazuh/wazuh-indexer-plugins/issues/475)
- Remove alerts and archives index creation from the setup plugin — these are now managed as data streams governed by ISM policies [#689](https://github.com/wazuh/wazuh-indexer-plugins/issues/689)
- Upgrade Gradle build toolchain — build scripts and plugins must be compatible with the new Gradle version [#630](https://github.com/wazuh/wazuh-indexer-plugins/issues/630)
- Update to JDK 25 [#1341](https://github.com/wazuh/wazuh-indexer/issues/1341)
- Upgrade to OpenSearch 3.0 [#874](https://github.com/wazuh/wazuh-indexer/issues/874)
- Migration of the Wazuh Common Schema from the wazuh-indexer repository to the wazuh-indexer-plugins repository.
