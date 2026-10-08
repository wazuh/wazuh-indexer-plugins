## [v5.0.0]

### Added

| Issue | Comment |
|-------|---------|
| [#1](https://github.com/wazuh/wazuh-indexer-plugins/issues/1) [#3](https://github.com/wazuh/wazuh-indexer-plugins/issues/3) [#13](https://github.com/wazuh/wazuh-indexer-plugins/issues/13) | Initialize `wazuh-indexer-plugins` repository |
| [#522](https://github.com/wazuh/wazuh-indexer-plugins/issues/522) [#558](https://github.com/wazuh/wazuh-indexer-plugins/issues/558) [#586](https://github.com/wazuh/wazuh-indexer-plugins/issues/586) [#630](https://github.com/wazuh/wazuh-indexer-plugins/issues/630) [#723](https://github.com/wazuh/wazuh-indexer-plugins/issues/723) [#850](https://github.com/wazuh/wazuh-indexer-plugins/issues/850) [#1001](https://github.com/wazuh/wazuh-indexer-plugins/issues/1001) [#1341](https://github.com/wazuh/wazuh-indexer/issues/1341) | Compatibility with OpenSearch 3.6.0 |
| [#434](https://github.com/wazuh/wazuh-indexer-plugins/issues/434) [#466](https://github.com/wazuh/wazuh-indexer-plugins/issues/466) [#533](https://github.com/wazuh/wazuh-indexer-plugins/issues/533) [#1249](https://github.com/wazuh/wazuh-indexer/issues/1249) | Create the Wazuh index templates, indices and index management policies at startup |
| [#831](https://github.com/wazuh/wazuh-indexer-plugins/issues/831) | Add `wazuh-events-raw-v5` data stream |
| [#832](https://github.com/wazuh/wazuh-indexer-plugins/issues/832) [#1348](https://github.com/wazuh/wazuh-indexer-plugins/issues/1348) | Add `wazuh-events-v5-unclassified` data stream for events without a category |
| [#72](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/72) [#1220](https://github.com/wazuh/wazuh-indexer-plugins/issues/1220) [#1334](https://github.com/wazuh/wazuh-indexer-plugins/issues/1334) | Add `wazuh-findings-v5-*` data streams with WCS-compliant findings and case management fields |
| [#884](https://github.com/wazuh/wazuh-indexer-plugins/issues/884) | Add `wazuh-active-responses` data stream |
| [#940](https://github.com/wazuh/wazuh-indexer-plugins/issues/940) [#1110](https://github.com/wazuh/wazuh-indexer-plugins/issues/1110) [#1235](https://github.com/wazuh/wazuh-indexer-plugins/issues/1235) | Add metrics and monitoring data streams |
| [#511](https://github.com/wazuh/wazuh-indexer-plugins/issues/511) [#351](https://github.com/wazuh/wazuh-indexer-plugins/issues/351) | Add SCA stateful index |
| [#1419](https://github.com/wazuh/wazuh-indexer-plugins/issues/1419) | Add `wazuh-agent-config` index |
| [#1425](https://github.com/wazuh/wazuh-indexer-plugins/issues/1425) | Add `wazuh-agent-stats` index |
| [#1422](https://github.com/wazuh/wazuh-indexer-plugins/issues/1422) | Add AI assistant support |
| [#276](https://github.com/wazuh/wazuh-indexer/issues/276) | Add cross-account support to the Amazon Security Lake integration |
| [#1213](https://github.com/wazuh/wazuh-indexer-plugins/issues/1213) | Add data retention policies for stream indices |
| [#553](https://github.com/wazuh/wazuh-indexer-plugins/issues/553) [#584](https://github.com/wazuh/wazuh-indexer-plugins/issues/584) [#590](https://github.com/wazuh/wazuh-indexer-plugins/issues/590) [#605](https://github.com/wazuh/wazuh-indexer-plugins/issues/605) [#606](https://github.com/wazuh/wazuh-indexer-plugins/issues/606) [#851](https://github.com/wazuh/wazuh-indexer-plugins/issues/851) [#1096](https://github.com/wazuh/wazuh-indexer-plugins/issues/1096) [#754](https://github.com/wazuh/wazuh-indexer-plugins/issues/754) [#638](https://github.com/wazuh/wazuh-indexer-plugins/issues/638) [#875](https://github.com/wazuh/wazuh-indexer-plugins/issues/875) [#1413](https://github.com/wazuh/wazuh-indexer-plugins/issues/1413) | Add the WCS definition of the event data streams, with categories, integration, enrichment, compliance and event correlation fields |
| [#981](https://github.com/wazuh/wazuh-indexer-plugins/issues/981) [#983](https://github.com/wazuh/wazuh-indexer-plugins/issues/983) [#989](https://github.com/wazuh/wazuh-indexer-plugins/issues/989) | Add missing `indicator.feed.name` and vulnerability fields to the WCS |
| [#515](https://github.com/wazuh/wazuh-indexer-plugins/issues/515) [#576](https://github.com/wazuh/wazuh-indexer-plugins/issues/576) [#560](https://github.com/wazuh/wazuh-indexer-plugins/issues/560) | Add checksum, metadata and `state.modified_at` fields to the stateful indices |
| [#870](https://github.com/wazuh/wazuh-indexer-plugins/issues/870) [#1105](https://github.com/wazuh/wazuh-indexer-plugins/issues/1105) [#961](https://github.com/wazuh/wazuh-indexer-plugins/issues/961) [#1069](https://github.com/wazuh/wazuh-indexer-plugins/issues/1069) | Initialize CTI content from the bundled snapshots and keep it up to date with scheduled and on-demand updates |
| [#735](https://github.com/wazuh/wazuh-indexer-plugins/issues/735) [#753](https://github.com/wazuh/wazuh-indexer-plugins/issues/753) [#829](https://github.com/wazuh/wazuh-indexer-plugins/issues/829) | Download IoCs from the CTI API and deliver them to the Wazuh Engine |
| [#325](https://github.com/wazuh/wazuh-indexer-plugins/issues/325) | Download the CTI vulnerability feed |
| [#812](https://github.com/wazuh/wazuh-indexer-plugins/issues/812) [#37](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/37) [#38](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/38) [#869](https://github.com/wazuh/wazuh-indexer-plugins/issues/869) [#1170](https://github.com/wazuh/wazuh-indexer-plugins/issues/1170) [#1103](https://github.com/wazuh/wazuh-indexer-plugins/issues/1103) | Add content spaces (`draft`, `test`, `custom`, `standard`) and the REST API to manage, promote and reset user-generated rules, decoders, integrations and KVDBs |
| [#756](https://github.com/wazuh/wazuh-indexer-plugins/issues/756) [#796](https://github.com/wazuh/wazuh-indexer-plugins/issues/796) | Add Engine filters index and API |
| [#833](https://github.com/wazuh/wazuh-indexer-plugins/issues/833) | Add support for Engine settings |
| [#918](https://github.com/wazuh/wazuh-indexer-plugins/issues/918) [#993](https://github.com/wazuh/wazuh-indexer-plugins/issues/993) [#1376](https://github.com/wazuh/wazuh-indexer-plugins/issues/1376) | Load the `standard`, `test` and `custom` spaces into the Wazuh Engine of every cluster node when their hash changes |
| [#1029](https://github.com/wazuh/wazuh-indexer-plugins/issues/1029) | Synchronize CTI integrations and rules with Security Analytics and create a threat detector for each integration |
| [#1356](https://github.com/wazuh/wazuh-indexer-plugins/issues/1356) | Add integration mode to enable or disable integrations and their threat detectors |
| [#56](https://github.com/wazuh/wazuh-indexer-security-analytics/issues/56) | Add rule testing to the logtest endpoint |
| [#1042](https://github.com/wazuh/wazuh-indexer-plugins/issues/1042) [#1218](https://github.com/wazuh/wazuh-indexer-plugins/issues/1218) | Add telemetry ping job reporting the environment's identity and version to the CTI API |
| [#1010](https://github.com/wazuh/wazuh-indexer-plugins/issues/1010) | Add version check endpoint |
| [#1084](https://github.com/wazuh/wazuh-indexer-plugins/issues/1084) | Add YAML representation for ruleset resources |
| [#1276](https://github.com/wazuh/wazuh-indexer-plugins/issues/1276) | Add configurable resource creation limits |
| [#1277](https://github.com/wazuh/wazuh-indexer-plugins/issues/1277) | Add settings to disable on-demand updates and policy updates for every user |
| [#1585](https://github.com/wazuh/wazuh-indexer-plugins/issues/1585) | Add plugin settings for the operational constants of the Setup and Content Manager plugins |
| [#529](https://github.com/wazuh/wazuh-indexer-plugins/issues/529) [#1538](https://github.com/wazuh/wazuh-indexer/issues/1538) [#1927](https://github.com/wazuh/wazuh-indexer/issues/1927) [#1960](https://github.com/wazuh/wazuh-indexer/issues/1960) [#1975](https://github.com/wazuh/wazuh-indexer/issues/1975) [#1976](https://github.com/wazuh/wazuh-indexer/issues/1976) [#934](https://github.com/wazuh/wazuh-indexer-plugins/issues/934) [#1240](https://github.com/wazuh/wazuh-indexer-plugins/issues/1240) [#1530](https://github.com/wazuh/wazuh-indexer-plugins/issues/1530) [#1656](https://github.com/wazuh/wazuh-indexer-plugins/issues/1656) | Add the Wazuh indexer 5.x documentation |



### Changed

| Issue | Comment |
|-------|---------|
| [#1284](https://github.com/wazuh/wazuh-indexer-plugins/issues/1284) [#1354](https://github.com/wazuh/wazuh-indexer-plugins/issues/1354) [#1793](https://github.com/wazuh/wazuh-indexer/issues/1793) [#1817](https://github.com/wazuh/wazuh-indexer/issues/1817) [#1818](https://github.com/wazuh/wazuh-indexer/issues/1818) | Unify the default settings of Wazuh indices for All-in-One deployments, auto-expanding to one replica on multi-node clusters |
| [#1271](https://github.com/wazuh/wazuh-indexer-plugins/issues/1271) | Use the `zstd` codec by default for indices created by Wazuh plugins |
| [#1328](https://github.com/wazuh/wazuh-indexer-plugins/issues/1328) | Reduce the in-memory TTL of deleted documents on stateful indices |
| [#599](https://github.com/wazuh/wazuh-indexer-plugins/issues/599) | Upgrade the WCS to ECS 9.1.0 |
| [#482](https://github.com/wazuh/wazuh-indexer-plugins/issues/482) [#975](https://github.com/wazuh/wazuh-indexer/issues/975) [#1068](https://github.com/wazuh/wazuh-indexer/issues/1068) [#1114](https://github.com/wazuh/wazuh-indexer/issues/1114) | Migrate WCS changes from 4.x |
| [#650](https://github.com/wazuh/wazuh-indexer-plugins/issues/650) | Replace time-series indices with data streams |
| [#506](https://github.com/wazuh/wazuh-indexer-plugins/issues/506) | Rework the FIM indices |
| [#775](https://github.com/wazuh/wazuh-indexer-plugins/issues/775) | Move `agent` fields under `wazuh` |
| [#477](https://github.com/wazuh/wazuh-indexer-plugins/issues/477) [#539](https://github.com/wazuh/wazuh-indexer-plugins/issues/539) [#547](https://github.com/wazuh/wazuh-indexer-plugins/issues/547) [#562](https://github.com/wazuh/wazuh-indexer-plugins/issues/562) [#582](https://github.com/wazuh/wazuh-indexer-plugins/issues/582) [#641](https://github.com/wazuh/wazuh-indexer-plugins/issues/641) [#697](https://github.com/wazuh/wazuh-indexer-plugins/issues/697) [#741](https://github.com/wazuh/wazuh-indexer-plugins/issues/741) [#811](https://github.com/wazuh/wazuh-indexer-plugins/issues/811) [#906](https://github.com/wazuh/wazuh-indexer-plugins/issues/906) [#1015](https://github.com/wazuh/wazuh-indexer-plugins/issues/1015) [#1123](https://github.com/wazuh/wazuh-indexer-plugins/issues/1123) [#298](https://github.com/wazuh/wazuh-indexer-plugins/issues/298) [#372](https://github.com/wazuh/wazuh-indexer-plugins/issues/372) | Update third-party integrations to their latest versions |
| [#1635](https://github.com/wazuh/wazuh-indexer-plugins/issues/1635) | Include the consumer name in the snapshot download log messages |


### Removed

| Issue | Comment |
|-------|---------|
| [#689](https://github.com/wazuh/wazuh-indexer-plugins/issues/689) | Remove the alerts and archives index templates |
| [#1063](https://github.com/wazuh/wazuh-indexer-plugins/issues/1063) | Remove the vulnerability scanner reference field |


### Fixed

| Issue | Comment |
|-------|---------|
| [#1632](https://github.com/wazuh/wazuh-indexer-plugins/issues/1632) | Fix vulnerabilities content updates failing with `Target for add operation is not a container` |
| [#1633](https://github.com/wazuh/wazuh-indexer-plugins/issues/1633) | Fix CTI content updates getting stuck on an offset that cannot be applied, by rebuilding the content from a newer snapshot |

## Prior versions
