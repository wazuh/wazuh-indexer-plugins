# CHANGELOG

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). See the [CONTRIBUTING guide](./CONTRIBUTING.md#Changelog) for instructions on how to add changelog entries.

## [Unreleased 5.0.x]

### Added
- Add RBAC index templates with its corresponding event generator [(#303)](https://github.com/wazuh/wazuh-indexer-plugins/pull/303)
- Implement content update based on offsets [(#307)](https://github.com/wazuh/wazuh-indexer-plugins/pull/307)
- Add technical documentation [(#320)](https://github.com/wazuh/wazuh-indexer-plugins/pull/320)
- Implement CTI snapshot download [(#318)](https://github.com/wazuh/wazuh-indexer-plugins/pull/318)
- Implement CTI snapshot unzip tool [(#319)](https://github.com/wazuh/wazuh-indexer-plugins/pull/319)
- Implement CTI snapshot indexing [(#338)](https://github.com/wazuh/wazuh-indexer-plugins/pull/338)
- Implement content "update" command [(#339)](https://github.com/wazuh/wazuh-indexer-plugins/pull/339)
- Add mappings for Wazuh rules (stage 1) to the Alerts index [#345](https://github.com/wazuh/wazuh-indexer-plugins/pull/345)
- Add index templates for SCA [(#351)](https://github.com/wazuh/wazuh-indexer-plugins/issues/351)
- Implement CVE ECS definition and index template [(#337)](https://github.com/wazuh/wazuh-indexer-plugins/pull/337)
- Implement a time-based management of the agent.status attribute in the wazuh-agents index [(#349)](https://github.com/wazuh/wazuh-indexer-plugins/pull/349)
- Implement RBAC "refresh" command [(#370)](https://github.com/wazuh/wazuh-indexer-plugins/pull/370)

### Dependencies

### Changed
- Refactor Content Manager's code and fix Catalog info indexing [(#317)](https://github.com/wazuh/wazuh-indexer-plugins/pull/317)
- Improved mdbook installation instructions [#332](https://github.com/wazuh/wazuh-indexer-plugins/pull/332)
- Third-party integrations maintenance [(#299)](https://github.com/wazuh/wazuh-indexer-plugins/pull/299) [(#374)](https://github.com/wazuh/wazuh-indexer-plugins/pull/374)
- Upgrade to Opensearch 2.19.1 [(#304)](https://github.com/wazuh/wazuh-indexer-plugins/pull/304)
- Add cross-account support for Security Lake integration [(#322)](https://github.com/wazuh/wazuh-indexer-plugins/pull/322)
- Improve ECS documentation I [(#328)](https://github.com/wazuh/wazuh-indexer-plugins/pull/328)
- Improve ECS documentation II [(#350)](https://github.com/wazuh/wazuh-indexer-plugins/pull/350)
- Index RBAC information on startup [(#356)](https://github.com/wazuh/wazuh-indexer-plugins/pull/356)

### Deprecated

### Removed

### Fixed
- Fix missing stateless inventory fields on the `alerts` template [(#342)](https://github.com/wazuh/wazuh-indexer-plugins/pull/342)
- Fix error on `generate-and-push-templates.sh` script when the index template file does not exist on setup plugin resources [(#303)](https://github.com/wazuh/wazuh-indexer-plugins/pull/303)
- Fix validation of commands by forcing `action.name` to exist before `action.args` [(#260)](https://github.com/wazuh/wazuh-indexer-plugins/issues/260)
- Fix mentions of `host.ip` and `host.os.full` in agents index template [(#330)](https://github.com/wazuh/wazuh-indexer-plugins/pull/330)

### Security

[Unreleased 5.0.x]: https://github.com/wazuh/wazuh-indexer-plugins/compare/main...main
