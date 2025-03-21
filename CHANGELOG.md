# CHANGELOG

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). See the [CONTRIBUTING guide](./CONTRIBUTING.md#Changelog) for instructions on how to add changelog entries.

## [Unreleased 5.0.x]

### Added
- Add RBAC index templates with its corresponding event generator [(#303)](https://github.com/wazuh/wazuh-indexer-plugins/pull/303)
- Add technical documentation [(#320)](https://github.com/wazuh/wazuh-indexer-plugins/pull/320)

### Dependencies

### Changed
- Refactor Content Manager's code and fix Catalog info indexing [(#317)](https://github.com/wazuh/wazuh-indexer-plugins/pull/317)
- Improved mdbook installation instructions [#332](https://github.com/wazuh/wazuh-indexer-plugins/pull/332)
- Third-party integrations maintenance [(#299)](https://github.com/wazuh/wazuh-indexer-plugins/pull/299)
- Upgrade to Opensearch 2.19.1 [(#304)](https://github.com/wazuh/wazuh-indexer-plugins/pull/304)
- Improve ECS documentation [(#328)](https://github.com/wazuh/wazuh-indexer-plugins/pull/328)


### Deprecated

### Removed

### Fixed
- Fix missing stateless inventory fields on the `alerts` template [(#342)](https://github.com/wazuh/wazuh-indexer-plugins/pull/342)
- Fix error on `generate-and-push-templates.sh` script when the index template file does not exist on setup plugin resources [(#303)](https://github.com/wazuh/wazuh-indexer-plugins/pull/303)
- Fix validation of commands by forcing `action.name` to exist before `action.args` [(#260)](https://github.com/wazuh/wazuh-indexer-plugins/issues/260)
- Fix mentions of `host.ip` and `host.os.full` in agents index template [(#330)](https://github.com/wazuh/wazuh-indexer-plugins/pull/330)

### Security

[Unreleased 5.0.x]: https://github.com/wazuh/wazuh-indexer-plugins/compare/main...main
