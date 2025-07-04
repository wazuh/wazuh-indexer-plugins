# CHANGELOG

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). See the [CONTRIBUTING guide](./CONTRIBUTING.md#Changelog) for instructions on how to add changelog entries.

## [Unreleased 5.0.x]

### Added
- Create index and index templates for 5.0.0 [(#452)](https://github.com/wazuh/wazuh-indexer-plugins/pull/452)
- Add ISM rollover policy for stateless indices [(#471)](https://github.com/wazuh/wazuh-indexer-plugins/pull/471)
- Add scripts to extract the product versions [(#483)](https://github.com/wazuh/wazuh-indexer-plugins/pull/483)
- Add SCA index to 5.0.0 [(#516)](https://github.com/wazuh/wazuh-indexer-plugins/pull/516)
- Add repository bumper [(#500)](https://github.com/wazuh/wazuh-indexer-plugins/pull/500)
- Add documentation for the setup plugin [(#498)](https://github.com/wazuh/wazuh-indexer-plugins/pull/498)
- Add documentation for default users and roles (RBAC) [(#535)](https://github.com/wazuh/wazuh-indexer-plugins/pull/535)

### Dependencies
-

### Changed
- Replace dependabot's directories keys with wildcard [(#443)](https://github.com/wazuh/wazuh-indexer-plugins/pull/443)
- Adapt setup plugin for 5.x [(#450)](https://github.com/wazuh/wazuh-indexer-plugins/pull/450)
- Third-party integrations maintenance [(#478)](https://github.com/wazuh/wazuh-indexer-plugins/pull/478) [(#540)](https://github.com/wazuh/wazuh-indexer-plugins/pull/540)
- Replace and remove deprecated settings [(#476)](https://github.com/wazuh/wazuh-indexer-plugins/pull/476)
- Migrate WCS changes from 4.x [(#488)](https://github.com/wazuh/wazuh-indexer-plugins/pull/488)
- Implement checksum fields into stateful ECS mappings [(#519)](https://github.com/wazuh/wazuh-indexer-plugins/pull/519)
- FIM indices rework [(#509)](https://github.com/wazuh/wazuh-indexer-plugins/pull/509)

### Deprecated
-

### Removed
- Delete files not needed for `5.0.0` [(#439)](https://github.com/wazuh/wazuh-indexer-plugins/pull/439)
- Remove extra fields from CSV documentation [(#479)](https://github.com/wazuh/wazuh-indexer-plugins/pull/479)
- Remove outdated documentation [(#532)](https://github.com/wazuh/wazuh-indexer-plugins/pull/532)

### Fixed
- Improve ECS folder structure [(#473)](https://github.com/wazuh/wazuh-indexer-plugins/pull/473)
- Fix permissions for job 'call-build-workflow' [(#492)](https://github.com/wazuh/wazuh-indexer-plugins/pull/492)
- Update event generators [(#505)](https://github.com/wazuh/wazuh-indexer-plugins/pull/505)
- Update `DEVELOPER_GUIDE.md` to use JDK 21 [(#538)](https://github.com/wazuh/wazuh-indexer-plugins/pull/538)

### Security
- Reduce risk of GITHUB_TOKEN exposure [(#484)](https://github.com/wazuh/wazuh-indexer-plugins/pull/484)
- Bump requests in /integrations/amazon-security-lake/tests [(#491)](https://github.com/wazuh/wazuh-indexer-plugins/pull/491)

[Unreleased 5.0.x]: https://github.com/wazuh/wazuh-indexer-plugins/compare/205f222d0d246129917fa211766e1735aae13ed7...main
