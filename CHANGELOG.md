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
- Implement retry mechanism to the initialization plugin [(#541)](https://github.com/wazuh/wazuh-indexer-plugins/pull/541)
- Add documentation for reporting plugin [(#544)](https://github.com/wazuh/wazuh-indexer-plugins/pull/544)
- Add index definition for stateless indices [(#554)](https://github.com/wazuh/wazuh-indexer-plugins/pull/554)
- Add tooling and index definitions for Wazuh decoders [(#581)](https://github.com/wazuh/wazuh-indexer-plugins/pull/581)
- Categorize WCS stateless indices [(#588)](https://github.com/wazuh/wazuh-indexer-plugins/pull/588)
- Add major version to index aliases [(#592)](https://github.com/wazuh/wazuh-indexer-plugins/pull/592)
- Increase max_docvalue_fields_search to 200 [(#594)](https://github.com/wazuh/wazuh-indexer-plugins/pull/594)
- Add cloud services subcategories [(#595)](https://github.com/wazuh/wazuh-indexer-plugins/pull/595)
- Add AWS Bedrock integration [(#602)](https://github.com/wazuh/wazuh-indexer-plugins/pull/602)
- Add wazuh.protocol.location and wazuh.protocol.queue fields to WCS [(#613)](https://github.com/wazuh/wazuh-indexer-plugins/pull/613)
- Add version to the GH Workflow names [(#570)](https://github.com/wazuh/wazuh-indexer-plugins/pull/570)
- Add browser-extensions and services inventory indices to documentation [(#574)](https://github.com/wazuh/wazuh-indexer-plugins/pull/574)
- Add state.modified_at to stateful indexes [(#561)](https://github.com/wazuh/wazuh-indexer-plugins/pull/561)
- Add WCS integration fields to stateless indices [(#621)](https://github.com/wazuh/wazuh-indexer-plugins/pull/621)

### Dependencies
-

### Changed
- Replace dependabot's directories keys with wildcard [(#443)](https://github.com/wazuh/wazuh-indexer-plugins/pull/443)
- Adapt setup plugin for 5.x [(#450)](https://github.com/wazuh/wazuh-indexer-plugins/pull/450)
- Third-party integrations maintenance [(#478)](https://github.com/wazuh/wazuh-indexer-plugins/pull/478) [(#540)](https://github.com/wazuh/wazuh-indexer-plugins/pull/540) [(#548)](https://github.com/wazuh/wazuh-indexer-plugins/pull/548) [(#566)](https://github.com/wazuh/wazuh-indexer-plugins/pull/566) [(#583)](https://github.com/wazuh/wazuh-indexer-plugins/pull/583)
- Replace and remove deprecated settings [(#476)](https://github.com/wazuh/wazuh-indexer-plugins/pull/476)
- Migrate WCS changes from 4.x [(#488)](https://github.com/wazuh/wazuh-indexer-plugins/pull/488) [(#552)](https://github.com/wazuh/wazuh-indexer-plugins/pull/552) [(#568)](https://github.com/wazuh/wazuh-indexer-plugins/pull/568)
- Implement checksum fields into stateful ECS mappings [(#519)](https://github.com/wazuh/wazuh-indexer-plugins/pull/519) [(#569)](https://github.com/wazuh/wazuh-indexer-plugins/pull/569)
- FIM indices rework [(#509)](https://github.com/wazuh/wazuh-indexer-plugins/pull/509)
- Update GitHub Actions versions in main branch [(#572)](https://github.com/wazuh/wazuh-indexer-plugins/pull/572)
- Update index templates with agent fields [(#578)](https://github.com/wazuh/wazuh-indexer-plugins/pull/578)
- Rename indices from *-5.x-* to *-v5-* [(#597)](https://github.com/wazuh/wazuh-indexer-plugins/pull/597)
- Use stricter field limits for the WCS indices [(#589)](https://github.com/wazuh/wazuh-indexer-plugins/pull/589)
- Bump WCS to ECS v9.1.0 [(#600)](https://github.com/wazuh/wazuh-indexer-plugins/pull/600)
- Replace genai.* nested fields with keyword array [(#608)](https://github.com/wazuh/wazuh-indexer-plugins/pull/608)
- Check GitHub actions with dependabot [(#601)](https://github.com/wazuh/wazuh-indexer-plugins/pull/601)
- Automatically regenerate dependant stateless modules on base module change [(#618)](https://github.com/wazuh/wazuh-indexer-plugins/pull/618)
- Restructure WCS files[(#629)](https://github.com/wazuh/wazuh-indexer-plugins/pull/629)
- Restructuring of the repository tooling [(#625)](https://github.com/wazuh/wazuh-indexer-plugins/pull/625)
- Fix mdbook to version 0.4.x [(#627)](https://github.com/wazuh/wazuh-indexer-plugins/pull/627)

### Deprecated
-

### Removed
- Delete files not needed for `5.0.0` [(#439)](https://github.com/wazuh/wazuh-indexer-plugins/pull/439)
- Remove extra fields from CSV documentation [(#479)](https://github.com/wazuh/wazuh-indexer-plugins/pull/479)
- Remove outdated documentation [(#532)](https://github.com/wazuh/wazuh-indexer-plugins/pull/532)
- Remove ECS object from WCS definitions [(#612)](https://github.com/wazuh/wazuh-indexer-plugins/pull/612)

### Fixed
- Improve ECS folder structure [(#473)](https://github.com/wazuh/wazuh-indexer-plugins/pull/473)
- Fix permissions for job 'call-build-workflow' [(#492)](https://github.com/wazuh/wazuh-indexer-plugins/pull/492)
- Update event generators [(#505)](https://github.com/wazuh/wazuh-indexer-plugins/pull/505)
- Update `DEVELOPER_GUIDE.md` to use JDK 21 [(#538)](https://github.com/wazuh/wazuh-indexer-plugins/pull/538)
- Fix WCS generator modules detection issues [(#620)](https://github.com/wazuh/wazuh-indexer-plugins/pull/620)

### Security
- Reduce risk of GITHUB_TOKEN exposure [(#484)](https://github.com/wazuh/wazuh-indexer-plugins/pull/484)
- Bump requests in /integrations/amazon-security-lake/tests [(#491)](https://github.com/wazuh/wazuh-indexer-plugins/pull/491)

[Unreleased 5.0.x]: https://github.com/wazuh/wazuh-indexer-plugins/compare/205f222d0d246129917fa211766e1735aae13ed7...main
