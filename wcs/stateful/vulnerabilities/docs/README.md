## `wazuh-states-vulnerabilities` index data model

### Fields summary

The fields are based on:

- [Global Queries](https://github.com/wazuh/wazuh/issues/27898) (included in 4.13.0).
- [States Persistence](https://github.com/wazuh/wazuh/issues/29840#issuecomment-2937251736) (included in 5.0.0)

Based on ECS:

- [Agent Fields](https://www.elastic.co/guide/en/ecs/current/ecs-agent.html).
- [Package Fields](https://www.elastic.co/guide/en/ecs/current/ecs-package.html).
- [Host Fields](https://www.elastic.co/guide/en/ecs/current/ecs-host.html).
- [Operating System Fields](https://www.elastic.co/guide/en/ecs/current/ecs-os.html).
- [Vulnerability Fields](https://www.elastic.co/guide/en/ecs/current/ecs-vulnerability.html).

The detail of the fields can be found in csv file [States vulnerabilities Fields](fields.csv).

### Transition table

| Field Name                        | Type    | Description                                                                                                         | Destination Field                 | Custom |
| --------------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------- | --------------------------------- | ------ |
| agent.build.original              | keyword | Extended build information for the agent.                                                                           | wazuh.agent.build.original        | FALSE  |
| agent.ephemeral_id                | keyword | Ephemeral identifier of this agent.                                                                                 | wazuh.agent.ephemeral_id          | FALSE  |
| agent.id                          | keyword | Unique identifier of this agent.                                                                                    | wazuh.agent.id                    | FALSE  |
| agent.name                        | keyword | Custom name of the agent.                                                                                           | wazuh.agent.name                  | FALSE  |
| agent.type                        | keyword | Type of the agent.                                                                                                  | wazuh.agent.type                  | FALSE  |
| agent.version                     | keyword | Version of the agent.                                                                                               | wazuh.agent.version               | FALSE  |
| host.os.full                      | keyword | Operating system name, including the version or code name.                                                          | host.os.full                      | FALSE  |
| host.os.kernel                    | keyword | Operating system kernel version as a raw string.                                                                    | host.os.kernel                    | FALSE  |
| host.os.name                      | keyword | Operating system name, without the version.                                                                         | host.os.name                      | FALSE  |
| host.os.platform                  | keyword | Operating system platform (such as centos, ubuntu, windows).                                                        | host.os.platform                  | FALSE  |
| host.os.type                      | keyword | Which commercial OS family (one of: linux, macos, unix, windows, ios or android).                                   | host.os.type                      | FALSE  |
| host.os.version                   | keyword | Operating system version as a raw string.                                                                           | host.os.version                   | FALSE  |
| package.architecture              | keyword | Package architecture.                                                                                               | package.architecture              | FALSE  |
| package.build_version             | keyword | Build version information.                                                                                          | package.build_version             | FALSE  |
| package.checksum                  | keyword | Checksum of the installed package for verification.                                                                 | package.checksum                  | FALSE  |
| package.description               | keyword | Description of the package.                                                                                         | package.description               | FALSE  |
| package.install_scope             | keyword | Indicating how the package was installed, e.g. user-local, global.                                                  | package.install_scope             | FALSE  |
| package.installed                 | date    | Time when package was installed.                                                                                    | package.installed                 | FALSE  |
| package.license                   | keyword | Package license.                                                                                                    | package.license                   | FALSE  |
| package.name                      | keyword | Package name.                                                                                                       | package.name                      | FALSE  |
| package.path                      | keyword | Path where the package is installed.                                                                                | package.path                      | FALSE  |
| package.reference                 | keyword | Package home page or reference URL.                                                                                 | package.reference                 | FALSE  |
| package.size                      | long    | Package size in bytes.                                                                                              | package.size                      | FALSE  |
| package.type                      | keyword | Package type.                                                                                                       | package.type                      | FALSE  |
| package.version                   | keyword | Package version.                                                                                                    | package.version                   | FALSE  |
| vulnerability.category            | keyword | Category of a vulnerability.                                                                                        | vulnerability.category            | FALSE  |
| vulnerability.classification      | keyword | Classification of the vulnerability.                                                                                | vulnerability.classification      | FALSE  |
| vulnerability.description         | keyword | Description of the vulnerability.                                                                                   | vulnerability.description         | FALSE  |
| vulnerability.detected_at         | date    | Vulnerability's detection date.                                                                                     | vulnerability.detected_at         | TRUE   |
| vulnerability.enumeration         | keyword | Identifier of the vulnerability.                                                                                    | vulnerability.enumeration         | FALSE  |
| vulnerability.id                  | keyword | ID of the vulnerability.                                                                                            | vulnerability.id                  | FALSE  |
| vulnerability.published_at        | date    | Vulnerability's publication date.                                                                                   | vulnerability.published_at        | TRUE   |
| vulnerability.report_id           | keyword | Scan identification number.                                                                                         | vulnerability.report_id           | FALSE  |
| vulnerability.scanner.condition   | keyword | The condition matched by the package that led the scanner to consider it vulnerable.                                | vulnerability.scanner.condition   | TRUE   |
| vulnerability.scanner.reference   | keyword | Scanner's resource that provides additional information, context, and mitigations for the identified vulnerability. | vulnerability.scanner.reference   | TRUE   |
| vulnerability.scanner.source      | keyword | The origin of the decision of the scanner (AKA feed used to detect the vulnerability).                              | vulnerability.scanner.source      | TRUE   |
| vulnerability.scanner.vendor      | keyword | Name of the scanner vendor.                                                                                         | vulnerability.scanner.vendor      | FALSE  |
| vulnerability.score.base          | float   | Vulnerability Base score.                                                                                           | vulnerability.score.base          | FALSE  |
| vulnerability.score.environmental | float   | Vulnerability Environmental score.                                                                                  | vulnerability.score.environmental | FALSE  |
| vulnerability.score.temporal      | float   | Vulnerability Temporal score.                                                                                       | vulnerability.score.temporal      | FALSE  |
| vulnerability.score.version       | keyword | CVSS version.                                                                                                       | vulnerability.score.version       | FALSE  |
| vulnerability.severity            | keyword | Severity of the vulnerability.                                                                                      | vulnerability.severity            | FALSE  |
| vulnerability.under_evaluation    | boolean | Indicates if the vulnerability is awaiting analysis by the NVD.                                                     | vulnerability.under_evaluation    | TRUE   |
| wazuh.cluster.name                | keyword | Wazuh cluster name.                                                                                                 | wazuh.cluster.name                | TRUE   |
| wazuh.cluster.node                | keyword | Wazuh cluster node name.                                                                                            | wazuh.cluster.node                | TRUE   |
| wazuh.schema.version              | keyword | Wazuh schema version.                                                                                               | wazuh.schema.version              | TRUE   |
| checksum                          | keyword | SHA1 hash used as checksum of the data collected by the agent.                                                      | checksum.hash.sha1                | TRUE   |
