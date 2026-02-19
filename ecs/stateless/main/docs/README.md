## Wazuh template for stateless indices

This is the **base template** for all stateless indices. It contains the complete set of Elastic Common Schema (ECS) fields and serves as the foundation to avoid duplication across other stateless index types.

All other stateless index templates inherit and reference the field definitions from this template to maintain consistency and reduce redundancy across the creation of the indices process.

### Fields summary

For this stage, we are using all the fields of the ECS. Dynamic mode is temporarily set to `false` to avoid the creation of new fields while allowing the indexing of events containing fields not in the schema. These fields can be retrieved from the original event (`_source`).

- [ECS main mappings](https://github.com/elastic/ecs/blob/v9.1.0/schemas/subsets/main.yml)

The detail of the fields can be found in csv file [Stateless Fields](fields.csv).

### WCS-specific fields

The Wazuh Common Schema (WCS) extends ECS with additional field sets specific to Wazuh's security monitoring capabilities. The following sections describe the custom additions.

#### `wazuh` — Wazuh agent and platform metadata

Core field set for Wazuh-specific context. Contains agent identity and host details (`wazuh.agent.*`), cluster topology (`wazuh.cluster.*`), integration metadata linking events to their source integration, decoders, and rules (`wazuh.integration.*`), ingestion protocol details (`wazuh.protocol.*`), and schema versioning (`wazuh.schema.*`).

#### `check` and `policy` — SCA (Security Configuration Assessment)

The `check` field set stores the results of SCA policy checks, including the check's condition, result, remediation steps, and rationale. Each check can reference multiple compliance frameworks through `check.compliance.<framework>`, where each framework object follows a uniform schema with `name`, `version`, `category`, `publisher`, and `requirements` fields. Supported frameworks: CMMC, FedRAMP, GDPR, HIPAA, ISO 27001, MITRE ATT&CK, NIS2, NIST 800-53, NIST 800-171, PCI DSS, and TSC.

The `policy` field set stores the SCA policy metadata (id, name, description, file, references) that groups related checks together.

#### `compliance` — Event-level compliance mapping

A top-level `compliance` field set that mirrors the same framework structure as `check.compliance` but applies at the event level rather than within an SCA check context. This allows any event — not just SCA results — to be tagged with the compliance frameworks it relates to. Same supported frameworks and schema as above.

#### `enrichments` — Threat intelligence enrichments

Extends the ECS `threat` model with fields for threat intelligence indicator enrichment. Contains standard indicator fields (`enrichments.indicator.*` — confidence, first/last seen, name, provider, type, reference) and custom fields (`enrichments.custom.*`) for vendor-specific attributes such as malware family, tags, and threat type classification. The `enrichments.source` field identifies the external provider that supplied the indicator.

#### `host` extensions — Hardware and network metrics

Extends the ECS `host` field set with hardware inventory fields: CPU details (`host.cpu.cores`, `host.cpu.name`, `host.cpu.speed`), memory stats (`host.memory.total`, `host.memory.free`, `host.memory.used.percentage`), and per-interface network counters for drops, errors, and queue lengths (`host.network.ingress.*`, `host.network.egress.*`).

#### `interface` and `network` extensions — Network interface inventory

The `interface` field set adds network interface inventory fields (alias, id, name, type, state, MTU). The `network` field set is extended with addressing fields (broadcast, gateway, netmask) and DHCP/metric information.

#### `observer` extensions — Observer interface details

Extends observer ingress/egress interface fields with MTU, state, and type information, complementing the ECS observer model.

#### `event` extensions

Two additional event fields: `event.changed_fields` (fields updated since the last scan) and `event.collector` (collector used to retrieve the event).

#### `agent.groups`

Adds a `groups` field to the ECS `agent` field set, representing the list of groups the agent belongs to.

#### `vulnerability.scanner.reference`

Extends the ECS `vulnerability` field set with a scanner reference URL pointing to additional information and mitigations for the identified vulnerability.
