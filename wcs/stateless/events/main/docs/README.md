## Wazuh template for stateless indices

This is the **base template** for all stateless indices. It contains the complete set of Elastic Common Schema (ECS) fields and serves as the foundation to avoid duplication across other stateless index types.

All other stateless index templates inherit and reference the field definitions from this template to maintain consistency and reduce redundancy across the creation of the indices process.

### Fields summary

For this stage, we are using all the fields of the ECS. The mapping is `strict_allow_templates`: every field is mapped through a dynamic template the first time a document uses it, and a document carrying a field outside the schema is rejected.

- [ECS main mappings](https://github.com/elastic/ecs/blob/v9.1.0/schemas/subsets/main.yml)

The detail of the fields can be found in csv file [Stateless Fields](fields.csv). The [Wazuh Common Schema](https://wazuh.github.io/wazuh-indexer-plugins/ref/modules/setup/schema.html) page of the documentation explains how Wazuh fills the key fields of events and findings.

### WCS-specific fields

The Wazuh Common Schema (WCS) extends ECS with additional field sets specific to Wazuh's security monitoring capabilities. The following sections describe the custom additions.

#### `wazuh` — Wazuh agent and platform metadata

Core field set for Wazuh-specific context, set by Wazuh components rather than parsed from the log. Contains agent identity and host details (`wazuh.agent.*`), the identifier of the received log shared by its raw event, normalized event and findings (`wazuh.event.id`), cluster topology (`wazuh.cluster.*`), integration metadata linking events to their source integration and decoders (`wazuh.integration.*`), the policy space that processed the event (`wazuh.space.*`), ingestion protocol details (`wazuh.protocol.*`), and schema versioning (`wazuh.schema.*`).

#### `check` and `policy` — SCA (Security Configuration Assessment)

The `check` field set stores the results of SCA policy checks, including the check's condition, result, remediation steps, and rationale. Each check can reference multiple compliance frameworks through `check.compliance.<framework>`, where each framework object follows a uniform schema with `name`, `version`, `category`, `publisher`, and `requirements` fields. Supported frameworks: CMMC, FedRAMP, GDPR, HIPAA, ISO 27001, MITRE ATT&CK, NIS2, NIST 800-53, NIST 800-171, PCI DSS, and TSC.

The `policy` field set stores the SCA policy metadata (id, name, description, file, references) that groups related checks together.

#### `compliance` — Event-level compliance mapping

A top-level `compliance` field set that mirrors the same framework structure as `check.compliance` but applies at the event level rather than within an SCA check context. This allows any event — not just SCA results — to be tagged with the compliance frameworks it relates to. Same supported frameworks and schema as above.

#### `host` extensions — Hardware and network metrics

Extends the ECS `host` field set with hardware inventory fields: CPU details (`host.cpu.cores`, `host.cpu.name`, `host.cpu.speed`), memory stats (`host.memory.total`, `host.memory.free`, `host.memory.used.percentage`), and per-interface network counters for drops, errors, and queue lengths (`host.network.ingress.*`, `host.network.egress.*`).

#### `interface` and `network` extensions — Network interface inventory

The `interface` field set adds network interface inventory fields (alias, id, name, type, state, MTU). The `network` field set is extended with addressing fields (broadcast, gateway, netmask) and DHCP/metric information.

#### `observer` extensions — Observer interface details

Extends observer ingress/egress interface fields with MTU, state, and type information, complementing the ECS observer model.

#### `event` extensions

Four additional event fields: `event.changed_fields` (fields updated since the last scan), `event.collector` (collector used to retrieve the event), and `event.doc_id` and `event.index`, which a finding uses to point to the `_id` and backing index of the event that matched the rule.

#### Wazuh descriptions of ECS fields

Some ECS fields keep their ECS type but carry a Wazuh description, because Wazuh fills them in a specific way: `@timestamp` and `message` (`custom/base.yml`), `event.start`, `event.end`, `event.created`, `event.ingested`, `event.original` and `event.id` (`custom/event.yml`), and `rule.id` (`custom/rule.yml`). For example, `@timestamp` is the time the Wazuh Engine received the event, while the time found in the original log is in `event.start`.

#### `file.diff`

Extends the ECS `file` field set with the unified diff of a file's content changes, as reported by FIM when `report_changes` is enabled. It is only mapped on the root `file` object: the reuses of `file` under `threat.indicator`, `threat.enrichments.indicator` and their `wazuh.threat` counterparts are excluded by the generator (see `EXCLUDED_FIELDS` in `wcs/generator/images/generator.sh`).

#### `agent.groups`

Adds a `groups` field to the ECS `agent` field set, representing the list of groups the agent belongs to.

#### `vulnerability.scanner.reference`

Extends the ECS `vulnerability` field set with a scanner reference URL pointing to additional information and mitigations for the identified vulnerability.

#### `process.state` and `process.previous.*` — Process state changes

Adds `process.state` to capture the current process state as reported by the collector. Extends the ECS `process.previous` reuse (previously limited to `args`, `args_count`, and `executable`) with `pid`, `name`, `state`, `command_line`, and `parent.pid`, so a `modified` process event can express what changed from, not just what changed to (e.g. a service's PID after it restarts).

These `process.*` additions are also applied to `findings`: its `subset.yml` for `process` lists the same `state` and `previous.*` fields, keeping both stateless events streams at field parity.

`process.previous.args`, `.args_count`, and `.executable` are kept even though none of our collectors populate them today: they come for free as part of the same ECS `process.previous` reuse the fields above depend on, so dropping them would require patching the vendored ECS schema for no mapping-size benefit.

#### `service.previous.state`

Adds a `previous.state` field to the ECS `service` field set, capturing the service's state prior to a `modified` event (e.g. `RUNNING` before a restart).

Unlike `process.*` above, this field is not module-scoped: since `service` uses `fields: "*"` in every stateless events module's `subset.yml`, and the generator always folds this module's `fields/custom` into every other `stateless/events/*` module, `service.previous.state` (and its `service.origin`/`service.target` self-nested copies) also reaches `findings` automatically. This is a pre-existing architectural side effect, not a per-module decision.

#### `package.previous.installed`

Adds a `previous.installed` field to the ECS `package` field set, capturing the package's installation date prior to a `modified` event. Reaches `findings` the same way `service.previous.state` does, for the same reason (`package` also uses `fields: "*"`).
