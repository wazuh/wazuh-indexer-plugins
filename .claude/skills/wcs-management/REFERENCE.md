# WCS module reference

Companion to `SKILL.md`. Copy-paste templates and the internals you need to
author WCS inputs correctly.

## Module anatomy

```
wcs/<family>/<module>/
├── docs
│   ├── fields.csv          # GENERATED — do not edit
│   └── README.md           # hand-written (see README rules)
├── event-generator
│   └── event_generator.py  # hand-written; hyphen dir is the convention
└── fields
    ├── custom
    │   └── <object>.yml     # custom fields grouped by object (wazuh.yml, state.yml, ...)
    ├── mapping-settings.json
    ├── subset.yml
    ├── template-settings.json
    └── template-settings-legacy.json
```

Everything under `wcs/<module>/mappings/**` is generated output (ECS tooling
writes `beats/`, `csv/`, `ecs/`, `elasticsearch/composable/`,
`elasticsearch/legacy/`). Never edit it.

Reference module to imitate: `wcs/stateful/vulnerabilities/` (rich custom
fields) and `wcs/cve/` (custom-object nesting + the short README style).

## `subset.yml`

Declares which ECS objects/fields (and custom objects) the module includes.
`fields: "*"` pulls the whole object; a nested `fields:` map cherry-picks.

```yaml
---
name: wazuh-<family>-<module>        # subset name; drives the generated subset path
fields:
  base:
    fields:
      message: {}                  # single ECS field
  package:
    fields: "*"                    # entire ECS object
  host:
    fields:
      os:
        fields:
          full: ""
          name: ""
          version: ""
  vulnerability:
    fields:
      id: {}
      severity: {}
      score:
        fields:
          base: {}
          version: {}
  state:
    fields: "*"                    # a custom object defined in fields/custom/state.yml
  wazuh:
    fields:
      cluster:
        fields: "*"
      schema:
        fields: "*"
```

A custom object (one you define under `fields/custom/`) must also be listed in
`subset.yml`, or the generator will not include it.

## `fields/custom/<object>.yml`

ECS-style field group. One file per object; the filename is the object name.

Simple custom object (`state.yml`, `checksum.yml`, `wazuh.yml` pattern):

```yaml
---
- name: state
  title: State
  description: >
    State custom fields
  fields:
    - name: modified_at
      type: date
      level: custom
      description: >
        Date/time when the state was last modified.
    - name: document_version
      type: integer
      level: custom
      description: >
        Version of the document.
```

Dotted sub-paths are allowed in a single entry (`wazuh.yml`):

```yaml
---
- name: wazuh
  title: Wazuh
  description: >
    Wazuh Inc. custom fields
  fields:
    - name: cluster.name
      type: keyword
      level: custom
      description: >
        Wazuh cluster name.
    - name: schema.version
      type: keyword
      level: custom
      description: >
        Wazuh schema version.
```

**Reusable / remap mechanism** — how ECS `agent.*` ends up as `wazuh.agent.*`
(this is what the "Destination Field" column of a module README records). The
`reusable.expected` block nests the object under another:

```yaml
---
- name: agent
  reusable:
    expected:
      - { at: wazuh, as: agent }   # agent.* is mapped under wazuh.agent.*
  title: Wazuh Agents
  short: Wazuh Inc. custom fields.
  type: group
  group: 2
  fields:
    - name: groups
      type: keyword
      level: custom
      description: >
        List of groups the agent belongs to.
      normalize:
        - array
      example: "[\"group1\", \"group2\"]"
```

Field entry keys you'll use: `name`, `type` (`keyword`, `date`, `integer`,
`long`, `float`, `boolean`, `date_nanos`, …), `level: custom`, `description`
(folded `>`), optional `normalize: [array]`, `example`.

**Short description limit (generator will fail otherwise):** the ECS generator
derives a `short` description from `description`, and `short` must be a single
line **≤ 120 characters**. A long or multi-line `description` with no explicit
`short` overflows that limit and the generation **fails**. Whenever a
`description` is long or spans multiple lines, add a one-line `short:` summary
alongside it:

```yaml
    - name: turns
      type: object
      level: custom
      short: Conversation turns, stored verbatim to reconstruct the chat in the UI.
      description: >
        Conversation turns (author and content, plus any other data returned by
        the AI provider). Shape varies by provider, so the object is unmapped:
        stored in _source and returned as-is, but neither indexed nor searchable.
```

Keep `short` under 120 chars. This applies to both field entries and the
group-level `description`/`short` at the top of a `custom/<object>.yml`.

## `fields/mapping-settings.json`

Almost always:

```json
{
    "dynamic": "strict",
    "date_detection": false
}
```

## `fields/template-settings.json` (composable)

`priority`, and settings nested under `template.settings`:

```json
{
  "index_patterns": ["wazuh-<family>-<module>*"],
  "priority": 1,
  "template": {
    "settings": {
      "index": {
        "codec": "zstd",
        "gc_deletes": "15s",
        "number_of_shards": "1",
        "number_of_replicas": "0",
        "auto_expand_replicas": "0-1",
        "refresh_interval": "2s",
        "query.default_field": [
          "package.name",
          "vulnerability.id",
          "wazuh.cluster.name"
        ]
      }
    }
  }
}
```

## `fields/template-settings-legacy.json` (legacy)

Same values, different shape: `order` instead of `priority`, and `settings` at
the **top level** (not nested under `template`):

```json
{
  "index_patterns": ["wazuh-<family>-<module>*"],
  "order": 1,
  "settings": {
    "index": {
      "codec": "zstd",
      "gc_deletes": "15s",
      "number_of_shards": "1",
      "number_of_replicas": "0",
      "auto_expand_replicas": "0-1",
      "refresh_interval": "2s",
      "query.default_field": [
        "package.name",
        "vulnerability.id",
        "wazuh.cluster.name"
      ]
    }
  }
}
```

Keep the two files in sync: `priority` ↔ `order`, and identical
`index_patterns` / index settings / `query.default_field`.

## README rules

**Avoid mentioning ECS / Elastic Common Schema; say WCS (Wazuh Common Schema)**.
Keep it short and redirect the detail to `fields.csv`. Model on `wcs/cve/docs/README.md`:

```markdown
## `wazuh-<index-name>` index data model

### Fields summary

The fields are based on <one line + link to the source issue/spec>.

The detail of the fields can be found in csv file [<Name> Fields](fields.csv).
```

Do **not** reproduce the older, verbose `stateful/vulnerabilities/docs/README.md`
(long ECS link list + full transition table) — that predates the rule.

## Generator internals worth knowing

- **`ECS_VERSION`** defaults to `v9.1.0` (`generate_schema.sh`); generated
  output is versioned under `mappings/<ECS_VERSION>/`.
- **Module → destination map** lives in `wcs/module_list.txt`, produced by
  `update_module_list.sh`. Most modules map to a bare filename copied under
  `plugins/setup/src/main/resources/templates/`.
- **`internal-state`** is the exception: its generated template goes to
  `plugins/content-manager/src/main/resources/mappings/internal-state-mapping.json`
  (consumed by content-manager's CredentialsIndex), not to setup.
- **Dynamic-template modules**: `stateless/events/main` and
  `stateless/events/findings` are auto-converted from static `properties` to
  `dynamic_templates` by `convert_to_dynamic_templates.py` inside
  `generate_schema.sh` (keeps `mapping.total_fields.limit` from exhausting).
  Editing `events/main` also triggers regeneration of all `stateless/events/*`.
- **`EXCLUDED_FIELDS`** in `wcs/generator/images/generator.sh` drops unwanted
  duplicate copies of a custom field from every module.
- **`schema_sanitizer.py`** (`images/`) rewrites ECS source mappings to WCS
  requirements at image-build time.
- **OpenSearch compatibility**: the tooling renames `order`→`priority` and
  nests `mappings`/`settings` under `template`, emitting
  `elasticsearch/legacy/opensearch-template.json` (the file copied to setup).

## Gotchas checklist

- **Generated files** — never hand-edit `mappings/**`,
  `plugins/setup/.../resources/templates/**`, `docs/fields.csv`,
  `internal-state-mapping.json`.
- **git detection** — `generate_schema.sh` diffs against `origin/main`; edits
  must be in the working tree, and a new module's files + regenerated
  `module_list.txt` must be **staged** or the module is invisible to the
  generator.
- **Two settings files** — `template-settings.json` and
  `-legacy.json` must carry the same values in their two shapes.
- **Limits are computed** — never hand-set `total_fields.limit` /
  `nested_fields.limit` / `max_docvalue_fields_search`; run
  `count_and_update_total_fields.sh` after generation.
- **New module wiring** — required: `subset.yml`+`custom/` inputs and the
  `update_module_list.sh` mapping (if not auto directory-scanned; needed for
  generation). Optional: `SetupPlugin.java` registration — the runtime-install
  step, done by default but the user may opt out ("I'll do the code").
- **Short description ≤ 120 chars** — a long/multi-line `description` without a
  single-line `short:` overflows the ECS `short` limit and **fails
  generation**; add a `short:` one-liner (see `custom/<object>.yml` above).
- **Docker required** — `generate_schema.sh` builds/runs a container that
  clones the ECS repo; no Docker means no generation.
