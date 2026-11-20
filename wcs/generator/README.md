# Wazuh Common Schema generator

The generation of the Wazuh Common Schema is automated using a set of scripts and Docker projects.

- [compose.yml](./compose.yml): Docker Compose file to define the services for the schema generator.
- [generate_schema.sh](./generate_schema.sh): generates the complete schema. The list of modules to generate is read from the [module_list.txt](../module_list.txt) file. Copies the generated files to the appropriate folders. The index templates are copied to Setup plugin's [resources/](../../plugins/setup/src/main/resources/) folder, while the CSV files are copied to each module's `docs/` folder. For the `stateless/events/main` and `stateless/events/findings` modules, it also converts the copied template to `dynamic_templates` via `convert_to_dynamic_templates.py`. For every regenerated module it then re-derives `index.query.default_field` from the module's own mapping via `generate_default_query_fields.py`.
- [push_schema.sh](./push_schema.sh): commits and pushes the changes in the schema to the repository. This script is meant to be used by our GH Workflow. Do not use it locally.
- [run_generator.sh](./run_generator.sh): Script to start the Docker Compose project. This is the main entry point for the schema generation.
- [update_module_list.sh](./update_module_list.sh): generates the [module_list.txt](../module_list.txt) file, by scanning the [wcs/](..) folder. Run this script whenever a new module is added.
- [images/Dockerfile](./images/Dockerfile): Dockerfile to build the image used for the schema generation. Clones the ECS repository, which contains the main tooling.
- [images/generator.sh](./images/generator.sh): our actual schema generation script. It is executed inside the container. Contains post-processing steps to make the templates compatible with OpenSearch and to adapt them to our needs. Its `EXCLUDED_FIELDS` list holds the fields to remove from every module, used to drop the unwanted copies of a custom field.
- [images/schema_sanitizer.py](./images/schema_sanitizer.py): Python script that modifies the ECS source mapping files to meet WCS requirements before generating the final templates. It is executedi in the image build process.
- [count_and_update_total_fields.sh](./count_and_update_total_fields.sh): counts fields in a generated index template and proposes (or applies with --apply) an updated mapping.total_fields.limit rounded up to the next 500.
- [convert_to_dynamic_templates.py](./convert_to_dynamic_templates.py): converts a generated index template's monolithic static `properties` block into a `dynamic_templates` array, so fields are mapped lazily on first ingest instead of all at once. Used to keep the field mapping count of the `wazuh-events` and `wazuh-findings` data streams (`stateless/events/main` and `stateless/events/findings` modules) under the `mapping.total_fields.limit`, since those streams define far more fields than any single document actually uses. `generate_schema.sh` runs it automatically for those two modules; see "Dynamic templates" below.
- [generate_default_query_fields.py](./generate_default_query_fields.py): rewrites a module's `index.query.default_field` from the mapping the same template declares, so the list cannot name a field the index does not have, a field no text term can match, or an entry with stray whitespace. `generate_schema.sh` runs it automatically for every regenerated module; see "Default query fields" below.
- [stamp_schema_versions.py](./stamp_schema_versions.py): writes the `schema_version` and `compat_version` a module declares in `fields/mapping-settings.json` into its generated template, as the template's `version` and under `mappings._meta.wazuh`. `generate_schema.sh` runs it automatically for every regenerated module; see "Schema versions" below.
- [check_schema_versions.py](./check_schema_versions.py): compares every generated template with the base branch, classifies the change as compatible or breaking, and fails when the schema versions do not match. Run by the GitHub workflow on every pull request; see "Schema versions" below.

### Requirements

- [Docker Compose](https://docs.docker.com/compose/install/)
- [Python 3](https://www.python.org/) (for `convert_to_dynamic_templates.py`, `generate_default_query_fields.py` and `count_and_update_total_fields.sh`)

### Usage

The generator is run automatically by our GH Workflow on pull requests that modify any of the modules.
However, it can also be run locally. To do so, follow these steps.

1. Update the modules list:

    ```bash
    ./update_module_list.sh
    ```

2. Run the generator for all modules:

    ```bash
    ./generate_schema.sh
    ```

    This also converts the `stateless/events/main` and `stateless/events/findings` templates to `dynamic_templates` (see "Dynamic templates" below) when either module is regenerated.

3. Update the number of total field of each module:
    ``` bash
    ./count_and_update_total_fields.sh all --apply
    ```

`generate_schema.sh` already re-derives the default query fields of every module it regenerates
(see "Default query fields" below). To re-derive them for every module regardless of what changed,
which is also how to check that none has drifted:

```bash
python3 generate_default_query_fields.py all
python3 generate_default_query_fields.py all --check
```

The scripts can be invoked from any location. When successful, all the generated files will be copied to their corresponding folders.

A new `mappings` folder will be created inside the module's folder, containing all the generated files.
The files are versioned using the ECS version, so different versions of the same module can be generated.
For our use case, the most important files are under `mappings/<ECS_VERSION>/generated/elasticsearch/legacy/`:

- `template.json`: Elasticsearch compatible index template for the module
- `opensearch-template.json`: OpenSearch compatible index template for the module

The original output is `template.json`, which is not compatible with OpenSearch by default.
In order to make this template compatible with OpenSearch, the following changes are made:

- The `order` property is renamed to `priority`.
- The `mappings` and `settings` properties are nested under the `template` property.

The tooling takes care of these changes automatically, generating the `opensearch-template.json` file as a result.

If a module has been removed from the repository, the `generate_schema.sh` script will skip it gracefully, issuing a warning message instead of failing.

### Dynamic templates

The `wazuh-events` and `wazuh-findings` data streams (`stateless/events/main` and `stateless/events/findings` modules) cover a very large surface of possible fields, but any single document only ever populates a small subset of them. Mapping every field statically at index-template level counts all of them towards `mapping.total_fields.limit` right away, which can exhaust the limit before any real data is ingested.

To avoid this, [convert_to_dynamic_templates.py](./convert_to_dynamic_templates.py) rewrites the generated template's static `properties` block into a `dynamic_templates` array (one `path_match` rule per field, keyed off the original mapping) plus a minimal `properties` scaffolding for the object structure. Field mappings are then created lazily, only when a document actually uses them, while still constraining each field to its intended type. A handful of fields (`@timestamp`, `labels`, `message`, `tags`) are kept as static `properties` rather than converted.

`generate_schema.sh` runs this conversion automatically, in place, on the copied `templates/streams/events.json` and `templates/streams/findings.json` files whenever `stateless/events/main` or `stateless/events/findings` is regenerated — no manual step is required. The conversion is idempotent: if a template already has `dynamic_templates` populated, the script leaves it unchanged.

To run it manually against an already-generated template:

```bash
python3 wcs/generator/convert_to_dynamic_templates.py input_template.json [output_template.json]
```

Omitting the output path prints the result to stdout instead of writing a file. To convert a template in place (as the pipeline does):

```bash
find plugins/setup/src/main/resources/templates/streams/ -name "events.json" -type f -exec python3 wcs/generator/convert_to_dynamic_templates.py {} {} \;
```

### Default query fields

`index.query.default_field` is the list of fields a `query_string` with no field qualifier searches. Hand-written lists drift away from the mapping they describe, and each way they drift breaks a search.

[generate_default_query_fields.py](./generate_default_query_fields.py) derives the list from the mapping the same template declares. It keeps only indexed fields of the text family (`keyword`, `text`, `match_only_text`, `wildcard`), trims every entry, and prefers the `wazuh.` prefixed field whenever a name exists both bare and under `wazuh.` - that is the branch the agent data populates, so `agent.id` becomes `wazuh.agent.id`.

How much of the mapping it uses depends on whether the mapping is closed:

- A **closed** mapping (`dynamic: strict` with no dynamic templates) describes every field the
  index can ever hold, so the list becomes the full set of its searchable text fields. This is the
  case of every `wazuh-states-*` template.
- An **open** mapping (`strict_allow_templates`, `dynamic: true`/`false`, or any mapping with
  dynamic templates) reaches far more fields than its `properties` block spells out - the
  `wazuh-events` and `wazuh-findings` streams reach over 1600 text fields through their dynamic
  templates, well past the 1024 field `indices.query.bool.max_clause_count` expansion limit a
  `query_string` is checked against, so listing them all would fail the very query the setting
  exists to serve. The curated list is kept instead, and each entry is only resolved against the
  mapping: trimmed, moved to its `wazuh.` twin when that is the reachable one, and dropped when it
  resolves to nothing searchable.

The derived list is written to the module's index template under `plugins/setup/src/main/resources/`
and back to the module's `fields/template-settings.json` and `fields/template-settings-legacy.json`,
so the next generation starts from the corrected list. Only the `query.default_field` array is
rewritten; the rest of each file is left byte for byte as it was. Templates that do not set
`query.default_field` are left alone - the script never adds the setting.

`generate_schema.sh` runs it for every regenerated module, after the `dynamic_templates`
conversion, so the events and findings lists resolve against the dynamic templates that ship. To
run it by hand for one module, or for all of them:

```bash
python3 wcs/generator/generate_default_query_fields.py stateful/fim/files
python3 wcs/generator/generate_default_query_fields.py all --verbose
```

`--check` reports what would change and exits non-zero if anything would, without writing, which
is how to assert in CI that no list has drifted from its mapping:

```bash
python3 wcs/generator/generate_default_query_fields.py all --check
```

### Schema versions

The Setup plugin creates the indices from these templates on the first boot of a cluster, and on later boots, after a package upgrade, it has to tell which of the existing indices no longer match the template that ships. A stored template only affects indices created afterwards, and a text comparison of live mappings against shipped ones cannot be trusted, so every template carries two version numbers instead, and every index created from it inherits them in its mapping metadata.

Each module declares them under `_meta.wazuh` in `fields/mapping-settings.json`, next to the rest of its mapping behaviour:

```json
{
  "dynamic": "strict",
  "date_detection": false,
  "_meta": {
    "wazuh": {
      "schema_version": 50000,
      "compat_version": 50000
    }
  }
}
```

- `schema_version` is the release that last changed the mappings or settings of the template.
- `compat_version` is the oldest `schema_version` whose indices can still be upgraded in place. It is equal to `schema_version` when the last change was breaking.

Both are release numbers: one digit for the major and two digits each for the minor and the patch, so that numeric order matches release order. A template that does not change in a release keeps its previous values.

| Release | major | minor | patch | number |
|---|---|---|---|---|
| 5.0.0 | 5 | 00 | 00 | 50000 |
| 5.2.0 | 5 | 02 | 00 | 50200 |
| 5.2.1 | 5 | 02 | 01 | 50201 |
| 5.10.14 | 5 | 10 | 14 | 51014 |

The generator copies `_meta` into the mappings of the generated template, and `stamp_schema_versions.py` completes it with the native `version` field of the template, which the generator does not produce, so the template ends up carrying both:

```json
"_meta": { "wazuh": { "schema_version": 50300, "compat_version": 50200 } }
```

An index carrying `schema_version: 50200` can be upgraded in place to this template; one carrying `50000` or `50100` must be rebuilt. The Setup plugin refuses to start on a template without the two fields, so hand-written templates under `plugins/setup/src/main/resources/templates/` must declare them too.

**When to change them.** The release the branch targets is the `version` of `VERSION.json`.

- If the change touches the mappings or settings of the module, set `schema_version` to the number of the release the branch targets. If an earlier change in the same release cycle already set it, leave it: two changes in one cycle carry the same number.
- If the change is breaking, set `compat_version` to the same number. Breaking means: a field removed, a field type changed, any other non-updatable parameter of an existing field changed, an analyzer or normalizer changed, a static index setting changed (`number_of_shards`, `codec`), or the index patterns or the data stream flag changed.
- If the change only adds fields, multi-fields or dynamic templates, or changes a dynamic setting (`refresh_interval`, `number_of_replicas`, `query.default_field`, the field limits, the ISM policy), leave `compat_version` as it is.

`check_schema_versions.py` enforces these rules on every pull request. It diffs each regenerated template against the base branch, classifies the change, and fails when the versions do not match: a changed template without the target `schema_version`, a breaking change without the matching `compat_version`, a compatible change that moved `compat_version`, or a template whose stamped versions differ from its `mapping-settings.json` because it was not regenerated. A version change without a template change is only a warning. The classification of every template is written to the job summary. To run it locally, from the repository root, against the branch the pull request targets:

```bash
python3 wcs/generator/check_schema_versions.py --base origin/5.0.0
python3 -m unittest discover -s wcs/generator/tests
```

Two builds of the same unreleased version carry the same numbers, so a template change between a release candidate and the final release, or between two nightly builds, is not detected: upgrades between pre-release builds are not supported.

### Uploading templates to the Indexer

You can either upload the index template using cURL or the UI (dev tools).

```bash
curl -u admin:admin -k -X PUT "https://indexer:9200/_index_template/wazuh-states-vulnerabilities" -H "Content-Type: application/json" -d @opensearch-template.json
curl -u admin:admin -k -X PUT "https://indexer:9200/template/wazuh-states-vulnerabilities" -H "Content-Type: application/json" -d @template.json
```

Notes:
- PUT and POST are interchangeable.
- The name of the index template does not matter. Any name can be used.
- Adjust credentials and URL accordingly.

### Creating new modules

The easiest way to create a new module is to take an existing one as a base. Copy a similar module and renaming it. Then, edit the `fields` files to match the new module fields.

The name of the folder will be the name of the module to be passed to the script. All 4 files are required.

- `fields/subset.yml`: This file contains the subset of ECS fields to be used for the module.
- `fields/template-settings-legacy.json`: This file contains the legacy template settings for the module.
- `fields/template-settings.json`: This file contains the composable template settings for the module.
- `fields/mapping-settings.json`: This file contains the mapping behaviour of the module (`dynamic`, `date_detection`) and, under `_meta.wazuh`, its `schema_version` and `compat_version`, both set to the release that adds it (see "Schema versions" above).
- `fields/custom`: folder containg custom fields for the module. This folder is optional.

> [!IMPORTANT]
> Add the new module to the [SetupPlugin.java](../../plugins/setup/src/main/java/com/wazuh/setup/SetupPlugin.java) file, so it is included in the installation process.

## Event generators

Each module contains a Python script to generate events for its module. The script prompts for the required parameters, so it can be launched without arguments:

```bash
./event_generator.py
```

The script will generate a JSON file with the events, and will also ask whether to upload them to the indexer. If the upload option is selected, the script will ask for the indexer URL and port, credentials, and index name.
The script uses log file. Check it out for debugging or additional information.

The [run_event_generators.sh](../scripts/run_event_generators.sh) script can be used to run all the event generators in sequence. It will prompt for the indexer details only once, and will use them for all the modules.

## GitHub Workflow

The schema generation is automated using a GitHub Workflow, defined in the [5_builderpackage_schema.yml](../../.github/workflows/5_builderpackage_schema.yml) file. After regenerating the modified modules it runs `check_schema_versions.py` (see "Schema versions" above) and pushes the regenerated templates to the pull request branch only if the check passes.

## Troubleshooting

1. In case you added a new module and the script is not recognizing it, make sure to run the `update_module_list.sh` script to update the modules list **AND** to stage the changes in Git, as the script compares the current Git working directory with the last state in main.
