# Wazuh Common Schema generator

The generation of the Wazuh Common Schema is automated using a set of scripts and Docker projects.

- [compose.yml](./compose.yml): Docker Compose file to define the services for the schema generator.
- [generate_schema.sh](./generate_schema.sh): generates the complete schema. The list of modules to generate is read from the [module_list.txt](../module_list.txt) file. Copies the generated files to the appropriate folders. The index templates are copied to Setup plugin's [resources/](../../plugins/setup/src/main/resources/) folder, while the CSV files are copied to each module's `docs/` folder.
- [push_schema.sh](./push_schema.sh): commits and pushes the changes in the schema to the repository. This script is meant to be used by our GH Workflow. Do not use it locally.
- [run_generator.sh](./run_generator.sh): Script to start the Docker Compose project. This is the main entry point for the schema generation.
- [update_module_list.sh](./update_module_list.sh): generates the [module_list.txt](../module_list.txt) file, by scanning the [ecs/](..) folder. Run this script whenever a new module is added.
- [images/Dockerfile](./images/Dockerfile): Dockerfile to build the image used for the schema generation. Clones the ECS repository, which contains the main tooling.
- [images/generator.sh](./images/generator.sh): our actual schema generation script. It is executed inside the container. Contains post-processing steps to make the templates compatible with OpenSearch and to adapt them to our needs.

### Requirements

- [Docker Compose](https://docs.docker.com/compose/install/)

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

The name of the folder will be the name of the module to be passed to the script. All 3 files are required.

- `fields/subset.yml`: This file contains the subset of ECS fields to be used for the module.
- `fields/template-settings-legacy.json`: This file contains the legacy template settings for the module.
- `fields/template-settings.json`: This file contains the composable template settings for the module.
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

The schema generation is automated using a GitHub Workflow, defined in the [5_builderpackage_schema.yml](../../.github/workflows/5_builderpackage_schema.yml) file.
