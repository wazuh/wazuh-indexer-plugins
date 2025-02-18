# Packages generation

This guide includes instructions to generate distribution packages locally using Docker.

Wazuh Indexer supports any of these combinations:

- distributions: `['tar', 'deb', 'rpm']`
- architectures: `['x64', 'arm64']`

Windows is currently not supported.

> For more information navigate to the [compatibility section](/ref/compatibility.html).

The process to build packages requires Docker and Docker Compose.

- [Install Docker](https://docs.docker.com/engine/install/)
- [Install Docker Compose](https://docs.docker.com/compose/install/linux/)

Before you get started, make sure to clean your environment by running `./gradlew clean`.

## Pre-requisites

1. Install [Docker](https://docs.docker.com/engine/install/) as per its instructions.

2. Your workstation must meet the minimum hardware requirements:

   - 8 GB of RAM (minimum)
   - 4 cores

   The more resources the better ☺

3. Clone the [wazuh-indexer](https://github.com/wazuh/wazuh-indexer).

## Building wazuh-indexer packages

The `builder` image automates the build and assemble process for the Wazuh Indexer and its plugins, making it easy to create packages on any system.

Use the script under `wazuh-indexer/build-scripts/builder/builder.sh` to build a package.

```bash
./builder.sh -h
Usage: ./builder.sh [args]

Arguments:
-p INDEXER_PLUGINS_BRANCH     [Optional] wazuh-indexer-plugins repo branch, default is 'main'.
-r INDEXER_REPORTING_BRANCH   [Optional] wazuh-indexer-reporting repo branch, default is 'main'.
-R REVISION                   [Optional] Package revision, default is '0'.
-s STAGE                      [Optional] Staging build, default is 'false'.
-d DISTRIBUTION               [Optional] Distribution, default is 'rpm'.
-a ARCHITECTURE               [Optional] Architecture, default is 'x64'.
-D      Destroy the docker environment
-h      Print help
```

The example below it will generate a wazuh-indexer package for Debian based systems, for the x64 architecture, using 1 as revision number and using the production naming convention.

```bash
# Wihtin wazuh-indexer/build-scripts/builder
bash builder.sh -d deb -a x64 -R 1 -s true
```

The resulting package will be stored at `wazuh-indexer/artifacts/dist`.

> The `STAGE` option defines the naming of the package. When set to `false`, the package will be unequivocally named with the commits' SHA of the `wazuh-indexer`, `wazuh-indexer-plugins` and `wazuh-indexer-reporting` repositories, in that order. For example: `wazuh-indexer_5.0.0-0_x86_64_aff30960363-846f143-494d125.rpm`.
