# How to generate a package

This guide includes instructions to generate distribution packages locally using Docker.

Wazuh Indexer supports any of these combinations:

- distributions: `['tar', 'deb', 'rpm']`
- architectures: `['x64', 'arm64']`

Windows is currently not supported.

> For more information navigate to the [compatibility section](/ref/compatibility.html).

Before you get started, make sure to clean your environment by running `./gradlew clean` on the **root level** of the `wazuh-indexer` repository.

## Pre-requisites

The process to build packages requires Docker and Docker Compose.

- [Install Docker](https://docs.docker.com/engine/install/)
- [Install Docker Compose](https://docs.docker.com/compose/install/linux/)

Your workstation must meet the minimum hardware requirements (the more resources the better ☺):

   - 8 GB of RAM (minimum)
   - 4 cores

The tools and source code to generate a package of Wazuh Indexer are hosted in the [wazuh-indexer](https://github.com/wazuh/wazuh-indexer) repository, so clone it if you haven't done already.

## Building `wazuh-indexer` packages

The Docker environment under `wazuh-indexer/build-scripts/builder` automates the build and assemble process for the Wazuh Indexer and its plugins, making it easy to create packages on any system.

Use the `builder.sh` script to build a package.

```bash
./builder.sh -h
Usage: ./builder.sh [args]

Arguments:
-p INDEXER_PLUGINS_BRANCH       [Optional] wazuh-indexer-plugins repo branch, default is 'main'.
-r INDEXER_REPORTING_BRANCH     [Optional] wazuh-indexer-reporting repo branch, default is 'main'.
-s SECURITY_ANALYTICS_BRANCH    [Optional] wazuh-indexer-security-analytics repo branch, default is 'main'.
-R REVISION     [Optional] Package revision, default is '0'.
-S STAGE        [Optional] Staging build, default is 'false'.
-d DISTRIBUTION [Optional] Distribution, default is 'rpm'.
-a ARCHITECTURE [Optional] Architecture, default is 'x64'.
-D      Destroy the docker environment
-h      Print help
```

The example below it will generate a wazuh-indexer package for _Debian_ based systems, for the _x64_ architecture, using _1_ as revision number and using the production naming convention.

```bash
# Wihtin wazuh-indexer/build-scripts/builder
bash builder.sh -d deb -a x64 -R 1 -S true
```

The resulting package will be stored at `wazuh-indexer/artifacts/dist`.

> The `STAGE` option defines the naming of the package. When set to `false`, the package will be unequivocally named with the commits' SHA of the `wazuh-indexer`, `wazuh-indexer-plugins` and `wazuh-indexer-reporting` repositories, in that order. For example: `wazuh-indexer_5.0.0-0_x86_64_aff30960363-846f143-494d125.rpm`.
