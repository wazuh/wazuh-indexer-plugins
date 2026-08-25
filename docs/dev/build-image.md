# How to generate a container image

This guide includes instructions to generate distribution packages locally using Docker.

Wazuh Indexer supports any of these combinations:

- distributions: `['tar', 'deb', 'rpm']`
- architectures: `['x64', 'arm64']`

Windows is currently not supported.

> For more information navigate to the [compatibility section](/ref/compatibility.html).

Before you get started, make sure to clean your environment by running `./gradlew clean` on the **root level** of the `wazuh-indexer` repository.

## Prerequisites

The process to build packages requires Docker and Docker Compose.

- [Install Docker](https://docs.docker.com/engine/install/)
- [Install Docker Compose](https://docs.docker.com/compose/install/linux/)

Your workstation must meet the minimum hardware requirements (the more resources the better):

   - 8 GB of RAM (minimum)
   - 4 cores

The tools and source code to generate a package of Wazuh Indexer are hosted in the [wazuh-indexer](https://github.com/wazuh/wazuh-indexer) repository, so clone it if you haven't done already.

## Building wazuh-indexer Docker images

The [docker](./docker) folder contains the code to build Docker images. Below there is an example of the command needed to build the image. Set the build arguments and the image tag accordingly.

The Docker image is built from a wazuh-indexer tarball (tar.gz), which must be placed in `wazuh-indexer/build-scripts/docker` and named following the convention `wazuh-indexer-<arch>.tar.gz`, where `<arch>` matches Docker's architecture naming (`amd64` or `arm64`).

```bash
# Copy and rename the tarball to the expected name (from wazuh-indexer/build-scripts/docker)
cp wazuh-indexer_<version>-<revision>_linux-x64.tar.gz wazuh-indexer-amd64.tar.gz

# Build the image
docker build --build-arg="VERSION=<version>" --tag=wazuh-indexer:<version>-<revision> --progress=plain --no-cache .
```

Then, start a container with:

```bash
docker run -p 9200:9200 -it --rm wazuh-indexer:<version>-<revision>
```

The `build-and-push-docker-image.sh` script automates the process to build and push Wazuh Indexer Docker images to our repository in quay.io. The script takes several parameters. Use the `-h` option to display them.

To push images, credentials must be set at environment level:

- QUAY_USERNAME
- QUAY_TOKEN

```bash
Usage: build-scripts/build-and-push-docker-image.sh [args]

Arguments:
-a ARCHITECTURE [Optional] Target architecture (amd64 or arm64), default is host arch.
-r REVISION     [Optional] Revision qualifier, default is 0.
-h help
```

The script will stop if the credentials are not set, or if the expected tarball is not found.

This script is used in the `5_builderpackage_docker.yml` **GitHub Workflow**, which is used to automate the process even more. When possible, **prefer this method**.

**Note**: all the scripts under the `ci` folder are used in the GitHub workflows and are not intended to be used manually..
