# Build image
## Building wazuh-indexer Docker images

The [docker](./docker) folder contains the code to build Docker images. Below there is an example of the command needed to build the image. Set the build arguments and the image tag accordingly.

The Docker image is built from a wazuh-indexer tarball (tar.gz), which must be present in the same folder as the Dockerfile in `wazuh-indexer/build-scripts/docker`.

```bash
docker build --build-arg="VERSION=5.0.0" --build-arg="INDEXER_TAR_NAME=wazuh-indexer_5.0.0-0_linux-x64.tar.gz" --tag=wazuh-indexer:5.0.0-0 --progress=plain --no-cache .
```

Then, start a container with:

```bash
docker run -p 9200:9200 -it --rm wazuh-indexer:5.0.0-0
```

The `build-and-push-docker-image.sh` script automates the process to build and push Wazuh Indexer Docker images to our repository in quay.io. The script takes serveral parameters. Use the `-h` option to display them.

To push images, credentials must be set at environment level:

- QUAY_USERNAME
- QUAY_TOKEN

```bash
Usage: build-scripts/build-and-push-docker-image.sh [args]

Arguments:
-n NAME         [required] Tarball name.
-r REVISION     [Optional] Revision qualifier, default is 0.
-h help
```

The script will stop if the credentials are not set, or if any of the required parameters are not provided.

This script is used in the `build-push-docker-image.yml` **GitHub Workflow**, which is used to automate the process even more. When possible, **prefer this method**.
