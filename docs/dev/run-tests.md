# How to run the tests
This section explains how to run the Wazuh Indexer tests.

### End-to-end tests
To execute all tests, you can use the command `./gradlew check`.

### Unit tests
For running unit tests, it is necessary to use `./gradlew test` within the corresponding plugin folder.

### Integration tests
To launch integration tests, you can run `./gradlew integTest` and `./gradlew yamlresttest` within the corresponding plugin folder.

### Package testing
For package testing, we conduct smoke tests on the packages using the [GitHub Actions Workflows](https://github.com/wazuh/wazuh-indexer/blob/4.9.0/.github/workflows/build.yml). These tests consist on installing the packages on a supported operating system. DEB packages are installed in the “Ubuntu 24.04” runner executing the workflow, while RPM packages are installed in a Red Hat 9 Docker container, as there is no RPM compatible runner available in GitHub Actions.

As a last note, there is also a **Vagrantfile** and **testing scripts** in the [repository](https://github.com/wazuh/wazuh-indexer-plugins/tree/master/test-tools) to test packaging. Refer to the README.md for more information.
