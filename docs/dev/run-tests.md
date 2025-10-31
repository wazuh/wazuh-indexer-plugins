# How to run the tests

This section explains how to run the Wazuh Indexer tests.

### Full set of tests

To execute all kind of tests, use the command `./gradlew check`. This command does not only run tests, but also tasks to check the quality of the code, such as documentation and linter checks.

### Unit tests

To run unit tests, use the `./gradlew test` command.

### Integration tests

To run integration tests, use the `./gradlew integTest` and the `./gradlew yamlresttest` commands.

### Package testing

For package testing, we conduct smoke tests on the packages using the [GitHub Actions Workflows](https://github.com/wazuh/wazuh-indexer/blob/main/.github/workflows/5_builderpackage_indexer.yml). These tests consist on installing the packages on a supported operating system. DEB packages are installed in the “Ubuntu 24.04” runner executing the workflow, while RPM packages are installed in a Red Hat 9 Docker container, as there is no RPM compatible runner available in GitHub Actions.

As a last note, there is also a **Vagrantfile** and **testing scripts** in the [repository](https://github.com/wazuh/wazuh-indexer-plugins/tree/main/tools) to perform some tests on a real wazuh-indexer service running on a virtual machine. Refer to its README.md for more information about how to run these tests.
