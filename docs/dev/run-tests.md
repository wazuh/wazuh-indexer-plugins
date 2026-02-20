# How to Run the Tests

This section explains how to run the Wazuh Indexer Plugins tests at various levels.

## Full Suite

To execute all tests and code quality checks (linting, documentation, formatting):

```bash
./gradlew check
```

This runs unit tests, integration tests, and static analysis tasks.

## Unit Tests

Run all unit tests across the entire project:

```bash
./gradlew test
```

Run unit tests for a specific plugin:

```bash
./gradlew :wazuh-indexer-content-manager:test
```

## Integration Tests

Run integration tests for a specific plugin:

```bash
./gradlew :wazuh-indexer-content-manager:integTest
```

## YAML REST Tests

Plugins can define REST API tests using YAML test specs. To run them:

```bash
./gradlew :wazuh-indexer-content-manager:yamlRestTest
```

## Reproducible Test Runs

Tests use randomized seeds. When a test fails, the output includes the seed that was used. To reproduce the exact same run:

```bash
./gradlew :wazuh-indexer-content-manager:test -Dtests.seed=DEADBEEF
```

Replace `DEADBEEF` with the actual seed from the failure output.

## Viewing Test Reports

After running tests, HTML reports are generated at:

```
plugins/<plugin-name>/build/reports/tests/test/index.html
```

Open this file in a browser to see detailed results with pass/fail status, stack traces, and timing.

For integration tests:

```
plugins/<plugin-name>/build/reports/tests/integTest/index.html
```

## Running a Single Test Class

To run a specific test class:

```bash
./gradlew :wazuh-indexer-content-manager:test --tests "com.wazuh.contentmanager.rest.service.RestPostRuleActionTests"
```

## Test Cluster (Vagrant)

For end-to-end testing on a real Wazuh Indexer service, the repository includes a Vagrant-based test cluster at [`tools/test-cluster/`](https://github.com/wazuh/wazuh-indexer-plugins/tree/main/tools/test-cluster). This provisions a virtual machine with Wazuh Indexer installed and configured.

Refer to its `README.md` for setup and usage instructions.

## Package Testing

Smoke tests on built packages are run via [GitHub Actions Workflows](https://github.com/wazuh/wazuh-indexer/blob/main/.github/workflows/5_builderpackage_indexer.yml). These install packages on supported operating systems:

- **DEB packages** — installed on the Ubuntu 24.04 GitHub Actions runner.
- **RPM packages** — installed in a Red Hat 9 Docker container.

## Useful Test Flags

| Flag | Description |
|---|---|
| `-Dtests.seed=<seed>` | Reproduce a specific randomized test run |
| `-Dtests.verbose=true` | Print test output to stdout |
| `--tests "ClassName"` | Run a single test class |
| `--tests "ClassName.methodName"` | Run a single test method |
| `-x test` | Skip unit tests in a build |
