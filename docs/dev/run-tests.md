# How to run the tests

This section explains how to run the Wazuh Indexer Plugins tests at various levels.

## Full suite

To execute all tests and code quality checks (linting, documentation, formatting):

```bash
./gradlew check
```

This runs unit tests, integration tests, and static analysis tasks.

## Unit tests

Run all unit tests across the entire project:

```bash
./gradlew test
```

Run unit tests for a specific plugin:

```bash
./gradlew :wazuh-indexer-content-manager:test
```

## Integration tests

Run integration tests for a specific plugin:

```bash
./gradlew :wazuh-indexer-content-manager:integTest
```

## YAML REST tests

Plugins can define REST API tests using YAML test specs. To run them:

```bash
./gradlew :wazuh-indexer-content-manager:yamlRestTest
```

## Reproducible test runs

Tests use randomized seeds. When a test fails, the output includes the seed that was used. To reproduce the exact same run:

```bash
./gradlew :wazuh-indexer-content-manager:test -Dtests.seed=DEADBEEF
```

Replace `DEADBEEF` with the actual seed from the failure output.

## Viewing test reports

After running tests, HTML reports are generated at:

```
plugins/<plugin-name>/build/reports/tests/test/index.html
```

Open this file in a browser to see detailed results with pass/fail status, stack traces, and timing.

For integration tests:

```
plugins/<plugin-name>/build/reports/tests/integTest/index.html
```

## Running a single test class

To run a specific test class:

```bash
./gradlew :wazuh-indexer-content-manager:test --tests "com.wazuh.contentmanager.rest.service.RestPostRuleActionTests"
```

## Test cluster (Vagrant)

For end-to-end testing on a real Wazuh Indexer service, the repository includes a Vagrant-based test cluster at [`tools/test-cluster/`](https://github.com/wazuh/wazuh-indexer-plugins/tree/main/tools/test-cluster). This provisions a virtual machine with Wazuh Indexer installed and configured.

Refer to its `README.md` for setup and usage instructions.

## Package testing

Built packages are tested by the [package builder Workflow](https://github.com/wazuh/wazuh-indexer/blob/main/.github/workflows/5_builderpackage_indexer.yml), each test in a throwaway container:

- **DEB packages** — an Ubuntu 22.04 container running systemd, started by `build-scripts/run_in_systemd_container.sh`.
- **RPM packages** — Red Hat UBI 9 containers: `redhat/ubi9`, or `redhat/ubi9-init` when the test needs systemd, through the same script with `SYSTEMD_IMAGE` set.

The tests cover:

- **Installation and removal** — the package installs, and removes (DEB: purges) without errors.
- **Removal leftovers** — `build-scripts/ci/test_purge.sh`: a purge always removes the `wazuh-indexer` user and group; what the service account owned in the package's four directories belongs to root and keeps its mode, and the directories are closed to everyone but root; only a directory that still holds files is listed as kept; the engine's runtime files and the JVM's performance data in `/tmp` do not outlive the purge; the certificates issued from the removed CA go with it, and an operator's own pair stays; a custom `path.repo` is left exactly as it was; a directory that cannot be handed over is reported and not listed as kept; a reinstall restores every owner and mode, and the node's certificates chain to its CA; and the resolver refuses a pair the CA did not issue. See [When the package is purged](packages.md#when-the-package-is-purged).
- **Credential and TLS resolution** — `build-scripts/ci/test_credentials.sh`. See [Credential and TLS resolution](packages.md#credential-and-tls-resolution).
- **Upgrades** — from the previous version, with the indexer stopped and running. Only when a previous version exists.
- **4.x upgrade block** — `build-scripts/ci/test_upgrade_block.sh`: the package refuses to upgrade a 4.x installation.

Each script documents its requirements in its header and can also be run on a throwaway VM.

## Useful test flags

- **`-Dtests.seed=<seed>`** — reproduce a specific randomized test run.
- **`-Dtests.verbose=true`** — print test output to stdout.
- **`--tests "ClassName"`** — run a single test class.
- **`--tests "ClassName.methodName"`** — run a single test method.
- **`-x test`** — skip unit tests in a build.
