# Compatibility

## Supported operating systems

We aim to support as many operating systems as [OpenSearch](https://opensearch.org/docs/2.11/install-and-configure/install-opensearch/index/#operating-system-compatibility) does. Wazuh indexer should work on many Linux distributions, but we only test a handful. The following table lists the operating system versions that we currently support.

 For 4.9.0 and above, we want to support the operating system versions and architectures included in the [Central Components sheet](https://docs.google.com/spreadsheets/d/1Zs9vUtpsw8jj3Sggr4fC8TAQpYA1SAiwplF3H595nQQ/edit#gid=949689823).

| Name          | Version     | Architecture    |
|---------------|-------------|-----------------|
| Red Hat       |  8, 9       | x86_64, aarch64 |
| Ubuntu        | 22.04, 24.04| x86_64, aarch64 |
| Amazon Linux  | 2, 2023     | x86_64, aarch64 |
| CentOS        |  8          | x86_64, aarch64 |

## OpenSeach

Currently, Wazuh indexer is using version `2.19.0` of OpenSearch.
