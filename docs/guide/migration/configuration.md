# Configuration migration

This page describes how to carry over a Wazuh indexer 4.x configuration to a 5.x installation. The configuration layout has changed only slightly between major versions, but several OpenSearch 3.x settings have been renamed or removed and must be reviewed before reusing any 4.x file as-is.

> **Important**:
> Do not copy 4.x configuration files verbatim into a 5.x installation. Use them as a reference and re-create each setting against the 5.x layout described below.

## Configuration paths

Both 4.x and 5.x install configuration under `/etc/wazuh-indexer/`. The canonical 5.x layout is:

| Path | Purpose |
| --- | --- |
| `/etc/wazuh-indexer/opensearch.yml` | Main cluster and node configuration |
| `/etc/wazuh-indexer/jvm.options` | JVM heap and GC settings |
| `/etc/wazuh-indexer/log4j2.properties` | Logging configuration |
| `/etc/wazuh-indexer/certs/` | Transport and HTTP TLS certificates |
| `/etc/wazuh-indexer/opensearch-security/` | Security plugin configuration (see [Authentication migration](authentication.md)) |

For a full description of each file, see [Configuration files](../../ref/configuration/configuration-files.md).

## Migration procedure

Perform these steps on the new 5.x host. The 4.x cluster is not modified by this procedure.

1. Install the 5.x package on a fresh host following [Installation](../../ref/getting-started/installation.md). This creates the default 5.x configuration tree under `/etc/wazuh-indexer/`.
2. Stop the new service before editing configuration:

    ```bash
    systemctl stop wazuh-indexer
    ```

3. Copy the relevant 4.x configuration values into the corresponding 5.x file. Do not overwrite the 5.x file with the 4.x file. Review each setting against the [Settings changes](#settings-changes) section below.
4. Migrate certificates by placing the existing trust and node certificates under `/etc/wazuh-indexer/certs/` and updating the `plugins.security.ssl.*` paths in `opensearch.yml` accordingly.
5. Re-create authentication configuration. See [Authentication migration](authentication.md).
6. Start the service:

    ```bash
    systemctl daemon-reload
    systemctl enable wazuh-indexer
    systemctl start wazuh-indexer
    ```

7. Confirm the node joins the new 5.x cluster:

    ```bash
    curl -k -u $USERNAME:$PASSWORD https://$WAZUH_INDEXER_IP_ADDRESS:9200/_cat/nodes?v
    ```

## Settings changes

The following 4.x settings have changed in 5.x and must be reviewed before reuse.

| 4.x setting | 5.x replacement | Notes |
| --- | --- | --- |
| `transport.port` | `http.port` | Transport-level port configuration has been consolidated; clusters now use `http.port` only. |
| `opensearch_performance_analyzer.*` | _Removed_ | The `opensearch-performance-analyzer` plugin is no longer shipped. Remove any related entries. |
| Multi-tenancy settings | _Disabled by default_ | Multi-tenancy is off by default. Enable explicitly only if required. |

Additional 4.x settings may have been removed or renamed by the OpenSearch 3.x base. Before starting the service, validate every setting against the [Compatibility](../../ref/compatibility.md) page and the upstream OpenSearch 3.x release notes.

## JVM and logging

`jvm.options` and `log4j2.properties` are usually safe to port over by copying individual non-default lines into the 5.x files. Do not replace the 5.x files outright, since the defaults shipped with 5.x are tuned for the new base engine.

## Related documentation

- [Migration Guide](README.md) — entry point and prerequisites
- [Authentication migration](authentication.md) — security plugin configuration
- [Legacy 4.x indices](legacy-indices.md) — historical data handling
- [Configuration files](../../ref/configuration/configuration-files.md) — full reference for each 5.x file
