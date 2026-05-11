# Configuration

The Content Manager plugin is configured through settings in `opensearch.yml`. All settings use the `plugins.content_manager` prefix.

## Settings Reference

| Setting                                              | Type    | Default                                  | Description                                                                     |
| ---------------------------------------------------- | ------- | ---------------------------------------- | ------------------------------------------------------------------------------- |
| `plugins.content_manager.cti.api`                    | String  | `https://api.pre.cloud.wazuh.com/api/v1` | Base URL for the Wazuh CTI API                                                  |
| `plugins.content_manager.catalog.sync_interval`      | Integer | `60`                                     | Sync interval in minutes. Valid range: 1–1440                                   |
| `plugins.content_manager.max_items_per_bulk`         | Integer | `999`                                    | Maximum documents per bulk indexing request. Valid range: 10–999                |
| `plugins.content_manager.max_concurrent_bulks`       | Integer | `5`                                      | Maximum concurrent bulk operations. Valid range: 1–5                            |
| `plugins.content_manager.client.timeout`             | Long    | `10`                                     | HTTP client timeout in seconds for CTI API requests. Valid range: 10–50         |
| `plugins.content_manager.catalog.update_on_start`    | Boolean | `true`                                   | Trigger content sync when the plugin starts                                     |
| `plugins.content_manager.catalog.update_on_schedule` | Boolean | `true`                                   | Enable the periodic sync job                                                    |
| `plugins.content_manager.catalog.ruleset`            | String  | `""`                                    | Full CTI consumer URL for ruleset content                                      |
| `plugins.content_manager.catalog.iocs`               | String  | `""`                                    | Full CTI consumer URL for IoC content                                          |
| `plugins.content_manager.catalog.vulnerabilities`    | String  | `""`                                    | Full CTI consumer URL for vulnerabilities content                              |
| `plugins.content_manager.catalog.create_detectors`   | Boolean | `true`                                   | Automatically create Security Analytics detectors from CTI content              |
| `plugins.content_manager.telemetry.enabled`          | Boolean | `true`                                   | Enable or disable the daily Update check service ping. This setting is dynamic. |

## Configuration Examples

### Default Configuration

No configuration is required for default behavior. The Content Manager will sync content every 60 minutes.

### Custom Sync Interval

To sync content every 30 minutes:

```yaml
# opensearch.yml
plugins.content_manager.catalog.sync_interval: 30
```

### Disable Automatic Sync

To disable all automatic synchronization and only sync manually via the API:

```yaml
# opensearch.yml
plugins.content_manager.catalog.update_on_start: false
plugins.content_manager.catalog.update_on_schedule: false
```

Content can still be synced on demand using:

```bash
curl -sk -u admin:admin -X POST \
  "https://192.168.56.6:9200/_plugins/_content_manager/update"
```

### Custom CTI API Endpoint

To point to a different CTI API (e.g., production):

```yaml
# opensearch.yml
plugins.content_manager.cti.api: "https://cti.wazuh.com/api/v1"
```

### Custom Catalog Consumer URLs

To override default consumers, provide full HTTP(S) consumer URLs:

```yaml
# opensearch.yml
plugins.content_manager.catalog.ruleset: "https://api.pre.cloud.wazuh.com/api/v1/catalog/contexts/beta-2-ruleset-5/consumers/public-ruleset-5"
plugins.content_manager.catalog.iocs: "https://api.pre.cloud.wazuh.com/api/v1/catalog/contexts/t1-iocs-5/consumers/public-iocs-5"
plugins.content_manager.catalog.vulnerabilities: "https://api.pre.cloud.wazuh.com/api/v1/catalog/contexts/t1-vulnerabilities-5/consumers/public-vulnerabilities-5"
```

Behavior:

- If a setting is non-empty, Content Manager attempts remote snapshot initialization first.
- If remote initialization fails, it falls back to the local packaged snapshot when available.
- If a setting is empty, initialization uses the local packaged snapshot directly.

### Tune Bulk Operations

For environments with limited resources, reduce the bulk operation concurrency:

```yaml
# opensearch.yml
plugins.content_manager.max_items_per_bulk: 10
plugins.content_manager.max_concurrent_bulks: 2
plugins.content_manager.client.timeout: 30
```

### Disable Security Analytics Detector Creation

If you do not use the OpenSearch Security Analytics plugin:

```yaml
# opensearch.yml
plugins.content_manager.catalog.create_detectors: false
```

### CTI communication headers

All HTTP clients that communicate with Wazuh CTI services send a custom `User-Agent` header:

```
User-Agent: Wazuh Indexer <version>
```

For example: `Wazuh Indexer 5.0.0`. This applies to the Console API client, Catalog API client, Snapshot client, and Telemetry client. The version is read from `VERSION.json` at plugin startup.

### Update check service behavior

The update check service is enabled by default and runs once per day, with an immediate first ping fired as soon as the job is registered in the scheduler.

- It is implemented by a scheduled job (`wazuh-telemetry-ping-job`) in `.wazuh-content-manager-jobs`.
- It sends a request to the CTI Update check API endpoint (`/ping`).
- The request includes:
  - Deployment identifier (`wazuh-uid`: cluster UUID)
  - Running version (`wazuh-tag`: `v<version>`)
  - User agent (`Wazuh Indexer <version>`)

This data allows Wazuh to determine if a newer version is available and notify users in the update check UI.

> The service only sends deployment identification/version metadata required for update checks. It does not send rules, events, or log payloads.

### Enable/Disable Update check service dynamically

The update check service can be enabled or disabled at runtime without restarting the node using the Cluster Settings API:

```bash
curl -sk -u admin:admin -X PUT "https://192.168.56.6:9200/_cluster/settings" -H 'Content-Type: application/json' -d'
{
  "persistent": {
    "plugins.content_manager.telemetry.enabled": false
  }
}'
```

## Notes

- Changes to `opensearch.yml` require a restart of the Wazuh Indexer to take effect, except for dynamic settings (like `plugins.content_manager.telemetry.enabled`), which can be updated at runtime via the OpenSearch API.
- The catalog URL settings (`plugins.content_manager.catalog.ruleset`, `plugins.content_manager.catalog.iocs`, and `plugins.content_manager.catalog.vulnerabilities`) should only be changed if instructed by Wazuh support or documentation, and must point to valid absolute HTTP(S) CTI consumer endpoints.
- The sync interval is enforced by the OpenSearch Job Scheduler. The actual sync timing may vary slightly depending on cluster load.
- The update check service runs with a fixed interval of 1 day when enabled. The first ping is sent immediately after the job is registered (on node start or when the setting is dynamically enabled); subsequent pings follow the 1-day interval.
