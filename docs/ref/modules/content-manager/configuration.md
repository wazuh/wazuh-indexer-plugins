# Configuration

The Content Manager plugin is configured through settings in `opensearch.yml`. All settings use the `plugins.content_manager` prefix.

## Settings Reference

| Setting | Type | Default | Description |
|---|---|---|---|
| `plugins.content_manager.cti.api` | String | `https://cti-pre.wazuh.com/api/v1` | Base URL for the Wazuh CTI API |
| `plugins.content_manager.catalog.sync_interval` | Integer | `60` | Sync interval in minutes. Valid range: 1–1440 |
| `plugins.content_manager.max_items_per_bulk` | Integer | `25` | Maximum documents per bulk indexing request. Valid range: 10–25 |
| `plugins.content_manager.max_concurrent_bulks` | Integer | `5` | Maximum concurrent bulk operations. Valid range: 1–5 |
| `plugins.content_manager.client.timeout` | Long | `10` | HTTP client timeout in seconds for CTI API requests. Valid range: 10–50 |
| `plugins.content_manager.catalog.update_on_start` | Boolean | `true` | Trigger content sync when the plugin starts |
| `plugins.content_manager.catalog.update_on_schedule` | Boolean | `true` | Enable the periodic sync job |
| `plugins.content_manager.catalog.content.context` | String | `development_0.0.3` | CTI catalog content context identifier |
| `plugins.content_manager.catalog.content.consumer` | String | `development_0.0.3_test` | CTI catalog content consumer identifier |
| `plugins.content_manager.ioc.content.context` | String | `ioc_provider` | IoC content context identifier |
| `plugins.content_manager.ioc.content.consumer` | String | `iocp_v1` | IoC content consumer identifier |
| `plugins.content_manager.catalog.create_detectors` | Boolean | `true` | Automatically create Security Analytics detectors from CTI content |

## Configuration Examples

### Default Configuration

No configuration is required for default behavior. The Content Manager will sync content every 60 minutes using the pre-configured CTI contexts.

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

## Notes

- Changes to `opensearch.yml` require a restart of the Wazuh Indexer to take effect.
- The `context` and `consumer` settings should only be changed if instructed by Wazuh support or documentation, as they must match valid CTI API contexts.
- The sync interval is enforced by the OpenSearch Job Scheduler. The actual sync timing may vary slightly depending on cluster load.
