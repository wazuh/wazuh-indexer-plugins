<!-- // ANCHOR: settings-table -->
## Content Manager settings

The Content Manager plugin is configured through settings in `opensearch.yml`. All settings use the `plugins.content_manager` prefix.

- **`plugins.content_manager.cti.api`** (String, default `https://api.pre.cloud.wazuh.com/api/v1`) — base URL for the Wazuh CTI API.
- **`plugins.content_manager.catalog.sync_interval`** (Integer, default `60`, range 10–1440) — sync interval in minutes.
- **`plugins.content_manager.max_items_per_bulk`** (Integer, default `999`, range 10–999) — maximum documents per bulk indexing request.
- **`plugins.content_manager.max_concurrent_bulks`** (Integer, default `5`, range 1–5) — maximum concurrent bulk operations.
- **`plugins.content_manager.max_bulk_bytes`** (Long, default `5242880` / 5 MB, range 1048576–104857600 / 1–100 MB) — maximum request body size, in bytes, for a single bulk indexing request.
- **`plugins.content_manager.client.timeout`** (Long, default `10`, range 10–50) — HTTP client timeout in seconds for CTI API requests.
- **`plugins.content_manager.pit_keepalive`** (Long, default `120`, range 60–600) — point-in-time keepalive in seconds used during paginated index scans.
- **`plugins.content_manager.engine.mock`** (Boolean, default `false`) — bypasses real Engine socket calls, returning mocked responses instead. Intended for testing only.
- **`plugins.content_manager.catalog.update_on_start`** (Boolean, default `true`) — trigger content sync when the plugin starts.
- **`plugins.content_manager.catalog.update_on_schedule`** (Boolean, default `true`) — enable the periodic sync job.
- **`plugins.content_manager.catalog.ruleset`** (String, default `""`) — full CTI consumer URL for ruleset content.
- **`plugins.content_manager.catalog.iocs`** (String, default `""`) — full CTI consumer URL for IoC content.
- **`plugins.content_manager.catalog.vulnerabilities`** (String, default `""`) — full CTI consumer URL for vulnerabilities content.
- **`plugins.content_manager.catalog.create_detectors`** (Boolean, default `true`) — automatically create Security Analytics detectors from CTI content.
- **`plugins.content_manager.telemetry.enabled`** (Boolean, default `true`, dynamic) — enable or disable the daily Update check service ping.
- **`plugins.content_manager.catalog.update_on_demand`** (Boolean, default `true`) — when `false`, on-demand content updates (`POST /update`) return `403 Forbidden` for every caller, regardless of role.
- **`plugins.content_manager.catalog.policy_update.enabled`** (Boolean, default `true`) — when `false`, policy updates (`PUT /policy/{space}`) return `403 Forbidden` for every caller, regardless of role.

<!-- // ANCHOR_END: settings-table -->

### Offline configuration / disabling automatic updates

<!-- // ANCHOR: offline-config --> 
On offline installations, disable every task that requires an internet connection to prevent failures.

```yaml
# opensearch.yml
plugins.content_manager.catalog.update_on_start: false
plugins.content_manager.catalog.update_on_schedule: false
plugins.content_manager.telemetry.enabled: false
```
<!-- // ANCHOR_END: offline-config -->

On online installations, manual synchronization can be performed on demand using the Content Manager API:

```
POST /_plugins/_content_manager/update"
```

### Custom scheduled synchronization interval

The plugin checks for new content every 60 minutes by default, but this can be customized by changing the `plugins.content_manager.catalog.sync_interval` setting. The value is specified in minutes and must be between 10 and 1440 (24 hours).

```yaml
# opensearch.yml
plugins.content_manager.catalog.sync_interval: 1440
```

#### Custom CTI API endpoint

To point to a different CTI API (e.g., production):

```yaml
# opensearch.yml
plugins.content_manager.cti.api: "https://cti.wazuh.com/api/v1"
```

#### Custom catalog consumer URLs

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

#### Tune bulk operations

For environments with limited resources, reduce the bulk operation concurrency:

```yaml
# opensearch.yml
plugins.content_manager.max_items_per_bulk: 10
plugins.content_manager.max_concurrent_bulks: 2
plugins.content_manager.client.timeout: 30
```

#### Disable Security Analytics detector creation

If you do not use the OpenSearch Security Analytics plugin:

```yaml
# opensearch.yml
plugins.content_manager.catalog.create_detectors: false
```

#### CTI communication headers

All HTTP clients that communicate with Wazuh CTI services send a custom `User-Agent` header:

```
User-Agent: Wazuh Indexer <version>
```

For example: `Wazuh Indexer 5.0.0`. This applies to the Console API client, Catalog API client, Snapshot client, and Telemetry client. The version is read from `VERSION.json` at plugin startup.

#### Update check service behavior

The update check service is enabled by default and runs once per day, with an immediate first ping fired as soon as the job is registered in the scheduler.

- It is implemented by a scheduled job (`wazuh-telemetry-ping-job`) in `.wazuh-content-manager-jobs`.
- It sends a request to the CTI Update check API endpoint (`/ping`).
- The request includes:
  - Deployment identifier (`wazuh-uid`: cluster UUID)
  - Running version (`wazuh-tag`: `v<version>`)
  - User agent (`Wazuh Indexer <version>`)

This data allows Wazuh to determine if a newer version is available and notify users in the update check UI.

> The service only sends deployment identification/version metadata required for update checks. It does not send rules, events, or log payloads.

#### Enable or disable the update check service dynamically

The update check service can be enabled or disabled at runtime without restarting the node using the Cluster Settings API:

```bash
curl -sk -u admin:admin -X PUT "https://192.168.56.6:9200/_cluster/settings" -H 'Content-Type: application/json' -d'
{
  "persistent": {
    "plugins.content_manager.telemetry.enabled": false
  }
}'
```

### Protecting sensitive configuration

Some endpoints modify configuration with a high impact on the platform and are protected by two independent controls:

- **`PUT /_plugins/_content_manager/policy/{space}`** — permission `cluster:admin/content_manager/policy/update`.
- **`POST /_plugins/_content_manager/update`** — permission `cluster:admin/content_manager/update/trigger`.
- **`PUT /_plugins/_setup/settings`** — permission `cluster:admin/setup/settings/update`.

1. **RBAC** — each endpoint is gated by a cluster permission (the action name above), enforced by the security plugin. Only the superuser `admin` (role `all_access`, cluster wildcard `*`) holds these permissions; the bundled `wazuh-server` and `wazuh-dashboard` users do not. To delegate any of these actions without granting full superuser, create a dedicated role for the permission(s) above. See the [access control reference](../../security/access-control.md).
2. **Per-endpoint disable settings** — each endpoint can be disabled independently with its own node setting; when disabled it returns `403 Forbidden` for **every** caller, including `admin` / `all_access`. This is intended for externally managed (e.g. Wazuh Cloud) deployments.

   - **`POST /_plugins/_content_manager/update`** — disable via `plugins.content_manager.catalog.update_on_demand: false`.
   - **`PUT /_plugins/_content_manager/policy/{space}`** — disable via `plugins.content_manager.catalog.policy_update.enabled: false`.
   - **`PUT /_plugins/_setup/settings`** — disable via `plugins.setup.settings_update.enabled: false`.

```yaml
# opensearch.yml — disable sensitive configuration endpoints on a managed deployment
plugins.content_manager.catalog.update_on_demand: false
plugins.content_manager.catalog.policy_update.enabled: false
plugins.setup.settings_update.enabled: false
```

### Notes

- Changes to `opensearch.yml` require a restart of the Wazuh Indexer to take effect, except for dynamic settings (like `plugins.content_manager.telemetry.enabled`), which can be updated at runtime via the OpenSearch API.
- The catalog URL settings (`plugins.content_manager.catalog.ruleset`, `plugins.content_manager.catalog.iocs`, and `plugins.content_manager.catalog.vulnerabilities`) should only be changed if instructed by Wazuh support or documentation, and must point to valid absolute HTTP(S) CTI consumer endpoints.
- The sync interval is enforced by the OpenSearch Job Scheduler. The actual sync timing may vary slightly depending on cluster load.
- The update check service runs with a fixed interval of 1 day when enabled. The first ping is sent immediately after the job is registered (on node start or when the setting is dynamically enabled); subsequent pings follow the 1-day interval.
- **Detector configuration:** the settings for Security Analytics detectors (interval, enabled status, and source indices) are managed directly via CTI integration files. If an integration's `detector` object is missing in the CTI source, the system will use built-in safety defaults.
