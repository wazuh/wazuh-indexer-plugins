<!-- // ANCHOR: settings-table -->
## Content Manager settings

The Content Manager plugin is configured through settings in `opensearch.yml`. All settings use the `plugins.content_manager` prefix.

- **`plugins.content_manager.cti.api`** (String, default `https://api.pre.cloud.wazuh.com/api/v1`) — base URL for the Wazuh CTI API.
- **`plugins.content_manager.catalog.sync_interval`** (Integer, default `60`, range 10–1440) — sync interval in minutes.
- **`plugins.content_manager.setup_wait.max_retries`** (Integer, default `4`, range 0–10) — number of retries the catalog sync job performs while waiting for the Setup plugin to report readiness on startup, before giving up until the next scheduled sync.
- **`plugins.content_manager.setup_wait.backoff_base_seconds`** (Integer, default `20`, range 1–120) — base delay, in seconds, for the exponential backoff between those retries (delay for retry `n` is `base * 2^n`; with the defaults, 20s/40s/80s/160s = 300s / 5 min worst case).
- **`plugins.content_manager.max_items_per_bulk`** (Integer, default `999`, range 10–999) — maximum documents per bulk indexing request.
- **`plugins.content_manager.max_concurrent_bulks`** (Integer, default `5`, range 1–5) — maximum concurrent bulk operations.
- **`plugins.content_manager.max_bulk_bytes`** (Long, default `5242880` / 5 MB, range 1048576–104857600 / 1–100 MB) — maximum request body size, in bytes, for a single bulk indexing request.
- **`plugins.content_manager.logtest.max_body_bytes`** (Long, default `1048576` / 1 MiB, range 1024–16777216 / 1 KiB–16 MiB, dynamic) — maximum size, in bytes, of a logtest request body (`POST /logtest`, `/logtest/normalization`, `/logtest/detection`). Requests whose body exceeds this are rejected with HTTP 413 at the REST layer, before parsing or dispatch, so an oversized event cannot be amplified into the response and exhaust the indexer's heap.
- **`plugins.content_manager.client.timeout`** (Long, default `10`, range 10–50) — HTTP client timeout in seconds for CTI API requests.
- **`plugins.content_manager.client.max_retries`** (Integer, default `3`, range 0–10) — number of times a CTI API request is retried after an HTTP 429 (Too Many Requests) response, before the 429 is returned to the caller.
- **`plugins.content_manager.client.retry_backoff_base_seconds`** (Integer, default `30`, range 1–300) — base delay, in seconds, for the exponential backoff used between 429 retries when the response carries no usable `Retry-After` header (delay for retry `n` is `base * 2^n`).
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
- **`plugins.content_manager.max_integrations`** (Integer, default `100`, minimum `0`, no upper bound, dynamic) — maximum number of integrations that can be created. Requests that would exceed this limit are rejected with HTTP 400.
- **`plugins.content_manager.max_decoders`** (Integer, default `200`, minimum `0`, no upper bound, dynamic) — maximum number of decoders that can be created. Requests that would exceed this limit are rejected with HTTP 400.
- **`plugins.content_manager.max_rules`** (Integer, default `200`, minimum `0`, no upper bound, dynamic) — maximum number of rules that can be created. Requests that would exceed this limit are rejected with HTTP 400.
- **`plugins.content_manager.max_kvdbs`** (Integer, default `100`, minimum `0`, no upper bound, dynamic) — maximum number of KVDBs that can be created. Requests that would exceed this limit are rejected with HTTP 400.
- **`plugins.content_manager.max_filters`** (Integer, default `100`, minimum `0`, no upper bound, dynamic) — maximum number of filters that can be created per space. Requests that would exceed this limit are rejected with HTTP 400.

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

### Setup readiness wait (startup race)

On node startup, the catalog sync job waits for the Setup plugin to finish creating its indices (signaled by the `.wazuh-setup-status` marker document) before it runs. If Setup has not finished within that wait, the sync is skipped for that run and deferred to the next scheduled run (`plugins.content_manager.catalog.sync_interval` minutes later, an hour by default) — on a slow-starting node (e.g. cluster still recovering shards), this can leave `.wazuh-cti-consumers` and the CTI content indices empty for up to that long.

The wait uses exponential backoff, controlled by `plugins.content_manager.setup_wait.max_retries` and `plugins.content_manager.setup_wait.backoff_base_seconds`. With the defaults (4 retries, 20s base), the schedule is 20s, 40s, 80s, 160s — 300s (5 min) total before giving up. Increase these on environments where Setup is known to take longer to initialize:

```yaml
# opensearch.yml
plugins.content_manager.setup_wait.max_retries: 4
plugins.content_manager.setup_wait.backoff_base_seconds: 30
```

The example above raises the total worst-case wait to 30+60+120+240 = 450s (7.5 min).

### CTI rate-limit retries (HTTP 429)

When the CTI API rate-limits a request it responds with HTTP 429 and a `Retry-After` header. The HTTP client honors that header: it waits the indicated time and retries the request, so a rate-limit no longer fails the synchronization pass. If the response carries no usable `Retry-After` header, it falls back to exponential backoff (`base * 2^n`).

The behavior is controlled by `plugins.content_manager.client.max_retries` and `plugins.content_manager.client.retry_backoff_base_seconds`. With the defaults (3 retries, 30s base), the fallback schedule is 30s, 60s, 120s — 210s (3.5 min) worst case before the 429 is surfaced and the pass defers to the next scheduled run:

```yaml
# opensearch.yml
plugins.content_manager.client.max_retries: 3
plugins.content_manager.client.retry_backoff_base_seconds: 30
```

The `Retry-After` header, when present, always takes precedence over the backoff base — the base applies only when the header is missing or unparseable.

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
- **`PUT /_plugins/_setup/settings`** — permission `plugin:wazuh/settings/write`.

1. **RBAC** — each endpoint is gated by a cluster permission (the action name above), enforced by the security plugin. Among the bundled users, only `wazuh-admin` holds these permissions; `wazuh-manager`, `wazuh-demo` and `wazuh-readonly` are excluded. The superuser `admin` (role `all_access`, cluster wildcard `*`) also holds them. To delegate any of these actions without granting full superuser, create a dedicated role for the permission(s) above. See the [access control reference](../../security/access-control.md).
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

#### Resource creation limits

The plugin enforces configurable upper bounds on the number of resources that can be created. Each limit applies to POST (creation) requests only — existing resources are not affected when a limit is lowered. The count is checked against the relevant index at request time; if the index does not yet exist, the check is skipped and creation proceeds.

All limit settings are dynamic and can be changed at runtime:

```bash
curl -X PUT "https://localhost:9200/_cluster/settings" \
  -H 'Content-Type: application/json' \
  -d '{
    "persistent": {
      "plugins.content_manager.max_integrations": 50,
      "plugins.content_manager.max_decoders": 100,
      "plugins.content_manager.max_rules": 100,
      "plugins.content_manager.max_kvdbs": 50,
      "plugins.content_manager.max_filters": 50
    }
  }'
```

Setting a limit to `0` blocks all new creation of that resource type.

### Notes

- Changes to `opensearch.yml` require a restart of the Wazuh Indexer to take effect, except for dynamic settings, which can be updated at runtime via the OpenSearch API. Dynamic settings include `plugins.content_manager.telemetry.enabled`, `plugins.content_manager.logtest.max_body_bytes`, and all five resource creation limits (`max_integrations`, `max_decoders`, `max_rules`, `max_kvdbs`, `max_filters`).
- The catalog URL settings (`plugins.content_manager.catalog.ruleset`, `plugins.content_manager.catalog.iocs`, and `plugins.content_manager.catalog.vulnerabilities`) should only be changed if instructed by Wazuh support or documentation, and must point to valid absolute HTTP(S) CTI consumer endpoints.
- The sync interval is enforced by the OpenSearch Job Scheduler. The actual sync timing may vary slightly depending on cluster load.
- The update check service runs with a fixed interval of 1 day when enabled. The first ping is sent immediately after the job is registered (on node start or when the setting is dynamically enabled); subsequent pings follow the 1-day interval.
- **Detector configuration:** the settings for Security Analytics detectors (interval, enabled status, and source indices) are managed directly via CTI integration files. If an integration's `detector` object is missing in the CTI source, the system will use built-in safety defaults.
