## Setup settings

The Setup plugin is configured through settings in `opensearch.yml`. All settings use the `plugins.setup` prefix.

- **`plugins.setup.timeout`** (Integer, default `30`) — timeout in seconds for index and search operations.
- **`plugins.setup.backoff`** (Integer, default `15`) — delay in seconds for the retry mechanism involving initialization tasks.
- **`plugins.setup.max_retries`** (Integer, default `1`, range 0–10) — number of times an initialization task (index or index-template creation) that timed out is re-attempted, each attempt separated by `plugins.setup.backoff`, before the failure is rethrown and the node shuts down. `0` disables retrying. Raise it on clusters where a cluster-manager election, and therefore the first index creation, routinely outlasts the default single re-attempt.
- **`plugins.setup.settings_update.enabled`** (Boolean, default `true`) — when `false`, the settings update endpoint (`PUT /_plugins/_setup/settings`) returns `403 Forbidden` for every caller, regardless of role. See [Protecting sensitive configuration](../content-manager/configuration.md#protecting-sensitive-configuration) for the full disable-endpoint pattern shared with Content Manager.
