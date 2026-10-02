## Setup settings

The Setup plugin is configured through settings in `opensearch.yml`. All settings use the `plugins.setup` prefix.

- **`plugins.setup.timeout`** (Integer, default `30`, range 5–120) — timeout in seconds for index and search operations.
- **`plugins.setup.backoff`** (Integer, default `15`, range 5–60) — delay in seconds for the retry mechanism involving initialization tasks.
- **`plugins.setup.max_retries`** (Integer, default `1`, range 0–10) — number of times an initialization task that timed out is re-attempted, each attempt separated by `plugins.setup.backoff`. `0` disables retrying. The budget is per task: each index, index template and ISM policy gets its own. When it runs out the exception is rethrown, initialization stops, every index registered after the failing one is skipped, and the setup status is marked `failed`. Raise it on clusters where a cluster-manager election, and therefore the first index creation, routinely outlasts the default single re-attempt.
- **`plugins.setup.settings_update.enabled`** (Boolean, default `true`) — when `false`, the settings update endpoint (`PUT /_plugins/_setup/settings`) returns `403 Forbidden` for every caller, regardless of role. See [Protecting sensitive configuration](../content-manager/configuration.md#protecting-sensitive-configuration) for the full disable-endpoint pattern shared with Content Manager.
