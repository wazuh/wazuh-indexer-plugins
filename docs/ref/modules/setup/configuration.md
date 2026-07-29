## Setup settings

The Setup plugin is configured through settings in `opensearch.yml`. All settings use the `plugins.setup` prefix.

- **`plugins.setup.timeout`** (Integer, default `30`) — timeout in seconds for index and search operations.
- **`plugins.setup.backoff`** (Integer, default `15`) — delay in seconds for the retry mechanism involving initialization tasks.
- **`plugins.setup.settings_update.enabled`** (Boolean, default `true`) — when `false`, the settings update endpoint (`PUT /_plugins/_setup/settings`) returns `403 Forbidden` for every caller, regardless of role. See [Protecting sensitive configuration](../content-manager/configuration.md#protecting-sensitive-configuration) for the full disable-endpoint pattern shared with Content Manager.
