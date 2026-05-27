## Setup settings

The Setup plugin is configured through settings in `opensearch.yml`. All settings use the `plugins.setup` prefix.

| Setting                 | Data type | Default value | Description                                                              |
| ----------------------- | --------- | ------------- | ------------------------------------------------------------------------ |
| `plugins.setup.timeout` | Integer   | `30`          | Timeout in seconds for index and search operations.                      |
| `plugins.setup.backoff` | Integer   | `15`          | Delay in seconds for the retry mechanism involving initialization tasks. |
