# Configuration files

Most of our plugins allow you to configure various settings through the `opensearch.yml` file. Below is an overview of the available configuration options and their default values.

## Setup plugin configuration

1. **Client Timeout**
   - **Key**: `setup.client.timeout`
   - **Type**: Integer
   - **Default**: `30`
   - **Minimum**: `5`
   - **Maximum**: `120`
   - **Description**: Timeout in seconds for index and search operations.


## Example

Below, there is an example of custom values for these settings within the `opensearch.yml` file:

```yaml
setup:
  client:
    timeout: 60
```
