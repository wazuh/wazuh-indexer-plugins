# Configuration files

## Command Manager plugin configuration

The Command Manager plugin allows you to configure various settings through the `opensearch.yml` file. Below is an overview of the available configuration options and their default values.

1. **Client Timeout**
   - **Key**: `command_manager.client.timeout`
   - **Type**: Integer
   - **Default**: `30`
   - **Minimum**: `5`
   - **Maximum**: `120`
   - **Description**: Timeout in seconds for index and search operations.

2. **Job Schedule**
   - **Key**: `command_manager.job.schedule`
   - **Type**: Integer
   - **Default**: `1`
   - **Minimum**: `1` 
   - **Maximum**: `10`
   - **Description**: Job execution interval in minutes.

3. **Job Max Docs**
   - **Key**: `command_manager.job.max_docs`
   - **Type**: Integer
   - **Default**: `1000`
   - **Minimum**: `5`
   - **Maximum**: `100000`
   - **Description**: Maximum number of documents to be returned by a search query.

### Example

Below there is an example of custom values for these settings within the `opensearch.yml` file:

```yaml
command_manager:
  client:
    timeout: 60
  job:
    schedule: 5
    max_docs: 4000
```