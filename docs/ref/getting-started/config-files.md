# Configuration files

### Command Manager Plugin Configuration

The Command Manager plugin allows you to configure various settings through the `opensearch.yml` file. Below is an overview of the available configuration options and their default values.

#### Configuration Structure

The configuration settings for the Command Manager plugin are structured in the following hierarchy within the `opensearch.yml` file:

```yaml
command_manager:
  timeout: int
  job:
    schedule: int
    page_size: int
    pit_keep_alive: int
    index:
      template: str
  api:
    prefix: str
    endpoint: str
  index:
    name: str
    template: str
```

#### Configuration Parameters

1. **Timeout**
   - **Key**: `command_manager.timeout`
   - **Type**: Integer
   - **Default**: `30`
   - **Minimum**: `5`
   - **Maximun**: `120`
   - **Description**: Specifies the API consulting timeout value in minutes.

2. **Job Schedule**
   - **Key**: `command_manager.job.schedule`
   - **Type**: Integer
   - **Default**: `1`
   - **Minimum**: `1` 
   - **Maximun**: `10`
   - **Description**: Defines the schedule interval in minutes for job execution.

3. **Job Max Docs**
   - **Key**: `command_manager.job.max_docs`
   - **Type**: Integer
   - **Default**: `1000`
   - **Minimum**: `5`
   - **Maximun**: `100000`
   - **Description**: Client class methods timeout in seconds.

#### Notes
- All configuration fields have default values and are not mandatory.
- Adjust these settings according to your needs by modifying the `opensearch.yml` file.
