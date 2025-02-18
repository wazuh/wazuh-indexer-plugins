# Configuration files

############ Proposed documentation ###############

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
   - **Default**: `20`
   - **Description**: Specifies the API consulting timeout value in seconds.

2. **Job Schedule**
   - **Key**: `command_manager.job.schedule`
   - **Type**: Integer
   - **Default**: `1`
   - **Description**: Defines the schedule interval in minutes for job execution.

3. **Job Page Size**
   - **Key**: `command_manager.job.page_size`
   - **Type**: Integer
   - **Default**: `100`
   - **Description**: Sets the number of records to process per page during job execution.

4. **Job PIT Keep Alive**
   - **Key**: `command_manager.job.pit_keep_alive`
   - **Type**: Integer
   - **Default**: `30`
   - **Description**: Determines the keep-alive time in seconds for the Point-In-Time (PIT) context.

5. **Job Index Template**
   - **Key**: `command_manager.job.index.template`
   - **Type**: String
   - **Default**: `index-template-scheduled-commands`
   - **Description**: Specifies the template name for the job scheduled commands index.

6. **API Prefix**
   - **Key**: `command_manager.api.prefix`
   - **Type**: String
   - **Default**: `/_command_manager`
   - **Description**: Sets the prefix for the command manager API endpoints.

7. **API Endpoint**
   - **Key**: `command_manager.api.endpoint`
   - **Type**: String
   - **Default**: `/commands`
   - **Description**: Defines the endpoint for command manager APIs.

8. **Index Name**
   - **Key**: `command_manager.index.name`
   - **Type**: String
   - **Default**: `.commands`
   - **Description**: Specifies the name of the index used for storing commands.

9. **Index Template**
   - **Key**: `command_manager.index.template`
   - **Type**: String
   - **Default**: `index-template-commands`
   - **Description**: Defines the template name for the commands index.

#### Notes
- All configuration fields have default values and are not mandatory.
- Adjust these settings according to your needs by modifying the `opensearch.yml` file.