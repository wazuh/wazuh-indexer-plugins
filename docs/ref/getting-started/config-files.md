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

2. **Job Schedule**
   - **Key**: `setup.job.schedule`
   - **Type**: Integer
   - **Default**: `1`
   - **Minimum**: `1`
   - **Maximum**: `10`
   - **Description**: Job execution interval in minutes.

3. **Job Max Docs**
   - **Key**: `setup.job.max_docs`
   - **Type**: Integer
   - **Default**: `1000`
   - **Minimum**: `5`
   - **Maximum**: `100000`
   - **Description**: Maximum number of documents to be returned by a search query.

## Command Manager plugin configuration

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

## Content Manager plugin configuration

1. **CTI API URL**
   - **Key**: `content_manager.api.cti`
   - **Type**: String
   - **Default**: `https://cti.wazuh.com/api/v1`
   - **Description**: URL of the CTI API, used for communicating with the threat intelligence service.

2. **Content Manager CTI API consumer ID**
   - **Key**: `content_manager.cti.consumer`
   - **Type**: String
   - **Default**: `vd_4.8.0`
   - **Description**: Identifier or name for the CTI API consumer.

3. **Content Manager CTI API context ID**
   - **Key**: `content_manager.cti.context`
   - **Type**: String
   - **Default**: `vd_1.0.0`
   - **Description**: Identifier or name within the CTI API context.

4. **CTI Client Maximum Retries Attempts**
   - **Key**: `content_manager.cti.client.max_attempts`
   - **Type**: Integer
   - **Default**: `3`
   - **Minimum**: `2`
   - **Maximum**: `5`
   - **Description**: The maximum number of retries for a request to the CTI Client.

5. **CTI Client Sleep Time (Seconds)**
   - **Key**: `content_manager.cti.client.sleep_time`
   - **Type**: Integer
   - **Default**: `60`
   - **Minimum**: `20`
   - **Maximum**: `100`
   - **Description**: This attribute helps calculate the delay before retrying the request to the CTI client in seconds.

6. **HTTP Client Timeout (Seconds)**
   - **Key**: `content_manager.http.client.timeout`
   - **Type**: Integer
   - **Default**: `10`
   - **Minimum**: `10`
   - **Maximum**: `50`
   - **Description**: The timeout duration for the HTTP client in seconds.

7. **Maximum Items per Bulk Request**
   - **Key**: `content_manager.max_items_per_bulk`
   - **Type**: Integer
   - **Default**: `25`
   - **Minimum**: `10`
   - **Maximum**: `25`
   - **Description**: The maximum number of elements that are included in a bulk request during the initialization from a snapshot.

8. **Maximum Co-Existing Bulk Operations**
   - **Key**: `content_manager.max_concurrent_bulks`
   - **Type**: Integer
   - **Default**: `5`
   - **Minimum**: `1`
   - **Maximum**: `5`
   - **Description**: The maximum number of co-existing bulk operations during the initialization from a snapshot.

9. **Client Timeout (Seconds) for Indexing**
   - **Key**: `content_manager.client.timeout`
   - **Type**: Long
   - **Default**: `10`
   - **Description**: The timeout duration for 'get' operations on the content index and context index, in seconds. .

10. **Maximum Changes to Fetch and Apply**
    - **Key**: `content_manager.max_changes`
    - **Type**: Long
    - **Default**: `1000`
    - **Description**: The maximum number of changes to be fetched and applied during the update of the content.

11. **Maximum Number of Documents per Job**
    - **Key**: `content_manager.job.max_docs`
    - **Type**: Integer
    - **Default**: `1000`
    - **Minimum**: `5`
    - **Maximum**: `100000`
    - **Description**: Maximum number of documents processed per indexing job.

12. **Job Schedule Interval (Minutes)**
    - **Key**: `content_manager.job.schedule`
    - **Type**: Integer
    - **Default**: `1`
    - **Minimum**: `1`
    - **Maximum**: `10`
    - **Description**: Interval in minutes between each scheduled job execution.

## Example

Below, there is an example of custom values for these settings within the `opensearch.yml` file:

```yaml
setup:
  client:
    timeout: 60
  job:
    schedule: 5
    max_docs: 4000
command_manager:
  client:
    timeout: 60
  job:
    schedule: 5
    max_docs: 4000
```
