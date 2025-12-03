# API Reference

The Content Manager plugin provides a RESTful API for managing CTI subscriptions and updates.

## Subscription Management

### Create or Update Subscription
Registers the Wazuh Indexer with the CTI provider using a device code.

* **Endpoint**: `POST /_plugins/content-manager/subscription`
* **Description**: Creates a new subscription or updates an existing one using the provided device authentication details.

**Request Body Parameters:**

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `device_code` | string | Yes | The device code obtained from the CTI provider. |
| `client_id` | string | Yes | The client identifier. |
| `expires_in` | integer | Yes | Expiration time in seconds. |
| `interval` | integer | Yes | Polling interval in seconds. |



**Example Request:**
``json
POST /_plugins/content-manager/subscription
{
  "device_code": "User-Code-123",
  "client_id": "wazuh-dashboard",
  "expires_in": 1800,
  "interval": 5
}
``

**Example Response:**
``json
{
  "message": "Subscription created successfully",
  "status": 201
}
``

**Error Responses:**
* `400 Bad Request`: Missing required parameters
* `404 Not Found`: If no subscription token is found.
* `500 Internal Server Error`: Unexpected error during processing



### Get Subscription
Retrieves the current subscription token.

* **Endpoint**: `GET /_plugins/content-manager/subscription`
* **Description**: Returns the active access token if a subscription exists.

**Example Response:**
``json
{
  "access_token": "eyJhbGciOiJSUzI1...",
  "token_type": "Bearer"
}
``

**Error Responses:**
* `404 Not Found`: If no subscription token is found.
* `500 Internal Server Error`: Unexpected error during processing


### Delete Subscription
Removes the current subscription.

* **Endpoint**: `DELETE /_plugins/content-manager/subscription`
* **Description**: Deletes the stored subscription token.

**Example Response:**
``json
{
  "message": "Subscription deleted successfully",
  "status": 200
}
``

**Error Responses:**
* `404 Not Found`: If no subscription token is found.
* `500 Internal Server Error`: Unexpected error during processing



## Content Updates

### Trigger Update
Manually triggers a content synchronization job.

* **Endpoint**: `POST /_plugins/content-manager/update`
* **Description**: Initiates the `CatalogSyncJob` to check for and apply updates. If a job is already running, a 409 Conflict is returned.

**Example Response:**
``json
{
  "message": "Update accepted",
  "status": 202
}
``

**Error Responses:**
* `404 Not Found`: If no subscription token is found.
* `409 Conflict`: If an update operation is already in progress.
* `429 Too Many Requests`: If the rate limit is exceeded.
* `500 Internal Server Error`: Unexpected error during processing