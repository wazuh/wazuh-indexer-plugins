# API reference

This document describes the Content Manager plugin REST API used to manage CTI subscriptions and trigger content updates. The API is implemented under the path prefix `/_plugins/content-manager` and exposes the following endpoints:

- `POST /_plugins/content-manager/subscription` — create or update the singleton subscription
- `GET  /_plugins/content-manager/subscription` — retrieve current subscription credentials
- `DELETE /_plugins/content-manager/subscription` — delete the subscription
- `POST /_plugins/content-manager/update` — trigger a content update (async)

All responses use JSON. When applicable, endpoints return standard HTTP status codes and error objects of the form:

```
{
	"message": "Human readable error message",
	"status": <http_status_code>
}
```

**Common headers (rate limiting)**

- `X-RateLimit-Limit`: maximum number of allowed requests in the current rate window
- `X-RateLimit-Remaining`: remaining requests in the current window
- `X-RateLimit-Reset`: Unix timestamp when the rate window resets

---

**POST /_plugins/content-manager/subscription**

Create or update the singleton CTI subscription. The subscription stores device flow information used later to obtain tokens.

Request body (application/json):

```
{
	"device_code": "<device_code>",
	"client_id": "<client_id>",
	"expires_in": <seconds_until_expiry>,
	"interval": <poll_interval_seconds>
}
```

Required fields: `device_code`, `client_id`, `expires_in`, `interval`.

Responses:

- 201 Created
	- body: `{ "status": 201, "message": "Subscription created successfully" }`
- 400 Bad Request
	- body: error object when required parameters are missing
- 401 Unauthorized
	- when the caller is not the expected internal user (platform specific)
- 500 Internal Server Error

Example:

Request:

```
POST /_plugins/content-manager/subscription
Content-Type: application/json

{
	"device_code": "abc123",
	"client_id": "content-client",
	"expires_in": 1800,
	"interval": 5
}
```

Success response (201):

```
{
	"status": 201,
	"message": "Subscription created successfully"
}
```

---

**GET /_plugins/content-manager/subscription**

Retrieve the currently stored credentials for the subscription. This returns the access token and token type that the plugin would use to call the external CTI API.

Responses:

- 200 OK
	- body: `{ "access_token": "<token>", "token_type": "Bearer" }`
- 404 Not Found
	- body: error object when no subscription or credentials exist
- 401 Unauthorized
	- when called by an unexpected user
- 500 Internal Server Error

Example response (200):

```
{
	"access_token": "eyJhbGci...",
	"token_type": "Bearer"
}
```

---

**DELETE /_plugins/content-manager/subscription**

Delete the singleton subscription and any stored credentials.

Responses:

- 200 OK
	- body: `{ "status": 200, "message": "Subscription deleted successfully" }`
- 404 Not Found
	- body: error object when no subscription exists
- 401 Unauthorized
	- when called by an unexpected user
- 500 Internal Server Error

Example response (200):

```
{
	"status": 200,
	"message": "Subscription deleted successfully"
}
```

---

**POST /_plugins/content-manager/update**

Trigger an asynchronous content update operation. The endpoint performs validation and rate limiting checks, then enqueues or starts the update. The operation is accepted and processed asynchronously; this endpoint does not return the updated content directly.

Behavior and status codes:

- 202 Accepted
	- The update request is accepted and processing has started (or will start). Response includes rate-limit headers when applicable.
- 404 Not Found
	- No subscription exists — a subscription must be created before updates can be triggered.
- 401 Unauthorized
	- When called by an unexpected user
- 409 Conflict
	- Another update is currently in progress
- 429 Too Many Requests
	- Rate limit exceeded. Response includes `X-RateLimit-Limit`, `X-RateLimit-Remaining` (often 0), and `X-RateLimit-Reset` headers.
- 503 Service Unavailable
	- External CTI service is currently unavailable
- 500 Internal Server Error

Special testing headers (for integration tests only):

- `X-Wazuh-Test-Rate-Limit`: integer override for the configured rate limit (allows test to simulate limits)
- `X-Wazuh-Test-Simulate-External-Service-Error`: set to `true` to simulate an external service outage (returns 503)
- `X-Wazuh-Test-Simulated-Duration`: server-side simulated processing duration in milliseconds (used to test concurrency/race conditions)

Example request:

```
POST /_plugins/content-manager/update
```

Accepted response (202) with rate-limit headers:

Headers:

```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 59
X-RateLimit-Reset: 1700000000
```

Body:

```
{ "status": "update accepted" }
```

Error example (429 Too Many Requests):

Headers:

```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1700000000
```

Body:

```
{
	"message": "Too many update requests. Please try again later.",
	"status": 429
}
```

---

Notes and implementation details:

- The subscription is implemented as a singleton model in the plugin; only one subscription may exist at a time.
- The update endpoint currently uses an in-memory concurrency guard for conflict detection; production implementations should replace this with a cluster-wide lock or task queue.
- Rate limiting and testing headers facilitate integration tests and local development. Test headers should not be used in production.

If you need sample curl commands or additional example workflows (e.g., full device-flow authentication exchange), ask and we will add them.

