# API Reference

All Notification plugin endpoints use the base path `/_plugins/_notifications`.

---

## Notification Configs

### Create a Notification Config

Creates a new notification channel configuration.

| | |
|---|---|
| **Method** | `POST` |
| **URI** | `/_plugins/_notifications/configs` |

**Request body:**

```json
{
  "config": {
    "name": "<config-name>",
    "description": "<config-description>",
    "config_type": "<channel-type>",
    "is_enabled": true,
    "<channel-type>": {
      // channel-specific fields
    }
  }
}
```

**Slack example:**

```json
{
  "config": {
    "name": "my-slack-channel",
    "description": "Slack notifications for alerts",
    "config_type": "slack",
    "is_enabled": true,
    "slack": {
      "url": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXX"
    }
  }
}
```

**Email example (with SMTP account):**

```json
{
  "config": {
    "name": "my-email-channel",
    "description": "Email alerts via SMTP",
    "config_type": "email",
    "is_enabled": true,
    "email": {
      "email_account_id": "<smtp-account-config-id>",
      "recipient_list": [
        { "recipient": "alerts@example.com" }
      ],
      "email_group_id_list": []
    }
  }
}
```

**SMTP account example:**

```json
{
  "config": {
    "name": "my-smtp-account",
    "description": "Corporate SMTP server",
    "config_type": "smtp_account",
    "is_enabled": true,
    "smtp_account": {
      "host": "smtp.example.com",
      "port": 587,
      "method": "start_tls",
      "from_address": "noreply@example.com"
    }
  }
}
```

**Webhook example:**

```json
{
  "config": {
    "name": "my-custom-webhook",
    "description": "Custom webhook for incident system",
    "config_type": "webhook",
    "is_enabled": true,
    "webhook": {
      "url": "https://incident.example.com/api/alert",
      "header_params": {
        "Content-Type": "application/json"
      },
      "method": "POST"
    }
  }
}
```

**Microsoft Teams example:**

```json
{
  "config": {
    "name": "my-teams-channel",
    "description": "Teams notifications",
    "config_type": "microsoft_teams",
    "is_enabled": true,
    "microsoft_teams": {
      "url": "https://outlook.office.com/webhook/..."
    }
  }
}
```

**SNS example:**

```json
{
  "config": {
    "name": "my-sns-topic",
    "description": "SNS notifications",
    "config_type": "sns",
    "is_enabled": true,
    "sns": {
      "topic_arn": "arn:aws:sns:us-east-1:123456789012:my-topic",
      "role_arn": "arn:aws:iam::123456789012:role/sns-publish-role"
    }
  }
}
```

**Response:**

```json
{
  "config_id": "<generated-config-id>"
}
```

---

### Update a Notification Config

Updates an existing notification channel configuration.

| | |
|---|---|
| **Method** | `PUT` |
| **URI** | `/_plugins/_notifications/configs/{config_id}` |

**Request body:** Same structure as create. All fields in the `config` object are replaced.

```json
{
  "config": {
    "name": "updated-slack-channel",
    "description": "Updated description",
    "config_type": "slack",
    "is_enabled": true,
    "slack": {
      "url": "https://hooks.slack.com/services/T00000000/B00000000/YYYYYYYY"
    }
  }
}
```

**Response:**

```json
{
  "config_id": "<config-id>"
}
```

---

### Get a Notification Config

Retrieves a specific notification configuration by ID.

| | |
|---|---|
| **Method** | `GET` |
| **URI** | `/_plugins/_notifications/configs/{config_id}` |

**Response:**

```json
{
  "config_list": [
    {
      "config_id": "<config-id>",
      "last_updated_time_ms": 1234567890,
      "created_time_ms": 1234567890,
      "config": {
        "name": "my-slack-channel",
        "description": "Slack notifications for alerts",
        "config_type": "slack",
        "is_enabled": true,
        "slack": {
          "url": "https://hooks.slack.com/services/..."
        }
      }
    }
  ],
  "total_hits": 1
}
```

---

### List Notification Configs

Retrieves notification configurations with filtering, sorting, and pagination.

| | |
|---|---|
| **Method** | `GET` |
| **URI** | `/_plugins/_notifications/configs` |

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `config_id` | String | Filter by a single config ID. |
| `config_id_list` | String | Comma-separated list of config IDs. |
| `from_index` | Integer | Pagination offset (default: `0`). |
| `max_items` | Integer | Maximum items to return (default: `100`). |
| `sort_field` | String | Field to sort by (e.g., `config_type`, `name`, `last_updated_time_ms`). |
| `sort_order` | String | Sort order: `asc` or `desc`. |
| `config_type` | String | Filter by channel type (e.g., `slack,email`). |
| `is_enabled` | Boolean | Filter by enabled status. |
| `name` | String | Filter by name (text search). |
| `description` | String | Filter by description (text search). |
| `last_updated_time_ms` | String | Range filter (e.g., `1609459200000..1640995200000`). |
| `created_time_ms` | String | Range filter. |
| `slack.url` | String | Filter by Slack webhook URL (text search). |
| `chime.url` | String | Filter by Chime webhook URL. |
| `microsoft_teams.url` | String | Filter by Teams webhook URL. |
| `webhook.url` | String | Filter by custom webhook URL. |
| `smtp_account.host` | String | Filter by SMTP host. |
| `smtp_account.from_address` | String | Filter by SMTP from address. |
| `smtp_account.method` | String | Filter by SMTP method (`ssl`, `start_tls`, `none`). |
| `sns.topic_arn` | String | Filter by SNS topic ARN. |
| `sns.role_arn` | String | Filter by SNS role ARN. |
| `ses_account.region` | String | Filter by SES region. |
| `ses_account.role_arn` | String | Filter by SES role ARN. |
| `ses_account.from_address` | String | Filter by SES from address. |
| `query` | String | Search across all keyword and text filter fields. |
| `text_query` | String | Search across text filter fields only. |

**Example:**

```bash
curl -sk -u admin:admin \
  "https://localhost:9200/_plugins/_notifications/configs?config_type=slack&max_items=10&sort_order=desc"
```

---

### Delete a Notification Config

Deletes one or more notification configurations.

| | |
|---|---|
| **Method** | `DELETE` |
| **URI** | `/_plugins/_notifications/configs/{config_id}` |

Or for bulk delete:

| | |
|---|---|
| **Method** | `DELETE` |
| **URI** | `/_plugins/_notifications/configs?config_id_list=id1,id2,id3` |

**Response:**

```json
{
  "delete_response_list": {
    "<config-id>": "OK"
  }
}
```

---

## Channels

### List Notification Channels

Returns a simplified list of all configured notification channels (ID, name, type, and enabled status).

| | |
|---|---|
| **Method** | `GET` |
| **URI** | `/_plugins/_notifications/channels` |

**Response:**

```json
{
  "channel_list": [
    {
      "config_id": "<id>",
      "name": "my-slack-channel",
      "config_type": "slack",
      "is_enabled": true
    }
  ],
  "total_hits": 1
}
```

---

## Features

### Get Plugin Features

Returns the notification features and allowed config types supported by the plugin.

| | |
|---|---|
| **Method** | `GET` |
| **URI** | `/_plugins/_notifications/features` |

**Response:**

```json
{
  "allowed_config_type_list": [
    "slack",
    "chime",
    "microsoft_teams",
    "webhook",
    "email",
    "sns",
    "ses_account",
    "smtp_account",
    "email_group"
  ],
  "plugin_features": {
    "tooltip_support": "true"
  }
}
```

---

## Test Notifications

### Send Test Notification

Sends a test notification to a configured channel to validate the configuration.

| | |
|---|---|
| **Method** | `POST` |
| **URI** | `/_plugins/_notifications/feature/test/{config_id}` |

> **Note:** `GET` is also supported for backwards compatibility but is deprecated and will be removed in a future major version.

**Example:**

```bash
curl -sk -u admin:admin -X POST \
  "https://localhost:9200/_plugins/_notifications/feature/test/<config-id>"
```

**Response:**

```json
{
  "status_list": [
    {
      "config_id": "<config-id>",
      "config_type": "slack",
      "config_name": "my-slack-channel",
      "delivery_status": {
        "status_code": "200",
        "status_text": "ok"
      }
    }
  ]
}
```

---

## Stats

### Get Plugin Stats

Returns internal plugin metrics and counters.

| | |
|---|---|
| **Method** | `GET` |
| **URI** | `/_plugins/_notifications/_local/stats` |

**Response:** A JSON object with flattened metric counters including:

- Request totals and interval counts for each API operation (create, update, delete, info, features, channels, send test).

---

## Summary Table

| Endpoint | Method | Description |
|---|---|---|
| `/_plugins/_notifications/configs` | `POST` | Create a new notification channel. |
| `/_plugins/_notifications/configs/{id}` | `PUT` | Update an existing notification channel. |
| `/_plugins/_notifications/configs/{id}` | `GET` | Get a specific notification channel. |
| `/_plugins/_notifications/configs` | `GET` | List/search notification channels with filters. |
| `/_plugins/_notifications/configs/{id}` | `DELETE` | Delete a notification channel. |
| `/_plugins/_notifications/configs` | `DELETE` | Bulk delete (with `config_id_list` param). |
| `/_plugins/_notifications/channels` | `GET` | List all channels (simplified view). |
| `/_plugins/_notifications/features` | `GET` | Get supported features and config types. |
| `/_plugins/_notifications/feature/test/{id}` | `POST` | Send a test notification. |
| `/_plugins/_notifications/_local/stats` | `GET` | Get plugin metrics. |
