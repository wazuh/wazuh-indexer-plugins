# API reference

All Notification plugin endpoints use the base path `/_plugins/_notifications`.

---

## Notification configs

### Create a notification config

Creates a new notification channel configuration.

- Method: `POST`
- Path: `/_plugins/_notifications/configs`

#### Request body

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

#### Slack example

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

#### Email example (with SMTP account)

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

#### SMTP account example

```json
{
  "config": {
    "name": "my_smtp_account",
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

#### Webhook example

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

#### Microsoft Teams example

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

#### SNS example

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

#### Active response example

An `active_response` channel is the target of [Active Response](../alerting/index.md#active-response) monitors. Instead of sending a message, each notification writes an execution request to the `wazuh-active-responses` data stream, from which the Wazuh Manager runs `executable` on the target agents.

```json
{
  "config": {
    "name": "block-source-ip",
    "description": "Block the source IP address on the agent that reported the event",
    "config_type": "active_response",
    "is_enabled": true,
    "active_response": {
      "type": "stateful",
      "stateful_timeout": 600,
      "executable": "block-ip",
      "location": "local"
    }
  }
}
```

- **`type`** (required) — `stateless` runs the command once; `stateful` also asks the agent to revert it after `stateful_timeout`.
- **`stateful_timeout`** (Integer) — required, and greater than `0`, when `type` is `stateful`.
- **`executable`** (required) — the command to run on the agent.
- **`extra_args`** (String) — additional arguments for the command.
- **`location`** (required) — `local` (the agent that reported the event), `defined-agent` (the agent in `agent_id`), or `all` (every agent).
- **`agent_id`** (String) — numeric agent ID. Required when `location` is `defined-agent`.

#### Response

```json
{
  "config_id": "<generated-config-id>"
}
```

---

### Update a notification config

Updates an existing notification channel configuration.

- Method: `PUT`
- Path: `/_plugins/_notifications/configs/{config_id}`

#### Request body

Same structure as create. All fields in the `config` object are replaced.

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

#### Response

```json
{
  "config_id": "<config-id>"
}
```

---

### Get a notification config

Retrieves a specific notification configuration by ID.

- Method: `GET`
- Path: `/_plugins/_notifications/configs/{config_id}`

#### Response

```json
{
  "start_index": 0,
  "total_hits": 1,
  "total_hit_relation": "eq",
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
  ]
}
```

---

### List notification configs

Retrieves notification configurations with filtering, sorting, and pagination.

- Method: `GET`
- Path: `/_plugins/_notifications/configs`

#### Query parameters

- **`config_id`** (String) — filter by a single config ID.
- **`config_id_list`** (String) — comma-separated list of config IDs.
- **`from_index`** (Integer, default `0`) — pagination offset.
- **`max_items`** (Integer, default `100`) — maximum items to return.
- **`sort_field`** (String) — field to sort by (e.g., `config_type`, `name`, `last_updated_time_ms`).
- **`sort_order`** (String) — sort order: `asc` or `desc`.
- **`config_type`** (String) — filter by channel type (e.g., `slack,email`).
- **`is_enabled`** (Boolean) — filter by enabled status.
- **`name`** (String) — filter by name (text search).
- **`description`** (String) — filter by description (text search).
- **`last_updated_time_ms`** (String) — range filter (e.g., `1609459200000..1640995200000`).
- **`created_time_ms`** (String) — range filter.
- **`slack.url`** (String) — filter by Slack webhook URL (text search).
- **`chime.url`** (String) — filter by Chime webhook URL.
- **`microsoft_teams.url`** (String) — filter by Teams webhook URL.
- **`webhook.url`** (String) — filter by custom webhook URL.
- **`smtp_account.host`** (String) — filter by SMTP host.
- **`smtp_account.from_address`** (String) — filter by SMTP from address.
- **`smtp_account.method`** (String) — filter by SMTP method (`ssl`, `start_tls`, `none`).
- **`sns.topic_arn`** (String) — filter by SNS topic ARN.
- **`sns.role_arn`** (String) — filter by SNS role ARN.
- **`ses_account.region`** (String) — filter by SES region.
- **`ses_account.role_arn`** (String) — filter by SES role ARN.
- **`ses_account.from_address`** (String) — filter by SES from address.
- **`email.email_account_id`** (String) — filter by the sender account config ID of `email` channels.
- **`email.email_group_id_list`** (String) — filter by email group config ID.
- **`email.recipient_list.recipient`** (String) — filter by a recipient of `email` channels (text search).
- **`email_group.recipient_list.recipient`** (String) — filter by a recipient of `email_group` configs (text search).
- **`active_response.type`** (String) — filter by Active Response type (`stateless`, `stateful`).
- **`active_response.executable`** (String) — filter by Active Response executable.
- **`active_response.extra_args`** (String) — filter by Active Response extra arguments.
- **`active_response.location`** (String) — filter by Active Response location (`local`, `defined-agent`, `all`).
- **`active_response.agent_id`** (String) — filter by Active Response target agent ID.
- **`active_response.stateful_timeout`** (String) — filter by Active Response stateful timeout.
- **`query`** (String) — search across all keyword and text filter fields.
- **`text_query`** (String) — search across text filter fields only.

Text filters also accept a `.keyword` suffix for an exact match, for example `name.keyword` or `active_response.executable.keyword`. The two `recipient_list.recipient` filters are the exception: they accept only the text form.

#### Example

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD \
  "https://127.0.0.1:9200/_plugins/_notifications/configs?config_type=slack&max_items=10&sort_order=desc"
```

---

### Delete a notification config

Deletes one or more notification configurations.

- Method: `DELETE`
- Path: `/_plugins/_notifications/configs/{config_id}`

Or for bulk delete:

- Method: `DELETE`
- Path: `/_plugins/_notifications/configs?config_id_list=id1,id2,id3`

#### Response

```json
{
  "delete_response_list": {
    "<config-id>": "OK"
  }
}
```

---

## Channels

### List notification channels

Returns a simplified list of all configured notification channels (ID, name, type, and enabled status).

- Method: `GET`
- Path: `/_plugins/_notifications/channels`

#### Response

```json
{
  "start_index": 0,
  "total_hits": 1,
  "total_hit_relation": "eq",
  "channel_list": [
    {
      "config_id": "<id>",
      "name": "my-slack-channel",
      "description": "Slack notifications for alerts",
      "config_type": "slack",
      "is_enabled": true
    }
  ]
}
```

---

## Features

### Get plugin features

Returns the notification features and allowed config types supported by the plugin.

- Method: `GET`
- Path: `/_plugins/_notifications/features`

#### Response

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
    "email_group",
    "active_response"
  ],
  "plugin_features": {
    "tooltip_support": "true"
  }
}
```

---

## Test notifications

### Send test notification

Sends a test notification to a configured channel to validate the configuration.

- Method: `POST`
- Path: `/_plugins/_notifications/feature/test/{config_id}`

> **Note:** `GET` is also supported for backwards compatibility but is deprecated and will be removed in a future major version.

#### Example

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X POST \
  "https://127.0.0.1:9200/_plugins/_notifications/feature/test/<config-id>"
```

#### Response

```json
{
  "event_source": {
    "title": "Test Message Title-<config-id>",
    "reference_id": "<config-id>",
    "severity": "info",
    "tags": []
  },
  "status_list": [
    {
      "config_id": "<config-id>",
      "config_type": "slack",
      "config_name": "my-slack-channel",
      "email_recipient_status": [],
      "delivery_status": {
        "status_code": "200",
        "status_text": "ok"
      }
    }
  ]
}
```

---

## Summary table

| Endpoint                                     | Method   | Description                                     |
| -------------------------------------------- | -------- | ----------------------------------------------- |
| `/_plugins/_notifications/configs`           | `POST`   | Create a new notification channel.              |
| `/_plugins/_notifications/configs/{id}`      | `PUT`    | Update an existing notification channel.        |
| `/_plugins/_notifications/configs/{id}`      | `GET`    | Get a specific notification channel.            |
| `/_plugins/_notifications/configs`           | `GET`    | List/search notification channels with filters. |
| `/_plugins/_notifications/configs/{id}`      | `DELETE` | Delete a notification channel.                  |
| `/_plugins/_notifications/configs`           | `DELETE` | Bulk delete (with `config_id_list` param).      |
| `/_plugins/_notifications/channels`          | `GET`    | List all channels (simplified view).            |
| `/_plugins/_notifications/features`          | `GET`    | Get supported features and config types.        |
| `/_plugins/_notifications/feature/test/{id}` | `POST`   | Send a test notification.                       |
