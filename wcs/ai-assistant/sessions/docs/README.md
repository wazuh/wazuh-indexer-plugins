## `wazuh-ai-assistant-sessions` index data model

### Fields summary

The fields describe a user's conversation with the Wazuh AI assistant. Added by:

- [Create AI assistant index as part of setup initialization](https://github.com/wazuh/wazuh-indexer-plugins/pull/1424).


The detail of the fields can be found in the csv file [Fields](fields.csv).

### Data stream

- **Index pattern:** `wazuh-ai-assistant-sessions*`
- **ISM policy:** `ai-assistant-sessions-policy` — rolls over backing indices daily (or earlier at 20 GB per primary shard) and deletes rolled-over indices once they reach 7 days of age.

### Field table

| Field | Type | Level | Description |
|-------|------|-------|-------------|
| `@timestamp` | date | core | Date/time when the event originated. |
| `user` | keyword | custom | Name of the user the conversation belongs to. |
| `title` | keyword | custom | Title of the conversation, usually derived from the first message sent by the user. |
| `created_at` | date | custom | Date and time when the conversation was created. |
| `updated_at` | date | custom | Date and time when the conversation was last updated. |
| `messages` | object | custom | Conversation turns, stored verbatim to reconstruct the chat in the UI. Not indexed nor searchable: the shape varies by AI provider, so the object is stored in `_source` and returned as-is. |
