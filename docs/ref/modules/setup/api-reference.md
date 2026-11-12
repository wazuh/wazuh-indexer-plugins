# API reference

The Setup plugin exposes a REST API under `/_plugins/_setup/`. All endpoints require authentication.

---

## Settings

### Update settings

Persists configuration settings to the `.wazuh-settings` index. Currently, it supports the `engine.index_raw_events` boolean flag, which controls whether the Engine indexes raw events into the `wazuh-events-raw-v5` data stream.

#### Request

- Method: `PUT`
- Path: `/_plugins/_setup/settings`

#### Request body

- **`engine`** (Object, required) — Engine settings object.
- **`engine.index_raw_events`** (Boolean, required) — whether the Engine indexes raw events into the `wazuh-events-raw-v5` data stream.

#### Example request

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X PUT \
  "https://127.0.0.1:9200/_plugins/_setup/settings" \
  -H 'Content-Type: application/json' \
  -d '{
    "engine": {
      "index_raw_events": true
    }
  }'
```

#### Example response (success)

```json
{
  "message": "Settings updated successfully.",
  "status": 200
}
```

#### Example response (missing field)

```json
{
  "message": "Missing required field: 'engine.index_raw_events'.",
  "status": 400
}
```

#### Example response (invalid type)

```json
{
  "message": "Field 'engine.index_raw_events' must be of type boolean.",
  "status": 400
}
```

#### Example response (settings updates disabled)

```json
{
  "message": "Setup settings updates are disabled on this deployment.",
  "status": 403
}
```

#### Status codes

- **200** — settings updated successfully.
- **400** — invalid request body, missing required fields, or wrong field type.
- **403** — settings updates are disabled on the node (`plugins.setup.settings_update.enabled` is `false`), which applies to every caller regardless of role, or the caller lacks the `plugin:wazuh/settings/write` cluster permission. See [Configuration](configuration.md).
- **500** — internal server error (e.g., failed to persist settings to the index).

---

## AI Assistant Settings

Reads and writes the reserved settings document of the AI assistant in `.wazuh-internal-state`,
which holds the privacy defaults and the field policy applied to the data the assistant is shown.
Providers are stored as separate documents; see [AI Assistant Providers](#ai-assistant-providers).

### Read the settings

#### Request

- Method: `GET`
- Path: `/_plugins/_setup/ai_assistant/settings`
- Permission: `plugin:wazuh/ai_assistant/settings/read`

#### Example response

```json
{
  "privacy_default_on": false,
  "privacy_default_per_provider": {},
  "user_can_override": true,
  "field_policy": [
    { "field": "wazuh.agent.name", "action": "anonymize", "kind": "HOST" },
    { "field": "wazuh.agent.host.ip", "action": "anonymize", "kind": "IP" },
    { "field": "wazuh.agent.id", "action": "allow" }
  ]
}
```

#### Status codes

- **200** — settings returned.
- **403** — the caller lacks the `plugin:wazuh/ai_assistant/settings/read` cluster permission.

### Update the settings

Persists the settings and the `field_policy`. Any key outside the allowlist below is **ignored, not
rejected**.

#### Request

- Method: `PUT`
- Path: `/_plugins/_setup/ai_assistant/settings`
- Permission: `plugin:wazuh/ai_assistant/settings/write`

#### Request body

- **`privacy_default_on`** (Boolean) — whether privacy is on by default.
- **`privacy_default_per_provider`** (Object) — per-provider overrides of that default.
- **`user_can_override`** (Boolean) — whether a user may change the privacy default.
- **`field_policy`** (Array) — one entry per field, each with `field`, `action` and, for an
  anonymized field, `kind`.

#### Example response

```json
{
  "message": "Settings updated.",
  "status": 200
}
```

#### Status codes

- **200** — settings updated.
- **400** — empty or malformed request body.
- **403** — the caller lacks the `plugin:wazuh/ai_assistant/settings/write` cluster permission.

---

## AI Assistant Providers

Each provider the assistant can talk to is its own document in `.wazuh-internal-state`. The
reserved document ids `wazuh-ai-assistant-settings` and `credentials` are refused by the write
endpoints rather than written or deleted.

### List the providers

#### Request

- Method: `GET`
- Path: `/_plugins/_setup/ai_assistant/providers`
- Permission: `plugin:wazuh/ai_assistant/settings/read`

#### Example response

```json
{
  "providers": [
    {
      "_id": "8c11c90d-1ead-4901-a5f0-1bd6d0a931cb",
      "name": "test-ai",
      "type": "anthropic",
      "base_url": "https://api.anthropic.com",
      "model": "claude-opus-4-6",
      "api_key": "enc:v1:SC/RyOIBkdm+kGl",
      "is_default": true
    }
  ]
}
```

#### Status codes

- **200** — provider list returned.
- **403** — the caller lacks the `plugin:wazuh/ai_assistant/settings/read` cluster permission.

### Create a provider

The body carries the document id, which must be a UUID and is never persisted as a provider field.

#### Request

- Method: `POST`
- Path: `/_plugins/_setup/ai_assistant/providers`
- Permission: `plugin:wazuh/ai_assistant/settings/write`

#### Request body

- **`id`** (String, required) — the document id to create the provider with. Must be a UUID.
- **`name`** (String) — display name.
- **`type`** (String) — provider type, for example `anthropic`.
- **`base_url`** (String) — API base URL.
- **`model`** (String) — model identifier.
- **`api_key`** (String) — the provider's API key, stored exactly as sent.
- **`is_default`** (Boolean) — whether this is the default provider.
- **`updated_at`** (String) — ignored if sent; always overwritten with a server-stamped timestamp.

#### Example request

```json
{
  "id": "8c11c90d-1ead-4901-a5f0-1bd6d0a931cb",
  "name": "test-ai",
  "type": "anthropic",
  "base_url": "https://api.anthropic.com",
  "model": "claude-opus-4-6",
  "api_key": "enc:v1:SC/RyOIBkdm+kGl",
  "is_default": true
}
```

#### Example response

```json
{
  "message": "Provider saved.",
  "status": 200,
  "id": "8c11c90d-1ead-4901-a5f0-1bd6d0a931cb"
}
```

#### Status codes

- **200** — provider created. `200`, not `201`.
- **400** — empty or malformed body, a missing `id`, an `id` that is not a UUID, or any field outside the provider schema: the backing index is `dynamic: strict`, so an unknown key is rejected rather than ignored.
- **403** — the caller lacks the `plugin:wazuh/ai_assistant/settings/write` cluster permission.

### Update a provider

Creates or updates the provider with the given id. Unlike create, the path segment is not
restricted to a UUID.

#### Request

- Method: `PUT`
- Path: `/_plugins/_setup/ai_assistant/providers/{id}`
- Permission: `plugin:wazuh/ai_assistant/settings/write`

#### Request body

The same fields as create, without `id` — the path segment carries it.

#### Status codes

- **200** — provider saved.
- **400** — empty or malformed body, any field outside the provider schema (the backing index is
  `dynamic: strict`), or a path `id` that is one of the reserved document ids
  (`wazuh-ai-assistant-settings`, `credentials`).
- **403** — the caller lacks the `plugin:wazuh/ai_assistant/settings/write` cluster permission.

### Delete a provider

#### Request

- Method: `DELETE`
- Path: `/_plugins/_setup/ai_assistant/providers/{id}`
- Permission: `plugin:wazuh/ai_assistant/settings/write`

#### Status codes

- **200** — provider deleted.
- **400** — the path `id` is one of the reserved document ids (`wazuh-ai-assistant-settings`,
  `credentials`).
- **403** — the caller lacks the `plugin:wazuh/ai_assistant/settings/write` cluster permission.
- **404** — no provider exists with the given id. A repeated delete also returns `404`.

---

## AI Assistant Sessions

Writes to the caller's own AI assistant sessions, stored in the `wazuh-ai-assistant-sessions` data
stream. Every operation requires the `plugin:wazuh/ai_assistant/session/write` cluster permission,
which the `wazuh_ai_assistant` role — mapped to every authenticated user — grants.

**`user` is derived from the authenticated caller, not from the request body.** A value sent for it
is discarded, so a session can only ever be created under the caller's own name. Update, rename and
delete load the stored session first and refuse anything that is not the caller's, reported as
`404` rather than `403` so the response does not confirm that somebody else's session id exists.

**There are no read endpoints, by design.** Listing sessions and reading a transcript are direct
queries against the data stream, scoped by the role's Document Level Security filter
(`{"term": {"user": "${user.name}"}}`), which correctly scopes reads and gives you OpenSearch's own
search, sorting and pagination. See
[Access control](../../security/access-control.md#wazuh_ai_assistant).

### Optimistic concurrency

Every write returns an opaque **`version`** token. A data stream permits no unconditional write to
one of its backing indices, so every write carries a concurrency check; `version` is what makes that
check visible to clients. Remember the token from the last response seen for a session and send it
back as `expected_version` on the next `PUT` — never parse or compare it.

On `409`, re-read the session from the index with `seq_no_primary_term: true`, merge, and retry with
the version that read returned. Do not retry with a freshly read version without merging: that is
the silent overwrite `expected_version` exists to prevent.

### Create a session

Only `title` and `messages` are persisted. `user`, `created_at`, `updated_at` and `@timestamp` are
stamped by the server; values sent for them, and any key outside the allowlist, are **discarded, not
rejected**, so a client may POST back a document it previously read. The id is generated by the
server: the data stream mints it, and client-chosen ids are not supported.

#### Request

- Method: `POST`
- Path: `/_plugins/_setup/ai_assistant/sessions`

#### Request body

- **`title`** (String, required) — must contain something other than whitespace, 200 characters or
  fewer. Trimmed before storing.
- **`messages`** (Array, required) — the transcript, up to 1000 entries. May be `[]` to open a blank
  session. Each entry is treated as an opaque object: `messages` is mapped as
  `{"type": "object", "enabled": false}`, so entries are stored and returned verbatim but never
  indexed or schema-checked, and a provider returning unanticipated fields cannot break saving.

The whole request body must be **5 MiB or smaller**, on every write route. The entry count bounds
how many turns a session holds but not how large each one is; without a byte ceiling the only limit
would be the cluster's `http.max_content_length` (100MB by default), which would make the
500-session per-owner cap meaningless as a storage bound. Oversized bodies are rejected with `400`
before being parsed.

#### Example request

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X POST \
  "https://127.0.0.1:9200/_plugins/_setup/ai_assistant/sessions" \
  -H 'Content-Type: application/json' \
  -d '{
    "title": "Any brute force attempts today?",
    "messages": [
      { "role": "user", "content": "Any brute force attempts today?", "createdAt": 1788961419723 }
    ]
  }'
```

#### Example response (success)

```json
{
  "id": "8itvhqABtpJqXy3PWi31",
  "title": "Any brute force attempts today?",
  "created_at": "2026-09-09T13:50:39.861Z",
  "updated_at": "2026-09-09T13:50:39.861Z",
  "messages": [
    { "role": "user", "content": "Any brute force attempts today?", "createdAt": 1788961419723 }
  ],
  "version": "12:1"
}
```

#### Status codes

- **200** — session created. `200`, not `201`, matching [`POST /_plugins/_setup/ai_assistant/providers`](#create-a-provider).
- **400** — empty or malformed body; a missing, blank or over-long `title`; a missing `messages`; more than 1000 messages; a body over 5 MiB.
- **403** — the caller lacks the `plugin:wazuh/ai_assistant/session/write` cluster permission.
- **409** — the caller already owns the maximum of 500 sessions. `409` rather than `400`: the request is well formed, it is the stored state that blocks it. Deleting a session frees a slot; updating an existing session is never blocked by the cap.

### Replace a session's transcript

Replaces `messages`, and `title` when one is sent. `user`, `created_at` and `@timestamp` are carried
over from the stored session; `updated_at` is re-stamped.

#### Request

- Method: `PUT`
- Path: `/_plugins/_setup/ai_assistant/sessions/{id}`

#### Request body

- **`messages`** (Array, required) — replaces the stored transcript wholesale. Up to 1000 entries.
- **`title`** (String, optional) — **optional on purpose.** A chat client auto-saves on every turn;
  if each save resent a recomputed title it would silently revert a rename the user had just made.
  When absent, the stored title is kept.
- **`expected_version`** (String, optional) — the `version` the client last saw. When present, the
  write is rejected with `409` if the stored session has moved past it. When absent, the write still
  carries the version this request just read, so the check narrows to "since this request started"
  rather than being disabled.

#### Example request

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X PUT \
  "https://127.0.0.1:9200/_plugins/_setup/ai_assistant/sessions/8itvhqABtpJqXy3PWi31" \
  -H 'Content-Type: application/json' \
  -d '{
    "messages": [
      { "role": "user", "content": "Any brute force attempts today?", "createdAt": 1788961419723 },
      { "role": "assistant", "content": "No brute force activity in the last 24 hours.", "createdAt": 1788961419744 }
    ],
    "expected_version": "12:1"
  }'
```

#### Example response (conflict)

```json
{
  "message": "Session was updated by another session since you last loaded it. Refresh and retry.",
  "status": 409
}
```

#### Status codes

- **200** — session updated. Returns the full session with the write's own fresh `version`.
- **400** — empty or malformed body; a `title` that is present but blank or over-long; a missing `messages`; more than 1000 messages; a body over 5 MiB.
- **403** — the caller lacks the cluster permission.
- **404** — no session exists with the given id, **or it belongs to another user**.
- **409** — the session changed since the version being checked against. The write was not applied.

### Rename a session

Changes `title` and nothing else. `messages`, `user`, `created_at` and `@timestamp` are carried over
untouched, and **`updated_at` is deliberately not re-stamped**: a rename is not session activity, and
bumping it would reorder a session list sorted by last activity.

Separate from `PUT` because a rename happens from a list row, where the client holds only a summary
and not the transcript.

#### Request

- Method: `PATCH`
- Path: `/_plugins/_setup/ai_assistant/sessions/{id}`

#### Request body

- **`title`** (String, required) — must contain something other than whitespace, 200 characters or
  fewer. Trimmed before storing.

#### Example request

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X PATCH \
  "https://127.0.0.1:9200/_plugins/_setup/ai_assistant/sessions/8itvhqABtpJqXy3PWi31" \
  -H 'Content-Type: application/json' \
  -d '{ "title": "Agent 003 connectivity" }'
```

#### Example response (success)

```json
{
  "id": "8itvhqABtpJqXy3PWi31",
  "title": "Agent 003 connectivity",
  "updated_at": "2026-09-09T13:44:09.066Z",
  "version": "13:1"
}
```

The response carries the write's own fresh `version`, so a client whose renamed session is also the
open one does not conflict on its next auto-save.

#### Status codes

- **200** — session renamed.
- **400** — empty or malformed body; a `title` that is blank, whitespace-only or over-long; a body over 5 MiB.
- **403** — the caller lacks the cluster permission.
- **404** — no session exists with the given id, or it belongs to another user.
- **409** — the session was written or deleted between this request's read and its write.

### Delete a session

Ownership is checked against the stored session first; one belonging to another user is reported as
`404` and left untouched.

#### Request

- Method: `DELETE`
- Path: `/_plugins/_setup/ai_assistant/sessions/{id}`

#### Example request

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X DELETE \
  "https://127.0.0.1:9200/_plugins/_setup/ai_assistant/sessions/8itvhqABtpJqXy3PWi31"
```

#### Example response (success)

```json
{
  "message": "Session deleted.",
  "status": 200,
  "id": "8itvhqABtpJqXy3PWi31"
}
```

#### Status codes

- **200** — session deleted.
- **403** — the caller lacks the cluster permission.
- **404** — no session exists with the given id, or it belongs to another user. A repeated delete also returns `404`.

---

> **Documentation maintenance** — modifications to the REST API must be reflected in both `openapi.yml` and this file.
