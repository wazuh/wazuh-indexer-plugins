# Retention

Stream indices (events, raw events, findings, metrics, active responses and AI assistant
sessions) are data streams managed by [Index State Management (ISM)](https://docs.opensearch.org/3.6/im-plugin/ism/index/)
policies shipped by the Setup plugin. Each policy has two states:

- **`hot`** — runs a `rollover` action. The write index is closed and a new backing index is
  created once the index reaches **20 GB per primary shard** (or 200,000,000 documents,
  whichever comes first).
- **`delete`** — deletes the index. The `hot` state transitions to it once the index reaches the
  policy's **deletion age**.

The two conditions are chained, not independent: ISM evaluates a state's transitions only after
that state's actions have completed. A backing index therefore becomes eligible for deletion only
**after it has rolled over**, and `min_index_age` is measured from index creation.

## The retention formula

```
retention ≈ max(deletion age, time to fill 20 GB per primary shard)
```

**The deletion age is a floor, not a ceiling.**

- At high ingest rates the shard fills quickly and the deletion age binds: it guarantees *at
  least* that much history however fast indices fill.
- At low ingest rates the fill time dominates and the deletion age never binds: data is kept
  much longer than the number in the policy description suggests.

## Per-stream values

Every stream rolls over at 20 GB per primary shard or 200,000,000 documents. Only the AI
assistant sessions policy adds an age condition (`min_index_age: 1d`) to the rollover itself.

| Policy | Streams | Rollover | Deletion age (floor) |
| --- | --- | --- | --- |
| `stream-events-policy` | `wazuh-events-v5-<category>` | 20 GB / 200M docs | 1 hour |
| `stream-raw-events-policy` | `wazuh-events-raw-v5` | 20 GB / 200M docs | 10 minutes |
| `stream-findings-policy` | `wazuh-findings-v5-<category>` | 20 GB / 200M docs | 90 days |
| `stream-metrics-policy` | `wazuh-metrics-*` | 20 GB / 200M docs | 30 days |
| `stream-active-responses-policy` | `wazuh-active-responses` | 20 GB / 200M docs | 3 days |
| `ai-assistant-sessions-policy` | `wazuh-ai-assistant-sessions` | 1 day, or 20 GB / 200M docs | 7 days |

The AI assistant sessions policy is the exception on purpose: 7-day conversation retention only
means something if indices roll over on a daily schedule, so that stream rotates by age. The
other five rotate by volume.

## Disk sizing

Stream templates use one primary shard per index and `auto_expand_replicas: 0-1`, so on any
cluster of two or more nodes the on-disk cost doubles. The 200M document condition effectively
never fires first — at ~1 KB per event that would be 200 GB on a shard that rolls at 20 GB.

Per active event category the cost is the 20 GB write index plus the ingest accumulated during
the deletion-age window:

| Events ingest | Active categories | Fill time | Primaries | With 1 replica | Retention |
| --- | --- | --- | --- | --- | --- |
| 10 GB/day | 3 | ~6 days | ~60 GB | ~120 GB | ~6 days |
| 100 GB/day | 3 | ~14 h | ~64 GB | ~128 GB | ~14 h |
| 1 TB/day | 4 | ~2 h | ~120 GB | ~240 GB | ~2 h |
| 10 TB/day | 4 | ~12 min | ~500 GB | ~1 TB | 1 h (floor binds) |

The ceiling is one hour of total event ingest plus 20 GB per active category, doubled if a
replica is allocated. **Events have no unbounded-disk failure mode.** What is unbounded on a
quiet deployment is retention *time*, not disk.

## Low-volume deployments retain data indefinitely

ISM never deletes a data stream's write index, and below 20 GB per primary shard the stream never
rolls over. On a low-volume deployment the events and raw events streams therefore **retain their
data indefinitely**: the backing index stays in the `hot` state on the `attempt_rollover` step
with `condition_not_met`, and the 1-hour and 10-minute deletion ages never apply.

This is the designed behaviour — disk usage stays bounded — but it has a consequence worth
stating plainly:

> The deletion ages in these policies **cannot be used as privacy or compliance statements**.
> "Raw events are deleted after 10 minutes" is only true of a deployment that fills 20 GB per
> primary shard. On a quiet deployment, raw events persist until the index rolls over or is
> removed by hand.

You can confirm what a given backing index is doing:

```bash
curl -sk -u admin:admin \
  'https://localhost:9200/_plugins/_ism/explain/.ds-wazuh-events-v5-security-000001?pretty'
```

A response showing `"step": {"name": "attempt_rollover", "step_status": "condition_not_met"}` and
`"rolled_over": false` means the index has not yet met a rollover condition and is not eligible
for deletion.

## Opting in to a hard time ceiling

If your deployment needs retention bounded in *time* rather than in volume — a regulatory
maximum, or a data-minimization requirement — add an age condition to the **rollover** action, as
`ai-assistant-sessions-policy` does. This is the supported way to cap retention.

Choose a `min_index_age` shorter than the deletion age that follows it, then update the policy:

```bash
curl -sk -u admin:admin -X PUT \
  'https://localhost:9200/_plugins/_ism/policies/stream-events-policy?if_seq_no=<seq>&if_primary_term=<term>' \
  -H 'Content-Type: application/json' -d '{
  "policy": {
    "policy_id": "stream-events-policy",
    "description": "Events, capped at ~1 day of retention.",
    "default_state": "hot",
    "states": [
      {
        "name": "hot",
        "actions": [
          {
            "retry": { "count": 3, "backoff": "exponential", "delay": "1m" },
            "rollover": {
              "min_index_age": "1h",
              "min_doc_count": 200000000,
              "min_primary_shard_size": "20gb"
            }
          }
        ],
        "transitions": [
          { "state_name": "delete", "conditions": { "min_index_age": "1d" } }
        ]
      },
      {
        "name": "delete",
        "actions": [
          {
            "retry": { "count": 3, "backoff": "exponential", "delay": "1m" },
            "delete": {}
          }
        ],
        "transitions": []
      }
    ],
    "ism_template": [
      {
        "index_patterns": [".ds-wazuh-events-v5-*", "wazuh-events-v5*"],
        "priority": 0
      }
    ]
  }
}'
```

Fetch the current `_seq_no` and `_primary_term` first with
`GET _plugins/_ism/policies/stream-events-policy`, and apply the updated policy to the existing
managed indices with `POST _plugins/_ism/change_policy/<index-pattern>`.

Two trade-offs to weigh before doing this:

- **More indices, more shards.** Rolling over on a schedule on a quiet deployment produces many
  small backing indices, each with its own shard overhead.
- **Data loss relative to today.** A deployment that currently keeps months of events inside a
  single 20 GB shard will start ageing them out at the ceiling you choose.

Do **not** use `min_rollover_age` in the transition instead: it expresses "N after rollover",
stacking the retention window on top of an already-full generation, which costs more disk at
exactly the ingest rates where disk matters.

## Related

- [Architecture](architecture.md) — how the Setup plugin creates policies and data streams.
- [Setup plugin development](../../../dev/plugins/setup.md) — per-policy definitions and how to
  add a new one.
