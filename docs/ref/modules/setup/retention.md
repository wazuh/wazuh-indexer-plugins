# Retention

Stream indices (events, raw events, findings, metrics, active responses and AI assistant sessions) are data streams managed by [Index State Management (ISM)](https://docs.opensearch.org/3.6/im-plugin/ism/index/) policies shipped by the Setup plugin. These are Wazuh's [default policies](#default-policies): do not edit them, create a [custom policy](#creating-a-custom-policy) instead. Each policy has two states:

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

The same holds for findings, metrics and active responses. On a deployment that never fills a shard, findings are kept well past the 90-day deletion age. To delete them on a schedule, put an age condition on the rollover in a [custom policy](#creating-a-custom-policy).

You can confirm what a given backing index is doing:

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD \
  'https://localhost:9200/_plugins/_ism/explain/.ds-wazuh-events-v5-security-000001?pretty'
```

A response showing `"step": {"name": "attempt_rollover", "step_status": "condition_not_met"}` and
`"rolled_over": false` means the index has not yet met a rollover condition and is not eligible
for deletion.

## Default policies

The six policies above are Wazuh's default policies. The Setup plugin indexes them by policy id whenever a node is elected cluster manager, which includes every restart and every upgrade, so the policies a new release ships always reach the deployment. Each write overwrites whatever is stored under that id: an edit made to a default policy, through the ISM API or the dashboard, is reverted on the next restart. ISM cannot mark a policy as read-only, so nothing stops the edit in the first place.

**Do not edit the default policies.** To change retention, [create a custom policy](#creating-a-custom-policy) instead. The Setup plugin only ever writes its own six policy ids, so a policy stored under any other id is never touched.

## Existing indices keep the policy version they started with

Each managed index runs on its own copy of the policy, taken when the index was attached to it and reported as `policy_seq_no` by the explain API. Storing a new version of the policy, whether by an edit, a restart or an upgrade, changes neither that copy nor the retention of the indices already managed. Only backing indices created afterwards start on the new version. This has two consequences:

- A retention change applies to the existing indices only once you move them with `change_policy`, as shown in [Creating a custom policy](#creating-a-custom-policy).
- After an upgrade that ships a new version of a default policy, the existing backing indices keep running the old version. On a low-volume deployment the write index never rolls over, so it can run the old version indefinitely.

To see which version each index runs, compare its `policy_seq_no` with the `_seq_no` of the stored policy:

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD \
  'https://localhost:9200/_plugins/_ism/policies/stream-findings-policy' | jq '._seq_no'

curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD \
  'https://localhost:9200/_plugins/_ism/explain/.ds-wazuh-findings-v5-*' \
  | jq -r 'to_entries[] | select(.value | type == "object") | [.key, .value.policy_id, .value.policy_seq_no] | @tsv'
```

Every restart rewrites the default policies, so their `_seq_no` grows even when their content does not change, and a lower `policy_seq_no` does not by itself mean that the index runs different rules. Add `?show_policy=true` to the explain request to see the copy the index runs.

To move the existing indices onto the current version of a policy, run `change_policy` with the same policy id, then verify the switch as described in step 4 of [Creating a custom policy](#creating-a-custom-policy):

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X POST \
  'https://localhost:9200/_plugins/_ism/change_policy/.ds-wazuh-findings-v5-*' \
  -H 'Content-Type: application/json' -d '{"policy_id": "stream-findings-policy"}'
```

## Creating a custom policy

ISM cannot clone a policy, so a custom policy starts as a copy of the default one. The steps below delete findings 30 days after their backing index is created, on any deployment, including those that never fill a shard. The same steps apply to any other stream: use its policy and index patterns from the [per-stream table](#per-stream-values). The commands use `jq`.

**1. Copy the default policy and change the copy.** Two changes set the retention, and a third makes the policy win over the default one:

- `min_index_age` on the **rollover** action makes the write index roll over daily, so it becomes eligible for deletion even when it never fills a shard. Keep it shorter than the deletion age.
- `min_index_age` on the **transition** to `delete` is the deletion age, measured from index creation.
- `priority: 1` in the `ism_template` makes ISM attach new backing indices to this policy instead of the default one (`priority: 0`).

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD \
  'https://localhost:9200/_plugins/_ism/policies/stream-findings-policy' \
  | jq '{policy: (.policy
      | del(.policy_id, .last_updated_time, .schema_version, .error_notification)
      | .description = "Custom findings policy: deletes findings 30 days after their backing index is created."
      | .states[0].actions[0].rollover.min_index_age = "1d"
      | .states[0].transitions[0].conditions.min_index_age = "30d"
      | .ism_template[].priority = 1)}' > custom-findings-policy.json
```

Review `custom-findings-policy.json` before going further.

**2. Store the copy under its own policy id.**

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X PUT \
  'https://localhost:9200/_plugins/_ism/policies/custom-findings-policy' \
  -H 'Content-Type: application/json' -d @custom-findings-policy.json
```

From now on, new findings backing indices are attached to `custom-findings-policy`.

**3. Move the existing indices onto it.** The `ism_template` applies only to indices created from now on, and the existing ones keep the policy they started with:

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X POST \
  'https://localhost:9200/_plugins/_ism/change_policy/.ds-wazuh-findings-v5-*' \
  -H 'Content-Type: application/json' -d '{"policy_id": "custom-findings-policy"}'
```

**4. Wait for the change to apply, and verify it.** `change_policy` is asynchronous: the response lists the indices it queued, not the indices it changed. Each index switches on its next ISM run (every 5 minutes by default) and reports `Attempting to change policy to custom-findings-policy` until the following run resumes the policy, so the switch can take two runs or more. It is complete when every index reports the new `policy_id` and a step name:

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD \
  'https://localhost:9200/_plugins/_ism/explain/.ds-wazuh-findings-v5-*' \
  | jq -r 'to_entries[] | select(.value | type == "object") | [.key, .value.policy_id, (.value.step.name // "pending")] | @tsv'
```

**Do not restart the cluster until every index has switched.** A restart while the change is still pending drops it, and you are left with some indices on your policy and some on the default one.

To go back to the default retention, run step 3 with `"policy_id": "stream-findings-policy"`, wait for the switch as in step 4, then delete `custom-findings-policy`.

Weigh two trade-offs before you shorten retention this way:

- **More indices, more shards.** Rolling over on a schedule on a quiet deployment produces many small backing indices, each with its own shard overhead.
- **Data loss relative to today.** A deployment that currently keeps months of data inside a single 20 GB shard starts deleting it at the age you choose, existing data included once step 3 applies.

Do **not** use `min_rollover_age` in the transition instead of the rollover condition: it expresses "N after rollover", stacking the retention window on top of an already-full generation, which costs more disk at exactly the ingest rates where disk matters.

## Related

- [Architecture](architecture.md) — how the Setup plugin creates policies and data streams.
- [Setup plugin development](../../../dev/plugins/setup.md) — per-policy definitions and how to
  add a new one.
