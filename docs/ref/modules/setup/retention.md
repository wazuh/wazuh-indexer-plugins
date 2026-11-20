# Retention

Stream indices (events, raw events, findings, metrics, active responses, AI assistant sessions and security audit logs) are data streams managed by [Index State Management (ISM)](https://docs.opensearch.org/3.6/im-plugin/ism/index/) policies shipped by the Setup plugin. These are Wazuh's [default policies](#default-policies): do not edit them through the ISM API or the dashboard. To change one, [edit its policy file](#changing-a-policy) instead. Each policy has two states:

- **`hot`** — runs a `rollover` action. The write index is closed and a new backing index is
  created once the index reaches **20 GB per primary shard** (or 200,000,000 documents,
  whichever comes first).
- **`delete`** — deletes the index. The `hot` state transitions to it once the policy's
  **deletion age** has passed since the index rolled over.

The two conditions are chained, not independent: ISM evaluates a state's transitions only after
that state's actions have completed. A backing index therefore becomes eligible for deletion only
**after it has rolled over**, and the deletion age (`min_rollover_age`) is measured from that
rollover, not from the creation of the index. Counting from the creation would delete a full index
as soon as it rolled over, because it took longer than the deletion age to fill, and the history
would drop to almost nothing at every rollover.

The AI assistant sessions and security audit log policies are the exception: they also roll over by
age, so every index is created at the previous rollover and `min_index_age`, measured from the
creation, is the retention.

## The retention formula

```
time an event is kept = time until its index rolls over (up to the fill time) + deletion age
```

**The deletion age is a floor, not a ceiling.**

- An event is kept for the deletion age after its index rolls over, so the history never drops
  below the deletion age at any moment, however fast indices fill. An event ingested just before a
  rollover is kept for the deletion age, and one ingested just after is kept for the fill time
  plus the deletion age.
- At high ingest rates the shard fills quickly and the deletion age dominates: retention is about
  the deletion age.
- At low ingest rates the fill time dominates: data is kept much longer than the number in the
  policy description suggests.

## Per-stream values

Every stream rolls over at 20 GB per primary shard or 200,000,000 documents. Only the AI assistant sessions and security audit log policies add an age condition to the rollover itself: `min_index_age: 1d` and `min_index_age: 30d`. Their deletion age counts from the creation of the index; the other five count it from the rollover.

| Policy | Streams | Rollover | Deletion age (floor) |
| --- | --- | --- | --- |
| `stream-events-policy` | `wazuh-events-v5-<category>` | 20 GB / 200M docs | 1 day after the rollover |
| `stream-raw-events-policy` | `wazuh-events-raw-v5` | 20 GB / 200M docs | 4 hours after the rollover |
| `stream-findings-policy` | `wazuh-findings-v5-<category>` | 20 GB / 200M docs | 90 days after the rollover |
| `stream-metrics-policy` | `wazuh-metrics-*` | 20 GB / 200M docs | 30 days after the rollover |
| `stream-active-responses-policy` | `wazuh-active-responses` | 20 GB / 200M docs | 3 days after the rollover |
| `ai-assistant-sessions-policy` | `wazuh-ai-assistant-sessions` | 1 day, or 20 GB / 200M docs | 7 days after the creation |
| `security-auditlogs-policy` | `security-auditlogs` | 30 days, or 20 GB / 200M docs | 90 days after the creation |

The AI assistant sessions and security audit log policies are the exception on purpose: a fixed retention only means something if indices roll over on a schedule, so those streams rotate by age. The audit log is also small, so without the monthly rollover it would never reach 20 GB and never be deleted. The other five rotate by volume.

## Disk sizing

Stream templates use one primary shard per index and `auto_expand_replicas: 0-1`, so on any
cluster of two or more nodes the on-disk cost doubles. The 200M document condition effectively
never fires first — at ~1 KB per event that would be 200 GB on a shard that rolls at 20 GB.

Per active event category the cost is the write index (up to 20 GB) plus the rolled-over indices
kept for the deletion age. Indices are deleted whole, so that is the ingest of the deletion age
rounded up to a whole number of 20 GB indices, and at least one. The table uses the 1-day deletion
age of `stream-events-policy`:

| Events ingest | Active categories | Fill time | Primaries (ceiling) | With 1 replica | Retention |
| --- | --- | --- | --- | --- | --- |
| 10 GB/day | 3 | ~6 days | ~120 GB | ~240 GB | 1 to ~7 days |
| 100 GB/day | 3 | ~14 h | ~180 GB | ~360 GB | 1 to ~1.6 days |
| 1 TB/day | 4 | ~2 h | ~1.1 TB | ~2.2 TB | 1 to ~1.1 days |
| 10 TB/day | 4 | ~12 min | ~10 TB | ~20 TB | ~1 day |

The ceiling is one deletion age of total event ingest plus up to 40 GB per active category (the
write index and the rounding up to a whole index), doubled if a replica is allocated. A longer
deletion age raises it in proportion: see [Keeping data longer](#keeping-data-longer) before you
change it. **Events have no unbounded-disk failure mode.** What is unbounded on a quiet deployment
is retention *time*, not disk.

The table assumes the default of one primary shard. The rollover condition is per primary shard, so a stream configured with more shards rolls over at 20 GB times its number of shards, and its write index and each index kept for the deletion age can be that large.

## Low-volume deployments retain data indefinitely

ISM never deletes a data stream's write index, and below 20 GB per primary shard the stream never
rolls over. On a low-volume deployment the events and raw events streams therefore **retain their
data indefinitely**: the backing index stays in the `hot` state on the `attempt_rollover` step
with `condition_not_met`, and the 1-day and 4-hour deletion ages never apply.

This is the designed behaviour — disk usage stays bounded — but it has a consequence worth
stating plainly:

> The deletion ages in these policies **cannot be used as privacy or compliance statements**.
> "Raw events are deleted 4 hours after the rollover" is only true of a deployment that fills 20 GB
> per primary shard. On a quiet deployment, raw events persist until the index rolls over or is
> removed by hand.

The same holds for findings, metrics and active responses. On a deployment that never fills a shard, findings are kept well past the 90-day deletion age. To delete them on a schedule, put an age condition on the rollover, as shown in [Changing a policy](#changing-a-policy).

You can confirm what a given backing index is doing:

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD \
  'https://localhost:9200/_plugins/_ism/explain/.ds-wazuh-events-v5-security-000001?pretty'
```

A response showing `"step": {"name": "attempt_rollover", "step_status": "condition_not_met"}` and
`"rolled_over": false` means the index has not yet met a rollover condition and is not eligible
for deletion.

## Default policies

The seven policies above are Wazuh's default policies. The Setup plugin indexes them by policy id whenever a node that has just started is elected cluster manager, which includes a full restart and every upgrade, so the policies a new release ships always reach the deployment. Each write overwrites whatever is stored under that id: an edit made to a default policy, through the ISM API or the dashboard, is reverted on the next full restart or upgrade. ISM cannot mark a policy as read-only, so nothing stops the edit in the first place.

**Do not edit the stored policies.** To change retention, [edit the policy file](#changing-a-policy) of the policy and turn on its switch in `setup.yml`: the Setup plugin then writes that file under the policy id, instead of the default policy, at every initialization. The Setup plugin only ever writes its own seven policy ids, so a policy stored under any other id is never touched.

## Existing indices keep the policy version they started with

Each managed index runs on its own copy of the policy, taken when the index was attached to it and returned by the explain API with `?show_policy=true`. Storing a new version of the policy, whether by an edit, a restart or an upgrade, changes neither that copy nor the retention of the indices already managed. Only backing indices created afterwards start on the new version. This has two consequences:

- A retention change applies to the existing indices only once you move them with `change_policy`, as shown in [Changing a policy](#changing-a-policy).
- After an upgrade that ships a new version of a default policy, the existing backing indices keep running the old version. On a low-volume deployment the write index never rolls over, so it can run the old version indefinitely.

To see which version each index runs, compare the `last_updated_time` of the stored policy with the one in the copy each index runs:

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD \
  'https://localhost:9200/_plugins/_ism/policies/stream-findings-policy' | jq '.policy.last_updated_time'

curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD \
  'https://localhost:9200/_plugins/_ism/explain/.ds-wazuh-findings-v5-*?show_policy=true' \
  | jq -r 'to_entries[] | select(.value | type == "object") | [.key, .value.policy_id, .value.policy.last_updated_time] | @tsv'
```

The Setup plugin writes the `last_updated_time` shipped with the release, or the one of the policy file when the policy is read from it. For a default policy it changes only when a release changes the policy, and an index with an older value runs an older version. An edit through the ISM API or the dashboard sets it to the time of the edit. Do not compare the `_seq_no` of the policy with the `policy_seq_no` of the index: every restart rewrites the default policies and raises their `_seq_no` even when their content does not change.

To move the existing indices onto the current version of a policy, run `change_policy` with the same policy id, then verify the switch as described in step 5 of [Changing a policy](#changing-a-policy). The same restart warning applies:

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X POST \
  'https://localhost:9200/_plugins/_ism/change_policy/.ds-wazuh-findings-v5-*' \
  -H 'Content-Type: application/json' -d '{"policy_id": "stream-findings-policy"}'
```

## Changing a policy

Each default policy has an editable copy, `<policy-id>.json`, in the [configuration directory](customization.md#the-configuration-directory) of the Setup plugin, and a switch in `setup.yml` that makes the plugin store that file instead of the default policy, under the same policy id. [Customization](customization.md#ism-policies) describes the switch. The steps below delete findings 30 days after their backing index is created, on any deployment, including those that never fill a shard. The same steps apply to any other stream, with its policy from the [per-stream table](#per-stream-values).

**1. Edit the policy file.** In `stream-findings-policy.json`, two changes set the retention and a third records the new version:

- `min_index_age` on the **rollover** action makes the write index roll over daily, so it becomes eligible for deletion even when it never fills a shard. Keep it shorter than the deletion age.
- `min_index_age` on the **transition** to `delete` is the deletion age, measured from index creation. It replaces the default policy's `min_rollover_age`, because a transition takes a single condition.
- `last_updated_time` is the current time in milliseconds, which `date +%s%3N` prints. It is how you tell later which version an index runs. Never set a time in the future: ISM applies a policy only to the indices created after it.

The `hot` state of the file then looks like this:

```json
{
  "name": "hot",
  "actions": [
    {
      "retry": { "count": 3, "backoff": "exponential", "delay": "1m" },
      "rollover": { "min_index_age": "1d", "min_doc_count": 200000000, "min_primary_shard_size": "20gb" }
    }
  ],
  "transitions": [
    { "state_name": "delete", "conditions": { "min_index_age": "30d" } }
  ]
}
```

Leave `policy_id` and the `ism_template` block as they are. ISM uses the index patterns of `ism_template` to attach the policy to the backing indices that a rollover creates: with other patterns those indices are left without a policy, and nothing deletes them.

**2. Turn the switch on.** In `setup.yml`:

```yaml
policies.stream-findings-policy.custom: true
```

**3. Restart the indexer.** The plugin reads the files when it initializes the cluster. On a cluster with several nodes, copy the same files to every cluster-manager-eligible node first, as described in [When changes take effect](customization.md#when-changes-take-effect). From then on, new findings backing indices run the edited policy.

**4. Move the existing indices onto it.** The existing indices keep the version they started with. `change_policy` with the same policy id moves them to the stored one:

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X POST \
  'https://localhost:9200/_plugins/_ism/change_policy/.ds-wazuh-findings-v5-*' \
  -H 'Content-Type: application/json' -d '{"policy_id": "stream-findings-policy"}'
```

**5. Wait for the change to apply, and verify it.** `change_policy` is asynchronous: the response lists the indices it queued, not the indices it changed. Each index switches on its next ISM run (every 5 minutes by default) and reports `Attempting to change policy to stream-findings-policy` until the following run resumes the policy, so the switch can take two runs or more. An index whose ISM run was interrupted by a recent restart of the node does not run again for up to an hour, and switches then. In order to make it run sooner: remove the policy from that index and add it back, with the two commands at the end of this step, and the index starts the stored policy at its next run. It is complete when every index reports a step name and the `last_updated_time` of the edited file:

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD \
  'https://localhost:9200/_plugins/_ism/explain/.ds-wazuh-findings-v5-*?show_policy=true' \
  | jq -r 'to_entries[] | select(.value | type == "object") | [.key, .value.policy.last_updated_time, (.value.step.name // "pending")] | @tsv'
```

**Do not restart the cluster until every index has switched.** A pending change survives a restart, but an index whose ISM run is interrupted while it switches stays on `Attempting to change policy to <policy_id>` for about an hour, then fails with `There is a version conflict between your previous execution and your managed index` and is no longer managed, so none of its retention applies. To list the indices in that state:

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD \
  'https://localhost:9200/_plugins/_ism/explain/.ds-wazuh-findings-v5-*' \
  | jq -r 'to_entries[] | select(.value | type == "object") | select(.value.retry_info.failed == true) | [.key, .value.policy_id, .value.info.message] | @tsv'
```

`_plugins/_ism/retry` and a new `change_policy` do not fix such an index. Remove the policy from it and add it back:

```bash
curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X POST \
  'https://localhost:9200/_plugins/_ism/remove/<index>'

curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X POST \
  'https://localhost:9200/_plugins/_ism/add/<index>' \
  -H 'Content-Type: application/json' -d '{"policy_id": "stream-findings-policy"}'
```

An index added back starts the policy again from its default state.

To go back to the default retention, set the switch back to `false`, restart, and run steps 4 and 5 again. The restart warning applies here too.

Weigh two trade-offs before you shorten retention this way:

- **More indices, more shards.** Rolling over on a schedule on a quiet deployment produces many small backing indices, each with its own shard overhead.
- **Data loss relative to today.** A deployment that currently keeps months of data inside a single 20 GB shard starts deleting it at the age you choose, existing data included once step 4 applies.

In a policy that rolls over by age, as in this example, keep `min_index_age` in the transition. `min_rollover_age` would stack the retention window on top of an already-full generation, which costs more disk at exactly the ingest rates where disk matters. The default policies of the streams that roll over by volume use `min_rollover_age` on purpose, so that the previous index is kept for the whole deletion age after it rolled over.

### Keeping data longer

To keep a stream longer without changing when it rolls over, for example to keep events for a weekend investigation window, change only the deletion age and leave the rollover as it is. In `stream-events-policy.json`, for 3 days of events, the transition of the `hot` state becomes:

```json
"transitions": [
  { "state_name": "delete", "conditions": { "min_rollover_age": "3d" } }
]
```

Set `last_updated_time`, turn on `policies.stream-events-policy.custom` and follow steps 3 to 5 with `stream-events-policy` as the policy id and `.ds-wazuh-events-v5-*` as the index pattern. The disk it needs grows with the deletion age, as the [Disk sizing](#disk-sizing) table shows: size the nodes for it before you apply the policy.

## Related

- [Customization](customization.md) — the configuration file of the Setup plugin and the policy files.
- [Architecture](architecture.md) — how the Setup plugin creates policies and data streams.
- [Setup plugin development](../../../dev/plugins/setup.md) — per-policy definitions and how to
  add a new one.
