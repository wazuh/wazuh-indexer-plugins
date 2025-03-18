## `commands` index data model

> [!NOTE]
> rev 0.1 - September 18th, 2024: Add initial model.
> rev 0.2 - September 30th, 2024: Change type of `request_id`, `order_id` and `id` to keyword.
> rev 0.3 - October 3rd, 2024: Change descriptions for `command.type`, `command.action.type`, `command.request_id`, `command.order_id`.
> rev 0.4 - October 9th, 2024: Apply changes described in https://github.com/wazuh/wazuh-indexer-plugins/issues/96#issue-2576028654.
> rev 0.5 - December 3rd, 2024: Added `@timestamp` and `delivery_timestamp` date fields.
> rev 0.6 - January 24th, 2025: Rename index to `wazuh-commands`. The index is now visible to users.

### Fields summary

This index stores information about the commands executed by the agents. The index appears in 5.0.0 for the first time.

The detail of the fields can be found in csv file [Command Fields](https://github.com/wazuh/wazuh-indexer-plugins/blob/main/ecs/command/docs/fields.csv).
