# Sigma filters

A Sigma filter excludes events from one or more rules without changing the rules themselves. Use it to tune a rule for your environment, for example to ignore an internal scanner, and keep receiving the CTI updates of a Standard rule: copying the rule to the Custom space to edit it would stop those updates.

Sigma filters follow the [Sigma filters specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-filters-specification.md). They are managed through the Content Manager API; see [Sigma filters](../content-manager/api.md#sigma-filters) in the API reference.

## Example

The rule `26a8d32e-0838-5589-948c-501b5a301cf5` (Standard, `apache-http`) detects requests to `/.git/` paths. An internal audit scanner triggers it on purpose, so its requests are filtered out:

```yaml
metadata:
  title: Ignore the internal audit scanner
logsource:
  product: apache-http
filter:
  rules:
    - 26a8d32e-0838-5589-948c-501b5a301cf5
  selection:
    user_agent.original|startswith: internal-scanner
  condition: not selection
```

Once the filter reaches the Custom space, the rule keeps matching every request to a `/.git/` path except the scanner's.

## How a filter applies

- **The filter's condition is added to the rule's condition.** The rule matches when `(<rule condition>) and (<filter condition>)` is true, as in pySigma. The filter author writes the negation: `condition: not selection`.
- **The rule is not modified.** It keeps its content, its hash and its CTI updates; the filter is applied again to each new version.
- **Several filters can target one rule.** All of them apply.
- **Deleting a filter restores the rule's original matching.**
- **The space sets where a filter applies:**

  | Filter space | Detectors | Log test |
  |---|---|---|
  | Draft | No | No |
  | Test | No | Yes, with `sigma_filters: test` (the default for the `test` space) |
  | Custom | Yes, for Standard and Custom rules | Yes, with `sigma_filters: custom` (the default for the `standard` and `custom` spaces) |

- **A change reaches the detectors when it is promoted to Custom.** The rules the filter targets are sent to Security Analytics again, and each detector that uses them is rebuilt once. Detectors keep their monitors: no monitor or query index is added.

## Filter format

A filter has the following fields:

- **`metadata.title`** (String, required) — title of the filter.
- **`metadata.author`**, **`metadata.description`** (String, optional).
- **`logsource`** (Object, required) — the log source the filter applies to. Each key the filter sets (`product`, `category`, `service`) must have the same value in the rules it targets. An empty object fits any rule.
- **`filter.rules`** (List of strings, required) — the ids of the rules the filter applies to. A filter of a space can target the Standard rules and the rules of its own space. `rules: any` is not supported.
- **Selections** (Objects, at least one) — named like rule selections, under `filter`, with the same fields and modifiers. Names use letters, digits and underscores, and do not start with a digit.
- **`filter.condition`** (String, required) — a single `not` over the filter's selections: `not selection`, `not 1 of sel*`, `not all of them` or `not (sel_a or sel_b)`. A condition without the `not` (`condition: selection`, the convention of the Sigma specification example) is rejected rather than applied inverted.
- **`enabled`** (Boolean, optional) — a disabled filter is not applied. Defaults to `true`.

## Validation

A filter is checked against every rule it targets when it is created or updated. It is rejected with a 400 that names the reason when:

- a target rule does not exist in the Standard space or in the filter's space;
- the filter's log source does not match a target rule;
- the condition is not a single top-level `not`, or refers to a selection the filter does not define;
- a field is not part of the Wazuh Common Schema (WCS);
- a target rule aggregates events (a `|` in its condition, or a `timeframe`);
- with the filter applied, a target rule compiles to a query that does not parse.

## When CTI changes a rule

CTI can change a Standard rule after a filter was written for it, for example its log source. A filter that no longer fits its rule is skipped, with a warning in the Wazuh Indexer log; the rule's other filters still apply, and the content update completes.

## Log test

`POST /_plugins/_content_manager/logtest` and `POST /_plugins/_content_manager/logtest/detection` take an optional `sigma_filters` field that selects whose filters apply to the evaluated rules: `test`, `custom` or `none`. When it is omitted, a `test` run applies the Test filters and a `standard` or `custom` run the Custom ones, as the detectors do. See [Logtest usage](../content-manager/rule-testing.md).

## The filter inside the rule

Security Analytics receives each rule with its filters applied. Each filter's selections are added to the rule's detection under the name `_filt_<first ten hexadecimal digits of the filter id>_<selection name>`, and the filter's condition refers to them by that name. These names are not shown in the rule, in log test results or in findings.

Selectors such as `1 of them` or `all of sel*` skip the identifiers that start with an underscore unless their own pattern starts with one, as the Sigma specification prescribes; a rule's selectors therefore never select a filter's selections. See [Selectors](rules.md#selectors).
