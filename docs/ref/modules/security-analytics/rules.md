# Rules

Wazuh uses the [Sigma](https://sigmahq.io/) rule format as the standard for Security Analytics detection rules. The Content Manager plugin accepts rules that follow the Sigma specification, extended with Wazuh-specific blocks for metadata, threat intelligence mapping, and compliance coverage.

This page describes the supported rule format, including field requirements, detection logic, supported modifiers, and Wazuh extensions.

> For the full Sigma standard, see the [Sigma Rules Specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md).

---

## Starting Example

The following example demonstrates a complete Sigma rule using all supported blocks:

```yaml
metadata:
  title: Python SQL Exceptions
  author: Thomas Patzke
  description: Detects SQL exceptions in Python applications according to PEP 249.

sigma_id: 19aefed0-ffd4-47dc-a7fc-f8b1425e84f9
status: stable
level: medium
enabled: true

tags:
  - attack.initial-access
  - attack.t1190

logsource:
  category: application
  product: python

detection:
  keywords:
    - DataError
    - IntegrityError
    - ProgrammingError
    - OperationalError
  condition: keywords

falsepositives:
  - Application bugs

mitre:
  tactic:
    - TA0001
  technique:
    - T1190
  subtechnique: []

compliance:
  pci_dss:
    - "6.5.1"
  gdpr:
    - Art. 32
```

### Components

A Wazuh Sigma rule is composed of the following blocks:

- **[Detection](#detection)**<br />_The rule's matching logic — selections, keywords, and conditions._
- **[Log Source](#log-source)**<br />_The type of log data the rule targets._
- **[Metadata](#metadata)**<br />_Authorship and lifecycle information (title, author, description, dates, references)._
- **[MITRE ATT&CK](#mitre-attck)**<br />_Threat intelligence mapping to MITRE tactics, techniques, and subtechniques._
- **[Compliance](#compliance)**<br />_Compliance framework mapping (GDPR, PCI DSS, NIST 800-53, etc.)._

The sections below describe each component in detail.

---

## Top-Level Fields

The following table lists all supported top-level fields in a Wazuh Sigma rule. Fields marked as **Required** must be present for the rule to pass validation.

| Field            | Type    | Required | Description                                                             |
| ---------------- | ------- | -------- | ----------------------------------------------------------------------- |
| `id`             | String  | Yes      | Globally unique rule identifier (UUIDv4 recommended)                    |
| `status`         | String  | Yes      | Rule maturity status: `experimental`, `test`, or `stable`               |
| `level`          | String  | Yes      | Alert severity: `informational`, `low`, `medium`, `high`, or `critical` |
| `sigma_id`       | String  | No       | Original Sigma rule identifier (UUID), preserved when importing from upstream |
| `enabled`        | Boolean | No       | Whether the rule is active (default: `true`)                            |
| `tags`           | Array   | No       | Categorization tags (e.g., `attack.initial-access`)                     |
| `falsepositives` | Array   | No       | Known sources of false positives                                        |
| `detection`      | Object  | Yes      | Detection logic: selections, keywords, and conditions                   |
| `logsource`      | Object  | Yes      | Classifies the type of log data the rule targets                        |
| `mitre`          | Object  | No       | MITRE ATT&CK threat intelligence mapping                                |
| `compliance`     | Object  | No       | Compliance framework mapping                                            |
| `metadata`       | Object  | Yes      | Other information                                                       |

---

## Detection

Required

The `detection` section defines the rule's matching logic. It consists of one or more **named selections** (or **keywords**) and a **condition** that combines them using boolean logic.

```yaml
detection:
  condition: selection
  selection:
    event.action: account-locked
    event.category|contains: authentication
```

The `detection` section must always contain:

- At least one named selection or a `keywords` list.
- A `condition` field that references those selections.


> [!IMPORTANT]
> All fields referenced in the `detection` section are validated against the Wazuh Common Schema. Rules that reference unknown fields are rejected with a structured error response identifying the offending field names. This prevents silent mismatches where a rule appears active but never triggers because it queries a non-existent field.

### Selections

A **selection** is a named object whose keys correspond to existing WCS fields and whose values define the matching criteria. A selection matches when any or all of its field conditions are satisfied, depending on the chosen syntax:

**Field list (implicit OR)**

```yaml
detection:
  selection:
    event.action:
      - login_failed # or
      - authentication_error
  condition: selection
```

This rule matches when `event.action` is either `"login_failed"` **or** `"authentication_error"`.

**Field dictionary (implicit AND)**

```yaml
detection:
  selection:
    log.level: ERROR # and
    event.kind: event
  condition: selection
```

This rule matches when `log.level` is `"ERROR"` **and** `event.kind` is `"event"`.

**Keywords (implicit OR)**

The detection by `keywords` performs value-only searches across all event fields, without specifying a target field name:

```yaml
detection:
  keywords:
    - DataError # or
    - IntegrityError
    - OperationalError
  condition: keywords
```

Each item in the list is effectively separated by a logical "OR" operator, meaning that the rule will match if any of the specified keywords are found in any field of the event.

### Conditions

The `condition` field is a string expression that combines named selections using boolean logic to define when the rule triggers. Each identifier in the condition must correspond to a named selection defined in the same `detection` object.

```yaml
condition: (selection_one or selection_two) and not filter
```

| Operator | Description                       | Example                              |
| -------- | --------------------------------- | ------------------------------------ |
| `and`    | Both operands must match          | `selection1 and selection2`          |
| `or`     | At least one operand must match   | `sel_error or sel_warn`              |
| `not`    | Negates the following operand     | `selection and not filter`           |
| `( )`    | Groups expressions for precedence | `(sel_a or sel_b) and not exclusion` |


**Example: simple condition**

```yaml
detection:
  selection:
    log.level: ERROR
  condition: selection
```

**Example: OR condition**

```yaml
detection:
  sel_error:
    log.level: ERROR
  sel_warn:
    log.level: WARN
  condition: sel_error or sel_warn
```

**Example: AND with NOT (exclusion pattern)**

```yaml
detection:
  selection:
    event.kind: event
  filter:
    process.thread.name|startswith: Test
  condition: selection and not filter
```

**Example: multi-selection AND**

```yaml
detection:
  sel_severity:
    event.severity|gte: 8
  sel_message:
    message|contains: fatal
  condition: sel_severity and sel_message
```

> **Reference**: See [Sigma Conditions](https://sigmahq.io/docs/basics/conditions.html) for the full specification of condition syntax.

### Modifiers

Modifiers transform how a field value is compared during detection. They are appended to the field name using the pipe (`|`) character:

```yaml
field_name|modifier: value
```

Multiple modifiers can be chained: `field|modifier1|modifier2: value`.

#### `contains`

Matches when the field value contains the specified substring. Wildcards are inserted around the value.

```yaml
message|contains: timeout
```

#### `startswith`

Matches when the field value begins with the specified string. A wildcard is inserted at the end of the value.

```yaml
process.thread.name|startswith: Gossip
```

#### `endswith`

Matches when the field value ends with the specified string. A wildcard is inserted at the beginning of the value.

```yaml
process.thread.name|endswith: "-5"
```

#### `base64`

Encodes the provided value as a Base64 string before comparison. Used to detect commands or parameters that an attacker has Base64-encoded to evade plain-text detection.

```yaml
process.command_line|base64: "/bin/bash"
```

#### `base64offset`

Generates all three possible Base64 offsets of the value to account for the byte position where it might appear inside a larger Base64-encoded blob. Usually preferred over `base64` when matching a substring inside an encoded stream, and typically chained with `contains`.

```yaml
process.command_line|base64offset|contains: "/bin/bash"
```

#### `wide`

Transforms the value to a UTF-16 (wide-character) byte sequence before comparison. Must be chained with an encoding modifier such as `base64` or `base64offset` — it cannot be the final modifier in the chain because the intermediate representation contains null bytes.

```yaml
process.command_line|wide|base64offset|contains: "ping"
```

#### `windash`

Expands command-line flag prefixes to match all Windows dash variants: `-`, `/`, `–` (en dash), `—` (em dash), and `―` (horizontal bar). Useful for detecting invocations where attackers swap dash characters to evade signatures.

```yaml
process.command_line|windash|contains: " -enc "
```

#### `re`

Matches the field value against a regular expression.

```yaml
process.thread.name|re: "^Repair"
```

Submodifiers can be chained with `re|<flag>`:

- `i` — case-insensitive matching.
- `m` — multi-line mode (`^`/`$` match the start/end of each line).
- `s` — single-line mode (`.` also matches newline characters).

#### `cidr`

Matches when the field value (an IPv4 or IPv6 address) falls within the specified CIDR subnet.

```yaml
source.ip|cidr: 10.42.0.0/16
```

IPv6 addresses are supported in the following formats:

- Standard: Full 8-group notation with leading zeros.

    E.g., `2001:0db8:85a3:0000:0000:8a2e:0370:7334`.

- Compressed: Zero-compression using `::` to omit consecutive zero groups.

    E.g., `2001:db8:85a3::8a2e:370:7334`.

- CIDR: Subnet notation with a prefix length.
  
    E.g., `2001:db8::/32`.

#### `exists`

Checks whether the field is present in the event. The value must be `true` (field must exist) or `false` (field must be absent).

```yaml
source.ip|exists: true
```

#### `all`

By default, list values are combined with `OR`. The `all` modifier changes the logic to `AND`, requiring every value in the list to match. Cannot be applied to single-item lists.

```yaml
event.category|contains|all:
  - authentication
  - failure
```

#### `lt`

Matches when the field value is less than the specified number.

```yaml
event.severity|lt: 10
```

#### `lte`

Matches when the field value is less than or equal to the specified number.

```yaml
event.severity|lte: 3
```

#### `gt`

Matches when the field value is greater than the specified number.

```yaml
event.severity|gt: 7
```

#### `gte`

Matches when the field value is greater than or equal to the specified number.

```yaml
event.duration|gte: 5000
```

> **Reference**: See [Sigma Modifiers](https://sigmahq.io/docs/basics/modifiers.html) for additional context on value transformation modifiers.

---

## Log Source

Required

The `logsource` section classifies the type of log data the rule targets. It helps organize rules by their applicable data source but does not affect detection matching directly.

### `product`

Required

The product or platform generating the log (e.g., `linux`, `windows`, `python`). Must hold the same value as `metadata.title` from the integration it belongs to.

```yaml
logsource:
  product: linux
```

### `category`

Optional

A broad classification of the log type within the product (e.g., `authentication`, `process_creation`, `application`, `webserver`, `firewall`). Useful for grouping related rules across products.

```yaml
logsource:
  category: authentication
```

### `service`

Optional

The specific service, daemon, or log channel within the product (e.g., `sshd`, `security`, `syslog`, `kerberos`). Use this when the log can be attributed to a particular subsystem or event channel.

```yaml
logsource:
  service: sshd
```

### `definition`

Optional

Free-form notes describing onboarding requirements or prerequisites for the log source — for example, audit policies that must be enabled, agent configuration needed, or specific event IDs to collect.

```yaml
logsource:
  definition: Script Block Logging must be enabled
```

> **Reference**: See [Sigma Log Sources](https://sigmahq.io/docs/basics/log-sources.html) for general guidance on log source classification, including the standard combinations of `product`, `category`, and `service`.

---

## Metadata

Required

The `metadata` block contains authorship and lifecycle fields. Only `title` is required; the others are optional.

### `title`

Required

Human-readable rule title shown in alerts and the rule catalog.

```yaml
metadata:
  title: Suspicious SSH Login from IPv6
```

Keep titles short and avoid prefixes like "Detects when ..." or "This rule will ...".

### `author`

Optional

The author of the rule. Free-form text; may include contact information such as an email address or handle.

```yaml
metadata:
  author: Security Team
```

### `date`

Optional

Creation date in ISO 8601 format (`YYYY-MM-DD`). Auto-managed when the rule is first registered.

```yaml
metadata:
  date: "2026-01-15"
```

### `modified`

Optional

Last modification date in ISO 8601 format (`YYYY-MM-DD`). Auto-managed when the rule's content changes.

```yaml
metadata:
  modified: "2026-03-02"
```

The `modified` date changes when the rule is updated.

### `description`

Optional

Brief explanation of what the rule detects and the context in which it is useful. Used by other products and services as a short summary of the rule's intent — avoid prefixes like "Detects when ..." or "This rule will ...".

```yaml
metadata:
  description: SSH login attempts from known malicious IPv6 ranges.
```

### `references`

Optional

URLs or plain-text references (advisories, CVE IDs, blog posts, documentation) explaining the motivation for the rule or providing background for analysts.

```yaml
metadata:
  references:
    - https://example.com/advisory/2025-001
    - CVE-2025-22222
```

### `documentation`

Optional

Free-form documentation text or a documentation URL providing additional context for analysts triaging the alert.

```yaml
metadata:
  documentation: https://docs.example.com/rules/ssh-ipv6
```

### `supports`

Optional

List of supported platforms, products, or contexts in which the rule is intended to operate.

```yaml
metadata:
  supports:
    - linux
    - macos
```

---

## MITRE ATT&CK

Optional

The `mitre` block maps a rule to MITRE ATT&CK tactics, techniques, and subtechniques. Each field is an array of ID strings:

- **`tactic`**<br />_MITRE tactic IDs (e.g., `TA0002`, `TA0005`)._
- **`technique`**<br />_MITRE technique IDs (e.g., `T1059`, `T1562`)._
- **`subtechnique`**<br />_MITRE subtechnique IDs (e.g., `T1059.001`)._

**Example**

```yaml
mitre:
  tactic:
    - TA0002
    - TA0005
  technique:
    - T1059
    - T1562
  subtechnique:
    - T1059.001
```

---

## Compliance

Optional

The `compliance` block maps a rule to one or more compliance frameworks. Each key is a normalized framework identifier and its value is an array of requirement ID strings.

**Supported frameworks**

- **`gdpr`**<br />_GDPR_
- **`pci_dss`**<br />_PCI DSS_
- **`cmmc`**<br />_CMMC_
- **`nist_800_53`**<br />_NIST 800-53_
- **`nist_800_171`**<br />_NIST 800-171_
- **`hipaa`**<br />_HIPAA_
- **`iso_27001`**<br />_ISO 27001_
- **`nis2`**<br />_NIS2_
- **`tsc`**<br />_TSC_
- **`fedramp`**<br />_FedRAMP_

**Example**

```yaml
compliance:
  gdpr:
    - Art. 32
    - Art. 25
  pci_dss:
    - "2.2.1"
    - "6.3.3"
  cmmc:
    - AC.1.001
  nist_800_53:
    - AC-3
    - AU-2
  hipaa:
    - 164.312(a)(1)
```

---

## Dynamic Event Field Referencing

A Sigma rule's metadata is normally static: the `title`, `tags`, `mitre`, and `compliance` blocks describe the rule itself and are attached unchanged to every finding it generates. Wazuh extends Sigma with **dynamic event-field referencing**, allowing those metadata fields to embed placeholders that resolve against the triggering event at enrichment time. Each finding written to the `wazuh-findings-v5-{logtype}-*` index then reflects the specific context of the event that matched — for example, the agent ID, hostname, or any other field present in the normalized event.

### Syntax

A placeholder takes the form `{{ field.path }}`, where `field.path` is a dot-separated path into the triggering event's `_source` document. Whitespace inside the delimiters is trimmed, so `{{ wazuh.agent.id }}` and `{{wazuh.agent.id}}` are equivalent. Placeholders may appear anywhere inside a supported field's value and may be mixed with literal text.

### Supported fields

Interpolation is applied only to the following fields of the enriched finding's `rule` object:

- `title`
- `tags`
- `mitre.tactic`, `mitre.technique`, `mitre.subtechnique`
- `compliance.*` (every framework sub-array)

The `detection` block — both `selection` and `condition` — is **never** interpolated.

### Example

```yaml
id: ed85157d-711b-4edb-8390-492ec63c92ac
sigma_id: 12345678-90ab-cdef-1234-567890abcdef
logsource:
  product: apache-http
tags:
  - attack.impact
  - attack.t1499.004
  - "{{ wazuh.agent.host.name }}"
level: high
status: test
detection:
  condition: selection
  selection:
    message|contains:
      - exit signal Segmentation Fault
    wazuh.integration.name: apache-http
metadata:
  title: "Apache segmentation fault in agent {{ wazuh.agent.id }}"
  description: Segmentation faults raised by an Apache worker process.
mitre:
  tactic:
    - TA0040
  technique:
    - T1499
  subtechnique:
    - T1499.004
compliance:
  pci_dss:
    - "6.2"
    - "11.4"
```

When this rule matches an event where `wazuh.agent.id = "001"` and `wazuh.agent.host.name = "web-prod-01"`, the resulting enriched finding contains:

```json
{
  "title": "Apache segmentation fault in agent 001",
  "tags": ["attack.impact", "attack.t1499.004", "web-prod-01"],
  "mitre": {
    "tactic": ["TA0040"],
    "technique": ["T1499"],
    "subtechnique": ["T1499.004"]
  },
  "compliance": {
    "pci_dss": ["6.2", "11.4"]
  }
}
```

### Resolution rules

- **Scalars** (string, number, boolean) are coerced to their string representation and substituted in place of the placeholder.
- **Scalar arrays** are expanded — each array element is coerced to a string and contributed as an additional element of the surrounding array. Supported for `tags`, `mitre.*`, and `compliance.*`.
- **Missing, null, or non-scalar** (object) values resolve to the empty string. Finding generation never fails because of an unresolved placeholder.
- A field whose value consists solely of a placeholder that resolves to the empty string is **dropped** from the surrounding array or map. For instance, a tag of `"{{ missing.field }}"` will not appear in `rule.tags`.

### Scope

Interpolation runs after the matching rule is fetched and before the enriched finding is indexed. It affects only the document written to `wazuh-findings-v5-{logtype}-*`. The raw rule document stored in the rule index is unchanged.
