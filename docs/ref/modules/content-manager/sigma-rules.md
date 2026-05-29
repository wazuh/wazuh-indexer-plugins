# Sigma Rules

Wazuh uses the [Sigma](https://sigmahq.io/) rule format as the standard for Security Analytics detection rules. The Content Manager plugin accepts rules that follow the Sigma specification, extended with Wazuh-specific blocks for metadata, threat intelligence mapping, and compliance coverage.

This page describes the supported rule format, including field requirements, detection logic, supported modifiers, and Wazuh extensions.

> For the full Sigma standard, see the [Sigma Rules Specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md).

---

## Rule Fields

The following table lists all supported top-level fields in a Wazuh Sigma rule payload. Fields marked as **Required** must be present for the rule to pass validation.

| Field            | Type    | Required | Description                                                                  |
|------------------|---------|----------|------------------------------------------------------------------------------|
| `status`         | String  | Yes      | Rule maturity status: `experimental`, `test`, or `stable`                    |
| `level`          | String  | Yes      | Alert severity: `informational`, `low`, `medium`, `high`, or `critical`      |
| `detection`      | Object  | Yes      | Detection logic (see [Detection](#detection))                                |
| `logsource`      | Object  | No       | Log source classification (see [Log Source](#log-source))                    |
| `sigma_id`       | String  | No       | Original Sigma rule identifier (UUID)                                        |
| `enabled`        | Boolean | No       | Whether the rule is active (default: `true`)                                 |
| `tags`           | Array   | No       | Categorization tags (e.g., `attack.initial-access`)                          |
| `falsepositives` | Array   | No       | Known sources of false positives                                             |
| `metadata`       | Object  | No       | Authorship and lifecycle information (see [Metadata Block](#metadata-block)) |
| `mitre`          | Object  | No       | MITRE ATT&CK mapping (see [MITRE ATT&CK Block](#mitre-attck-block))          |
| `compliance`     | Object  | No       | Compliance framework mapping (see [Compliance Block](#compliance-block))     |

> **Note**: The `fields` and `related` fields from the upstream Sigma specification are **not supported** and will be ignored if present.

---

## Log Source

The `logsource` object classifies the type of log data the rule targets. It helps organize rules by their applicable data source but does not affect detection matching directly.

| Field        | Type   | Required | Description                                                                     |
|--------------|--------|----------|---------------------------------------------------------------------------------|
| `product`    | String | No       | The product or platform generating the log (e.g., `linux`, `windows`, `python`) |
| `category`   | String | No       | The log category (e.g., `authentication`, `process_creation`, `application`)    |
| `service`    | String | No       | The specific service or log channel (e.g., `sshd`, `security`, `syslog`)        |
| `definition` | String | No       | Additional requirements or notes for the log source                             |

> **Reference**: See [Sigma Log Sources](https://sigmahq.io/docs/basics/log-sources.html) for general guidance on log source classification.

**Example**

```json
{
  "logsource": {
    "product": "linux",
    "category": "authentication",
    "service": "sshd"
  }
}
```

---

## Detection

The `detection` object defines the rule's matching logic. It consists of one or more **named selections** (or **keywords**) and a **condition** that combines them using boolean logic.

### Structure

```json
{
  "detection": {
    "selection_name": { ... },
    "another_selection": { ... },
    "condition": "selection_name and another_selection"
  }
}
```

The `detection` object must always contain:

- At least one named selection or a `keywords` list.
- A `condition` field that references those selections.

### Selections

A **selection** is a named object whose keys are [event field references](#dynamic-event-field-referencing) and whose values define the match criteria. A selection matches when **all** of its field conditions are satisfied (implicit AND within a selection).

```json
{
  "selection": {
    "log.level": "ERROR",
    "event.kind": "event"
  }
}
```

Field values can be:

| Value Type | Behavior                                                       |
|------------|----------------------------------------------------------------|
| String     | Exact match (case-insensitive). Supports wildcards `*` and `?` |
| Number     | Exact numeric comparison                                       |
| Array      | Matches if the field equals **any** element in the list (OR)   |
| `null`     | Matches if the field is absent or null                         |

**List values (OR within a field)**

```json
{
  "selection": {
    "event.action": ["login_failed", "authentication_error"]
  }
}
```

This matches when `event.action` is either `"login_failed"` or `"authentication_error"`.

### Keywords

A `keywords` entry is a special selection that performs value-only searches across all event fields, without specifying a target field name:

```json
{
  "detection": {
    "keywords": ["DataError", "IntegrityError", "OperationalError"],
    "condition": "keywords"
  }
}
```

A keyword matches if any event field contains the specified value.

---

## Condition

The `condition` field is a string expression that combines named selections using boolean logic to define when the rule triggers.

### Operators

| Operator | Description                       | Example                              |
|----------|-----------------------------------|--------------------------------------|
| `and`    | Both operands must match          | `selection1 and selection2`          |
| `or`     | At least one operand must match   | `sel_error or sel_warn`              |
| `not`    | Negates the following operand     | `selection and not filter`           |
| `( )`    | Groups expressions for precedence | `(sel_a or sel_b) and not exclusion` |

### Identifiers

Each identifier in the condition must correspond to a named selection defined in the same `detection` object.

### Examples

**Simple condition**

```json
{
  "detection": {
    "selection": { "log.level": "ERROR" },
    "condition": "selection"
  }
}
```

**OR condition**

```json
{
  "detection": {
    "sel_error": { "log.level": "ERROR" },
    "sel_warn": { "log.level": "WARN" },
    "condition": "sel_error or sel_warn"
  }
}
```

**AND with NOT (exclusion pattern)**

```json
{
  "detection": {
    "selection": { "event.kind": "event" },
    "filter": { "process.thread.name|startswith": "Test" },
    "condition": "selection and not filter"
  }
}
```

**Multi-selection AND**

```json
{
  "detection": {
    "sel_severity": { "event.severity|gte": 8 },
    "sel_message": { "message|contains": "fatal" },
    "condition": "sel_severity and sel_message"
  }
}
```

> **Reference**: See [Sigma Conditions](https://sigmahq.io/docs/basics/conditions.html) for the full specification of condition syntax.

---

## Value Modifiers

Modifiers transform how a field value is compared during detection. They are appended to the field name using the pipe (`|`) character:

```
"field_name|modifier": "value"
```

Multiple modifiers can be chained: `"field|modifier1|modifier2": "value"`.

### Supported Modifiers

| Modifier     | Description                                                  | Example               |
|--------------|--------------------------------------------------------------|-----------------------|
| `contains`   | Field value contains the specified substring                 | `"message             |contains": "timeout"`                 |
| `startswith` | Field value starts with the specified string                 | `"process.thread.name |startswith": "Gossip"`    |
| `endswith`   | Field value ends with the specified string                   | `"process.thread.name |endswith": "-5"`          |
| `re`         | Field value matches the specified regular expression         | `"process.thread.name |re": "^Repair"`           |
| `cidr`       | IP field value falls within the specified CIDR subnet        | `"source.ip           |cidr": "10.42.0.0/16"`             |
| `exists`     | Field exists (is not null/absent) in the event               | `"source.ip           |exists": true`                      |
| `gte`        | Field value is greater than or equal to the specified number | `"event.duration      |gte": 5000`                    |
| `gt`         | Field value is greater than the specified number             | `"event.severity      |gt": 7`                        |
| `lte`        | Field value is less than or equal to the specified number    | `"event.severity      |lte": 3`                       |
| `lt`         | Field value is less than the specified number                | `"event.severity      |lt": 10`                       |

> **Reference**: See [Sigma Modifiers](https://sigmahq.io/docs/basics/modifiers.html) for additional context on value transformation modifiers.

### Wildcards

Within string values (with or without modifiers), the following wildcard characters are supported:

| Character | Meaning                         |
|-----------|---------------------------------|
| `*`       | Matches zero or more characters |
| `?`       | Matches exactly one character   |

**Example**

```json
{
  "selection": {
    "log.origin.file.name": "Storage*.java"
  }
}
```

This matches `StorageService.java`, `StorageProxy.java`, etc.

### Combining Modifiers

Numeric modifiers can be combined within a single selection to express ranges:

```json
{
  "selection": {
    "event.duration|gte": 5000,
    "event.severity|lt": 10
  }
}
```

This matches events where duration ≥ 5000 **and** severity < 10.

---

## Dynamic Event Field Referencing

Detection selections reference fields from the normalized event using **dot-notation** paths aligned with the [Wazuh Common Schema (WCS)](../../glossary.md). These are the same field names produced by decoders during event normalization.

Examples of valid field references:

| Field                  | Type   | Description                    |
|------------------------|--------|--------------------------------|
| `event.kind`           | String | Event classification           |
| `event.category`       | Array  | Event category list            |
| `event.action`         | String | Action performed               |
| `event.severity`       | Long   | Numeric severity value         |
| `event.duration`       | Long   | Event duration in milliseconds |
| `log.level`            | String | Log level (INFO, ERROR, etc.)  |
| `source.ip`            | String | Source IP address              |
| `process.thread.name`  | String | Thread name                    |
| `process.command_line` | String | Full command line              |
| `message`              | String | Log message body               |
| `log.origin.file.name` | String | Source file name               |
| `log.origin.file.line` | Long   | Source file line number        |

When a rule matches an event, the matched field values are included in the [enriched finding](../security-analytics/index.md) under `matched_conditions`, providing full context for alert investigation.

### WCS Field Validation

All fields referenced in the `detection` stanza are validated against the Wazuh Common Schema. Rules that reference unknown fields are rejected with a structured error response identifying the offending field names. This prevents silent mismatches where a rule appears active but never triggers because it queries a non-existent field.

---

## IPv6 Support

Detection conditions support IPv6 addresses in the following formats:

| Format     | Example                                   |
|------------|-------------------------------------------|
| Standard   | `2001:0db8:85a3:0000:0000:8a2e:0370:7334` |
| Compressed | `2001:db8:85a3::8a2e:370:7334`            |
| CIDR       | `2001:db8::/32`                           |

**Example detection with IPv6**

```json
{
  "detection": {
    "selection": {
      "source.ip|cidr": "2001:db8:bad::/48"
    },
    "condition": "selection"
  }
}
```

---

## Wazuh Extensions

Wazuh extends the standard Sigma format with three additional blocks aligned with the Wazuh Common Schema (WCS):

- **`metadata`** — Authorship and lifecycle information.
- **`mitre`** — MITRE ATT&CK threat intelligence mapping.
- **`compliance`** — Compliance framework mapping.

These blocks are optional. Existing rules without them continue to work without modification.

---

### Metadata Block

The `metadata` block contains authorship and lifecycle fields. All fields are optional unless noted.

| Field           | Type   | Required | Description                                      |
|-----------------|--------|----------|--------------------------------------------------|
| `title`         | String | Yes*     | Human-readable rule title                        |
| `author`        | String | No       | Rule author                                      |
| `date`          | String | No       | Creation date (ISO 8601, auto-managed)           |
| `modified`      | String | No       | Last modification date (ISO 8601, auto-managed)  |
| `description`   | String | No       | Brief description of what the rule detects       |
| `references`    | Array  | No       | Reference URLs (documentation, advisories, etc.) |
| `documentation` | String | No       | Documentation text or URL                        |
| `supports`      | Array  | No       | Supported platforms or contexts                  |

> \* `title` is required when creating or updating rules via the API.

**Example**

```json
{
  "metadata": {
    "title": "Suspicious SSH Login from IPv6",
    "author": "Security Team",
    "description": "Detects SSH login attempts from known malicious IPv6 ranges.",
    "references": [
      "https://example.com/advisory/2025-001"
    ]
  }
}
```

---

### MITRE ATT&CK Block

The `mitre` block maps a rule to MITRE ATT&CK tactics, techniques, and subtechniques. Each field is an array of ID strings.

| Field          | Type  | Description                                  |
|----------------|-------|----------------------------------------------|
| `tactic`       | Array | MITRE tactic IDs (e.g., `TA0002`, `TA0005`)  |
| `technique`    | Array | MITRE technique IDs (e.g., `T1059`, `T1562`) |
| `subtechnique` | Array | MITRE subtechnique IDs (e.g., `T1059.001`)   |

**Example**

```json
{
  "mitre": {
    "tactic": ["TA0002", "TA0005"],
    "technique": ["T1059", "T1562"],
    "subtechnique": ["T1059.001"]
  }
}
```

---

### Compliance Block

The `compliance` block maps a rule to one or more compliance frameworks. Each key is a normalized framework identifier and its value is an array of requirement ID strings.

**Supported frameworks**

| Key            | Framework    |
|----------------|--------------|
| `gdpr`         | GDPR         |
| `pci_dss`      | PCI DSS      |
| `cmmc`         | CMMC         |
| `nist_800_53`  | NIST 800-53  |
| `nist_800_171` | NIST 800-171 |
| `hipaa`        | HIPAA        |
| `iso_27001`    | ISO 27001    |
| `nis2`         | NIS2         |
| `tsc`          | TSC          |
| `fedramp`      | FedRAMP      |

**Example**

```json
{
  "compliance": {
    "gdpr": ["Art. 32", "Art. 25"],
    "pci_dss": ["2.2.1", "6.3.3"],
    "cmmc": ["AC.1.001"],
    "nist_800_53": ["AC-3", "AU-2"],
    "hipaa": ["164.312(a)(1)"]
  }
}
```

---

## Complete Example

The following JSON payload demonstrates a rule using all supported blocks, suitable for the [Create Rule](api.md#create-rule) API endpoint:

```json
{
  "integration": "6b7b7645-00da-44d0-a74b-cffa7911e89c",
  "resource": {
    "metadata": {
      "title": "Python SQL Exceptions",
      "author": "Thomas Patzke",
      "description": "Detects SQL exceptions in Python applications according to PEP 249."
    },
    "sigma_id": "19aefed0-ffd4-47dc-a7fc-f8b1425e84f9",
    "status": "stable",
    "level": "medium",
    "enabled": true,
    "tags": [
      "attack.initial-access",
      "attack.t1190"
    ],
    "logsource": {
      "category": "application",
      "product": "python"
    },
    "detection": {
      "keywords": [
        "DataError",
        "IntegrityError",
        "ProgrammingError",
        "OperationalError"
      ],
      "condition": "keywords"
    },
    "falsepositives": [
      "Application bugs"
    ],
    "mitre": {
      "tactic": ["TA0001"],
      "technique": ["T1190"],
      "subtechnique": []
    },
    "compliance": {
      "pci_dss": ["6.5.1"],
      "gdpr": ["Art. 32"]
    }
  }
}
```

---

## Backward Compatibility

All Wazuh extension blocks (`metadata`, `mitre`, `compliance`) are optional. Rules that do not include these blocks continue to parse and function correctly. This ensures full backward compatibility with existing rules and standard Sigma rules that do not use Wazuh extensions.
