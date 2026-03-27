# Sigma Rules

Wazuh uses the [Sigma](https://sigmahq.io/) rule format as the standard for Security Analytics detection rules. The Content Manager plugin accepts rules that follow the Sigma specification, extended with Wazuh-specific blocks for metadata, threat intelligence mapping, and compliance coverage.

This page describes the supported rule format, including Wazuh extensions, validation behavior, and examples.

> For the full Sigma standard, see the [Sigma Rules Specification](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md).

## Standard Sigma Fields

The following standard Sigma fields are supported in rule payloads:

| Field            | Type    | Description                                                        |
| ---------------- | ------- | ------------------------------------------------------------------ |
| `sigma_id`       | String  | Original Sigma rule identifier (UUID)                              |
| `status`         | String  | Rule maturity status (`experimental`, `test`, `stable`)            |
| `level`          | String  | Alert severity (`informational`, `low`, `medium`, `high`, `critical`) |
| `logsource`      | Object  | Log source definition (`product`, `category`, `service`, `definition`) |
| `detection`      | Object  | Detection logic with `condition` and selection fields              |
| `tags`           | Array   | Categorization tags (e.g., `attack.initial-access`)               |
| `falsepositives` | Array   | Known sources of false positives                                   |
| `fields`         | Array   | Fields of interest that should be included in the output           |
| `related`        | Array   | Related rules, each with `id` and `type`                          |
| `enabled`        | Boolean | Whether the rule is active                                         |

## Wazuh Extensions

Wazuh extends the standard Sigma format with three additional blocks aligned with the Wazuh Common Schema (WCS):

- **`metadata`** — Authorship and lifecycle information.
- **`mitre`** — MITRE ATT&CK threat intelligence mapping.
- **`compliance`** — Compliance framework mapping.

These blocks are optional. Existing rules without them continue to work without modification.

---

### Metadata Block

The `metadata` block contains authorship and lifecycle fields. All fields are optional.

| Field           | Type   | Description                                      |
| --------------- | ------ | ------------------------------------------------ |
| `title`         | String | Human-readable rule title                        |
| `author`        | String | Rule author                                      |
| `date`          | String | Creation date (ISO 8601)                         |
| `modified`      | String | Last modification date (ISO 8601)                |
| `description`   | String | Brief description of what the rule detects       |
| `references`    | Array  | Reference URLs (documentation, advisories, etc.) |
| `documentation` | String | Documentation text or URL                        |
| `supports`      | Array  | Supported platforms or contexts                  |

> **Note**: When creating or updating rules via the API, `title` is required within `metadata`. The `date` and `modified` fields are automatically managed by the server.

**Example**

```json
{
  "metadata": {
    "title": "Suspicious SSH Login from IPv6",
    "author": "Security Team",
    "description": "Detects SSH login attempts from known malicious IPv6 ranges.",
    "references": [
      "https://example.com/advisory/2025-001"
    ],
    "documentation": ""
  }
}
```

---

### MITRE ATT&CK Block

The `mitre` block maps a rule to MITRE ATT&CK tactics, techniques, and subtechniques. Each field is an array of ID strings.

| Field          | Type  | Description                                       |
| -------------- | ----- | ------------------------------------------------- |
| `tactic`       | Array | MITRE tactic IDs (e.g., `TA0002`, `TA0005`)      |
| `technique`    | Array | MITRE technique IDs (e.g., `T1059`, `T1562`)      |
| `subtechnique` | Array | MITRE subtechnique IDs (e.g., `T1059.001`)        |

During indexing, this block is mapped to the flat WCS `mitre` format by extracting the ID arrays:

```json
{
  "mitre": {
    "tactic": ["TA0002", "TA0005"],
    "technique": ["T1059", "T1562"],
    "subtechnique": ["T1059.001"]
  }
}
```

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

| Key            | Framework        |
| -------------- | ---------------- |
| `gdpr`         | GDPR             |
| `pci_dss`      | PCI DSS          |
| `cmmc`         | CMMC             |
| `nist_800_53`  | NIST 800-53      |
| `nist_800_171` | NIST 800-171     |
| `hipaa`        | HIPAA            |
| `iso_27001`    | ISO 27001        |
| `nis2`         | NIS2             |
| `tsc`          | TSC              |
| `fedramp`      | FedRAMP          |

During indexing, this block is mapped to the flat WCS compliance format:

```json
{
  "compliance": {
    "pci_dss": ["2.2.1", "6.3.3"],
    "gdpr": ["Art. 32", "Art. 25"]
  }
}
```

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

## IPv6 Support

Detection conditions support IPv6 addresses in the following formats:

| Format     | Example                                    |
| ---------- | ------------------------------------------ |
| Standard   | `2001:0db8:85a3:0000:0000:8a2e:0370:7334` |
| Compressed | `2001:db8:85a3::8a2e:370:7334`            |
| CIDR       | `2001:db8::/32`                            |

**Example detection with IPv6**

```json
{
  "detection": {
    "selection": {
      "source.ip": [
        "2001:db8:bad::/48",
        "fe80::1234:5678:90ab:cdef"
      ]
    },
    "condition": "selection"
  }
}
```

---

## WCS Field Validation

All fields referenced in the `detection` stanza are validated against the Wazuh Common Schema (WCS). Rules that reference unknown fields are rejected with a structured error response identifying the offending field names.

This ensures that detection logic only targets fields that exist in the indexed data, preventing silent mismatches where a rule appears active but never triggers because it queries a non-existent field.

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
