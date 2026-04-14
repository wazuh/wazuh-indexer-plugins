# Rule Testing Workflow

This guide explains how to create, test, and promote custom detection rules using the Content Manager's logtest feature. The logtest endpoint lets you validate that your rules and decoders correctly detect events before deploying them to production.

## Overview

The rule testing workflow follows the Content Manager's space promotion chain:

```
Draft → Test → Custom
```

1. **Draft**: Create your integration, decoders, and rules.
2. **Test**: Promote to the test space and validate with logtest.
3. **Custom**: Once validated, promote to custom for production use.

Logtest sends a raw log event through the full detection pipeline — the Wazuh Engine normalizes the event, and the Security Analytics Plugin (SAP) evaluates your Sigma rules against the normalized output. The combined result shows exactly what was decoded and which rules matched.

Logtest supports both the `test` and `standard` spaces. Use `test` for validating draft content, and `standard` for testing against production rules.

---

## Step 1: Create an Integration

An integration groups related decoders, rules, and KVDBs together. Start by creating one:

```bash
curl -sk -u admin:admin -X POST \
  "https://localhost:9200/_plugins/_content_manager/integrations" \
  -H 'Content-Type: application/json' \
  -d '{
    "resource": {
      "category": "endpoint-security",
      "enabled": true,
      "metadata": {
        "title": "SSH Brute Force Detection",
        "author": "Security Team",
        "description": "Detects SSH brute force attempts from auth logs.",
        "references": ["https://attack.mitre.org/techniques/T1110/"]
      }
    }
  }'
```

The response returns the integration ID:

```json
{
  "message": "a0b448c8-3d3c-47d4-b7b9-cbc3c175f509",
  "status": 201
}
```

Save this ID — you'll need it for creating rules and running logtest.

## Step 2: Create a Decoder

Decoders tell the Engine how to parse and normalize raw log events. Link a decoder to your integration:

```bash
curl -sk -u admin:admin -X POST \
  "https://localhost:9200/_plugins/_content_manager/decoders" \
  -H 'Content-Type: application/json' \
  -d '{
    "integration": "a0b448c8-3d3c-47d4-b7b9-cbc3c175f509",
    "resource": {
      "enabled": true,
      "metadata": {
        "title": "SSH Auth Log Decoder",
        "author": "Security Team",
        "description": "Parses sshd authentication events from auth.log.",
        "module": "sshd",
        "references": ["https://wazuh.com"],
        "versions": ["Wazuh 5.*"]
      },
      "name": "decoder/sshd-auth/0",
      "check": [
        {"tmp_json.event.original": "regex_match(sshd\\\\[)"}
      ],
      "normalize": [
        {
          "map": [
            {"event.category": "[\"authentication\"]"},
            {"event.kind": "event"},
            {"@timestamp": "get_date()"}
          ]
        }
      ]
    }
  }'
```

## Step 3: Create a Rule

Rules use the [Sigma format](sigma-rules.md) to define detection logic. Link a rule to the same integration:

```bash
curl -sk -u admin:admin -X POST \
  "https://localhost:9200/_plugins/_content_manager/rules" \
  -H 'Content-Type: application/json' \
  -d '{
    "integration": "a0b448c8-3d3c-47d4-b7b9-cbc3c175f509",
    "resource": {
      "metadata": {
        "title": "SSH Failed Password Attempt",
        "description": "Detects failed SSH password authentication attempts.",
        "author": "Security Team",
        "references": ["https://attack.mitre.org/techniques/T1110/001/"]
      },
      "sigma_id": "ssh-failed-password",
      "enabled": true,
      "status": "experimental",
      "logsource": {
        "product": "linux",
        "category": "authentication"
      },
      "detection": {
        "condition": "selection",
        "selection": {
          "event.category": "authentication",
          "event.outcome": "failure"
        }
      },
      "level": "medium",
      "tags": ["attack.credential-access", "attack.t1110.001"],
      "mitre": {
        "tactic": ["TA0006"],
        "technique": ["T1110"],
        "subtechnique": ["T1110.001"]
      }
    }
  }'
```
## Step 4: Promote to Test Space

Before running logtest, your content must be in the **test** space. 

```bash
# 1. Preview what will be promoted
curl -sk -u admin:admin \
  "https://localhost:9200/_plugins/_content_manager/promote?space=draft"

# 2. Execute the promotion (use the changes from the preview response)
curl -sk -u admin:admin -X POST \
  "https://localhost:9200/_plugins/_content_manager/promote" \
  -H 'Content-Type: application/json' \
  -d '{
    "space": "draft",
    "changes": { ... }
  }'
```

## Step 5: Run Logtest

Send a sample event to validate your detection pipeline:

```bash
curl -sk -u admin:admin -X POST \
  "https://localhost:9200/_plugins/_content_manager/logtest" \
  -H 'Content-Type: application/json' \
  -d '{
    "integration": "a0b448c8-3d3c-47d4-b7b9-cbc3c175f509",
    "space": "test",
    "queue": 1,
    "location": "/var/log/auth.log",
    "event": "Dec 19 12:00:00 host sshd[12345]: Failed password for root from 10.0.0.1 port 54321 ssh2",
    "trace_level": "ALL"
  }'
```

### Understanding the Response

The response has two sections:

**`normalization`** — Shows how the Engine decoded and normalized the event:

```json
{
  "normalization": {
    "output": {
      "event": {
        "category": ["authentication"],
        "kind": "event",
        "outcome": "failure",
        "original": "Dec 19 12:00:00 host sshd[12345]: Failed password for root from 10.0.0.1 port 54321 ssh2"
      },
      "source": { "ip": "10.0.0.1" },
      "user": { "name": "root" }
    },
    "asset_traces": ["decoder/sshd-auth/0"],
    "validation": { "valid": true, "errors": [] }
  }
}
```

**`detection`** — Shows which Sigma rules matched the normalized event:

```json
{
  "detection": {
    "status": "success",
    "rules_evaluated": 1,
    "rules_matched": 1,
    "matches": [
      {
        "rule": {
          "id": "85bba177-a2e9-4468-9d59-26f4798906c9",
          "title": "SSH Failed Password Attempt",
          "level": "medium",
          "tags": ["attack.credential-access", "attack.t1110.001"]
        },
        "matched_conditions": [
          "event.category matched 'authentication'",
          "event.outcome matched 'failure'"
        ]
      }
    ]
  }
}
```

### Trace Levels

The `trace_level` field controls how much detail the Engine returns:

| Level        | Description                                                  |
| ------------ | ------------------------------------------------------------ |
| `NONE`       | Only the final normalized output. Use for quick checks.      |
| `ASSET_ONLY` | Output plus the list of decoders that matched (asset traces).|
| `ALL`        | Full trace including every decoder attempted. Use for debugging decoder issues. |

## Step 6: Iterate

If the results aren't what you expect:

1. **Decoder not matching?** Check `asset_traces` — if your decoder isn't listed, review the `check` conditions. Use `trace_level: ALL` to see which decoders were attempted.
2. **Rule not matching?** Compare the normalized event fields with your rule's `detection` block. Field names and values must match exactly (case-insensitive for strings).
3. **Unexpected matches?** Review `matched_conditions` to understand why a rule triggered.

After making changes:
- Update the rule or decoder via `PUT` on the respective endpoint.
- Re-promote draft → test.
- Run logtest again.

## Step 7: Promote to Custom

Once your rules are validated, promote from test to custom for production use:

```bash
# Preview
curl -sk -u admin:admin \
  "https://localhost:9200/_plugins/_content_manager/promote?space=test"

# Execute
curl -sk -u admin:admin -X POST \
  "https://localhost:9200/_plugins/_content_manager/promote" \
  -H 'Content-Type: application/json' \
  -d '{
    "space": "test",
    "changes": { ... }
  }'
```

Content in the custom space is picked up by the Wazuh Engine and actively used for log processing.

---

## Best Practices

### Rule Design

- **Start specific, broaden later.** Begin with tight detection conditions and loosen them as you understand the log patterns. Overly broad rules generate noise.
- **Use meaningful field names.** Align your decoder's `normalize` output with the Wazuh Common Schema (WCS) — e.g., `event.category`, `source.ip`, `user.name`.
- **Set appropriate severity levels.** Use `informational` for visibility rules, `low`/`medium` for suspicious activity, and `high`/`critical` only for confirmed threats or high-confidence detections.
- **Add context to rules.** Include `description`, `references`, `falsepositives`, and MITRE mappings. This helps analysts triage alerts and understand why a rule exists.

### Testing Strategy

- **Test with real log samples.** Use actual log events from your environment, not fabricated examples. Real logs expose edge cases (encoding, missing fields, unexpected formats).
- **Test positive AND negative cases.** Verify that your rule matches what it should, and verify it does NOT match what it shouldn't. Send benign events that look similar to confirm no false positives.
- **Use `trace_level: ALL` when debugging.** The full trace shows every decoder attempt, making it easy to spot why a particular decoder was or wasn't selected.
- **Test one change at a time.** When iterating on rules or decoders, change one thing per cycle. This makes it clear what fixed (or broke) the detection.

### Promotion Workflow

- **Always preview before promoting.** The promote preview shows exactly what will change. Review it to avoid promoting unintended modifications.
- **Keep draft as your working space.** Make all edits in draft. Never try to modify content directly in test or custom.
- **Promote frequently in small batches.** Smaller promotions are easier to validate and roll back. Avoid accumulating dozens of changes before testing.
- **Validate in test before promoting to custom.** The test space exists specifically for this purpose. Don't skip it.

---

## Quick Reference

| Action | Endpoint | Method |
| --- | --- | --- |
| Create integration | `/_plugins/_content_manager/integrations` | POST |
| Create decoder | `/_plugins/_content_manager/decoders` | POST |
| Create rule | `/_plugins/_content_manager/rules` | POST |
| Update rule | `/_plugins/_content_manager/rules/{id}` | PUT |
| Preview promotion | `/_plugins/_content_manager/promote?space={space}` | GET |
| Execute promotion | `/_plugins/_content_manager/promote` | POST |
| Run logtest | `/_plugins/_content_manager/logtest` | POST |

For full endpoint details, see the [API Reference](api.md). For Sigma rule format details, see [Sigma Rules](sigma-rules.md).
