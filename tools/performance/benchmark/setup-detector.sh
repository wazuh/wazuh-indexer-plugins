#!/bin/bash
#
# setup-detector.sh — pre-create the security-analytics detector that turns indexed
# system-activity events into findings, OFFLINE and deterministically (no CTI API).
#
# Runs on the indexer host (localhost) against the local wazuh-indexer. Idempotent: it
# clears a prior perf detector/rule/log-type first, then creates them fresh. Steps:
#   1. custom log type   POST /_plugins/_security_analytics/logtype          (detector/logtype.json)
#   2. custom Sigma rule POST /_plugins/_security_analytics/rules?category=… (detector/rule.yml) → rule id
#   3. field mappings    POST /_plugins/_security_analytics/mappings         (map index ↔ log type)
#   4. detector          POST /_plugins/_security_analytics/detectors        (detector/detector.json)
#
# The detector's DocumentLevelMonitor then runs on its 1-minute schedule and writes a
# finding into wazuh-findings-v5-* for every matching event. So keep the load window
# (--duration) at least a couple of minutes.
#
# Usage: setup-detector.sh [--target https://localhost:9200] [--user admin] [--password admin]
#                          [--index wazuh-events-v5-system-activity] [--insecure]
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DET_DIR="$HERE/detector"
TARGET="https://localhost:9200"
USER="admin"
PASSWORD="admin"
INDEX="wazuh-events-v5-system-activity"
LOG_TYPE="system_activity"
INSECURE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)   TARGET="$2"; shift 2 ;;
        --user)     USER="$2"; shift 2 ;;
        --password) PASSWORD="$2"; shift 2 ;;
        --index)    INDEX="$2"; shift 2 ;;
        --insecure) INSECURE="-k"; shift ;;
        *) echo "Usage: $0 [--target URL] [--user U] [--password P] [--index IDX] [--insecure]"; exit 1 ;;
    esac
done

SAPI="$TARGET/_plugins/_security_analytics"
req() { curl $INSECURE -sS -u "$USER:$PASSWORD" -H 'Content-Type: application/json' "$@"; }

echo "[INFO] Pre-creating perf detector against $TARGET (index $INDEX, log type $LOG_TYPE)"

# 0. Best-effort cleanup of a prior perf run so this is idempotent. Detector first (it
#    references the rule), then the rule, then the log type.
PRIOR_DET=$(req "$SAPI/detectors/_search" -d '{"query":{"match":{"detector.name":"perf-system-activity"}}}' \
    | grep -o '"_id":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
[[ -n "${PRIOR_DET:-}" ]] && { echo "[INFO] Deleting prior detector $PRIOR_DET"; req -X DELETE "$SAPI/detectors/$PRIOR_DET" >/dev/null || true; }

# 1. Custom log type (ignore "already exists").
echo "[INFO] Creating custom log type '$LOG_TYPE'"
req -X POST "$SAPI/logtype" --data-binary "@$DET_DIR/logtype.json" -o /tmp/perf-logtype.out -w '  HTTP %{http_code}\n' || true
grep -q '"already exists"\|resource_already_exists\|"status":409' /tmp/perf-logtype.out 2>/dev/null \
    && echo "[INFO] Log type already exists — reusing." || true

# 2. Custom Sigma rule → capture its id.
echo "[INFO] Creating custom Sigma rule (category=$LOG_TYPE)"
req -X POST "$SAPI/rules?category=$LOG_TYPE" --data-binary "@$DET_DIR/rule.yml" -o /tmp/perf-rule.out -w '  HTTP %{http_code}\n'
RULE_ID=$(grep -o '"_id":"[^"]*"' /tmp/perf-rule.out | head -1 | cut -d'"' -f4 || true)
if [[ -z "${RULE_ID:-}" ]]; then
    echo "[ERROR] Could not create/parse the rule id. Response:" >&2
    cat /tmp/perf-rule.out >&2
    exit 1
fi
echo "[INFO] Rule id: $RULE_ID"

# 3. Field mappings: map the events index to the log type (partial → keep existing fields).
echo "[INFO] Creating field mappings for $INDEX"
req -X POST "$SAPI/mappings" -o /tmp/perf-mappings.out -w '  HTTP %{http_code}\n' -d "{
  \"index_name\": \"$INDEX\",
  \"rule_topic\": \"$LOG_TYPE\",
  \"partial\": true
}" || { echo "[WARN] mappings call returned non-zero:"; cat /tmp/perf-mappings.out; }

# 4. Detector wiring the rule to the index. Substitute the rule id + index into the body.
echo "[INFO] Creating detector"
DET_BODY=$(sed -e "s/__RULE_ID__/$RULE_ID/g" -e "s|__INDEX__|$INDEX|g" "$DET_DIR/detector.json")
req -X POST "$SAPI/detectors" -d "$DET_BODY" -o /tmp/perf-detector.out -w '  HTTP %{http_code}\n'
DET_ID=$(grep -o '"_id":"[^"]*"' /tmp/perf-detector.out | head -1 | cut -d'"' -f4 || true)
if [[ -z "${DET_ID:-}" ]]; then
    echo "[ERROR] Detector creation failed. Response:" >&2
    cat /tmp/perf-detector.out >&2
    exit 1
fi
echo "[INFO] Detector id: $DET_ID (enabled, 1-minute schedule)"
echo "[INFO] Detector pre-created — indexing matching events into $INDEX will produce findings."
