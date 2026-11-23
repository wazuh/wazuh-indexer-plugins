#!/usr/bin/env bash
# Prepares the Wazuh indexer of the development environments for the integrations:
# waits until the setup plugin has created the events and findings data streams,
# then creates the read-only role and user that Logstash exports the data with.
# Running it again updates the role and the user.
#
# Environment:
#   WAZUH_INDEXER_URL             Wazuh indexer URL, e.g. https://wazuh.indexer:9200.
#   WAZUH_INDEXER_ADMIN_PASSWORD  Password of the admin user.
#   WAZUH_EXPORT_USERNAME         User to create.
#   WAZUH_EXPORT_PASSWORD         Password of that user.
#   WAZUH_INDEXER_CA              CA certificate of the Wazuh indexer. Default: /setup/root-ca.pem.
#   WAZUH_CUSTOM_STREAM           Optional custom data stream to create and export, to test the
#                                 export of data streams other than the Wazuh ones.
set -euo pipefail

CA="${WAZUH_INDEXER_CA:-/setup/root-ca.pem}"
ROLE="wazuh-export"

api() {
  curl -sS --fail-with-body --cacert "${CA}" -u "admin:${WAZUH_INDEXER_ADMIN_PASSWORD}" \
    -H "Content-Type: application/json" "$@"
}

# The setup plugin marks its initialization ready once every index template, policy and data
# stream exists, whatever the number of categories.
echo "Waiting for the setup plugin to create the events and findings data streams"
status=""
for _ in $(seq 1 60); do
  status=$(api "${WAZUH_INDEXER_URL}/.wazuh-setup-status/_doc/setup-status" 2>/dev/null |
    grep -o '"status":"[a-z]*"' | cut -d'"' -f4 || true)
  [ "${status}" = "ready" ] && break
  [ "${status}" = "failed" ] && break
  sleep 5
done
if [ "${status}" != "ready" ]; then
  echo "The setup plugin did not finish its initialization: ${status:-no status}" >&2
  exit 1
fi

# Exporting another data stream only needs its name or pattern in the role. The custom data
# stream of the development environment maps its fields dynamically.
patterns='"wazuh-events-v5-*", "wazuh-findings-v5-*"'
if [ -n "${WAZUH_CUSTOM_STREAM:-}" ]; then
  echo "Creating the template of the ${WAZUH_CUSTOM_STREAM} data stream"
  api -X PUT "${WAZUH_INDEXER_URL}/_index_template/${WAZUH_CUSTOM_STREAM}" \
    -d "{\"index_patterns\": [\"${WAZUH_CUSTOM_STREAM}\"], \"data_stream\": {}, \"priority\": 10,
         \"template\": {\"settings\": {\"number_of_replicas\": 0}}}"
  echo
  patterns="${patterns}, \"${WAZUH_CUSTOM_STREAM}\""
fi

# Search the events and findings data streams. Logstash checks the connection with
# a request to the root endpoint (cluster:monitor/main) and, as a scroll request
# names no index, continuing and clearing a scroll are cluster permissions too.
echo "Creating the ${ROLE} role"
api -X PUT "${WAZUH_INDEXER_URL}/_plugins/_security/api/roles/${ROLE}" -d "{
  \"description\": \"Read-only access to export the Wazuh events and findings data streams\",
  \"cluster_permissions\": [\"cluster:monitor/main\", \"indices:data/read/scroll\", \"indices:data/read/scroll/clear\"],
  \"index_permissions\": [
    { \"index_patterns\": [${patterns}], \"allowed_actions\": [\"read\"] }
  ]
}"
echo

echo "Creating the ${WAZUH_EXPORT_USERNAME} user"
api -X PUT "${WAZUH_INDEXER_URL}/_plugins/_security/api/internalusers/${WAZUH_EXPORT_USERNAME}" \
  -d "{\"password\": \"${WAZUH_EXPORT_PASSWORD}\", \"description\": \"Logstash export of the Wazuh integrations\"}"
echo

api -X PUT "${WAZUH_INDEXER_URL}/_plugins/_security/api/rolesmapping/${ROLE}" \
  -d "{\"users\": [\"${WAZUH_EXPORT_USERNAME}\"]}"
echo
echo "Done"
