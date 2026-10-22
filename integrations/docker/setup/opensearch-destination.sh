#!/usr/bin/env bash
# Prepares the destination OpenSearch cluster of the development environment:
# installs the index template of the Wazuh data streams and creates the role and
# user that Logstash writes with. Running it again updates all of them.
#
# Environment:
#   OPENSEARCH_URL               Destination URL, e.g. https://opensearch.node:9200.
#   OPENSEARCH_ADMIN_USERNAME    Administrator. Default: admin.
#   OPENSEARCH_ADMIN_PASSWORD    Password of the administrator.
#   OPENSEARCH_LOGSTASH_USERNAME User to create.
#   OPENSEARCH_LOGSTASH_PASSWORD Password of that user.
#   OPENSEARCH_CA                CA certificate of the destination. Default: /setup/root-ca.pem.
#   WAZUH_INDEX_TEMPLATE         Index template. Default: /setup/wazuh-index-template.json.
set -euo pipefail

CA="${OPENSEARCH_CA:-/setup/root-ca.pem}"
TEMPLATE="${WAZUH_INDEX_TEMPLATE:-/setup/wazuh-index-template.json}"
ROLE="wazuh-logstash-writer"

api() {
  curl -sS --fail-with-body --cacert "${CA}" \
    -u "${OPENSEARCH_ADMIN_USERNAME:-admin}:${OPENSEARCH_ADMIN_PASSWORD}" \
    -H "Content-Type: application/json" "$@"
}

echo "Waiting for OpenSearch"
for _ in $(seq 1 60); do
  api "${OPENSEARCH_URL}/_cluster/health?wait_for_status=yellow&timeout=5s" > /dev/null 2>&1 && break
  sleep 5
done
api "${OPENSEARCH_URL}/_cluster/health?wait_for_status=yellow&timeout=5s" > /dev/null

echo "Installing the Wazuh index template"
api -X PUT "${OPENSEARCH_URL}/_index_template/wazuh" -d @"${TEMPLATE}"
echo

# Append documents to the logs-wazuh.*-* data streams, creating them on the first write
# and adding the mappings of the fields that appear for the first time.
echo "Creating the ${ROLE} role"
api -X PUT "${OPENSEARCH_URL}/_plugins/_security/api/roles/${ROLE}" -d '{
  "description": "Write the Wazuh events and findings exported by Logstash",
  "cluster_permissions": ["cluster:monitor/main", "indices:data/write/bulk"],
  "index_permissions": [
    {
      "index_patterns": ["logs-wazuh.*-*"],
      "allowed_actions": [
        "indices:data/write/index",
        "indices:data/write/bulk*",
        "indices:admin/create",
        "indices:admin/data_stream/create",
        "indices:admin/mapping/put"
      ]
    }
  ]
}'
echo

echo "Creating the ${OPENSEARCH_LOGSTASH_USERNAME} user"
api -X PUT "${OPENSEARCH_URL}/_plugins/_security/api/internalusers/${OPENSEARCH_LOGSTASH_USERNAME}" \
  -d "{\"password\": \"${OPENSEARCH_LOGSTASH_PASSWORD}\", \"description\": \"Logstash writer of the Wazuh integrations\"}"
echo

api -X PUT "${OPENSEARCH_URL}/_plugins/_security/api/rolesmapping/${ROLE}" \
  -d "{\"users\": [\"${OPENSEARCH_LOGSTASH_USERNAME}\"]}"
echo
echo "Done"
