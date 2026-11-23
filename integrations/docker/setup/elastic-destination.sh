#!/usr/bin/env bash
# Prepares the destination Elasticsearch cluster of the development environment:
# installs the index template of the Wazuh data streams and creates the role and
# user that Logstash writes with. Running it again updates all of them.
#
# Environment:
#   ELASTIC_URL                Destination URL, e.g. https://es01:9200.
#   ELASTIC_PASSWORD           Password of the elastic user.
#   ELASTIC_LOGSTASH_USERNAME  User to create.
#   ELASTIC_LOGSTASH_PASSWORD  Password of that user.
#   ELASTIC_CA                 CA certificate of the destination. Default: /setup/certs/ca/ca.crt.
#   WAZUH_INDEX_TEMPLATE       Index template. Default: /setup/wazuh-index-template.json.
set -euo pipefail

CA="${ELASTIC_CA:-/setup/certs/ca/ca.crt}"
TEMPLATE="${WAZUH_INDEX_TEMPLATE:-/setup/wazuh-index-template.json}"
ROLE="wazuh-logstash-writer"

api() {
  curl -sS --fail-with-body --cacert "${CA}" -u "elastic:${ELASTIC_PASSWORD}" \
    -H "Content-Type: application/json" "$@"
}

echo "Waiting for Elasticsearch"
for _ in $(seq 1 60); do
  api "${ELASTIC_URL}/_cluster/health?wait_for_status=yellow&timeout=5s" > /dev/null 2>&1 && break
  sleep 5
done
api "${ELASTIC_URL}/_cluster/health?wait_for_status=yellow&timeout=5s" > /dev/null

# The template composes logs@mappings and logs@settings, which Elasticsearch installs on its own
# shortly after it starts: until they exist, installing the template fails (HTTP 400).
# The API takes one name per request.
echo "Waiting for the built-in logs component templates"
for name in logs@mappings logs@settings; do
  for _ in $(seq 1 60); do
    api "${ELASTIC_URL}/_component_template/${name}" > /dev/null 2>&1 && break
    sleep 5
  done
  api "${ELASTIC_URL}/_component_template/${name}" > /dev/null
done

echo "Installing the Wazuh index template"
api -X PUT "${ELASTIC_URL}/_index_template/wazuh" -d @"${TEMPLATE}"
echo

# Append documents to the logs-wazuh.*-* data streams, creating them on the first write.
echo "Creating the ${ROLE} role"
api -X PUT "${ELASTIC_URL}/_security/role/${ROLE}" -d '{
  "description": "Write the Wazuh events and findings exported by Logstash",
  "cluster": ["monitor"],
  "indices": [{ "names": ["logs-wazuh.*-*"], "privileges": ["create_doc", "auto_configure"] }]
}'
echo

echo "Creating the ${ELASTIC_LOGSTASH_USERNAME} user"
api -X PUT "${ELASTIC_URL}/_security/user/${ELASTIC_LOGSTASH_USERNAME}" \
  -d "{\"password\": \"${ELASTIC_LOGSTASH_PASSWORD}\", \"roles\": [\"${ROLE}\"]}"
echo
echo "Done"
