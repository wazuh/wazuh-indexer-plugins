#!/bin/bash

# This script checks that specific fields are present in the mappings of given indices.
# Checks that metadata fields required by Wazuh States indices are present.
# Runs a curl command against localhost:9200 to get the mappings of each index.
# Related to issue: https://github.com/wazuh/wazuh-indexer-plugins/issues/576

set -e

indices=(
    "wazuh-states-fim-files"
    "wazuh-states-inventory-users"
    "wazuh-states-inventory-interfaces"
    "wazuh-states-inventory-ports"
    "wazuh-states-inventory-hotfixes"
    "wazuh-states-inventory-system"
    "wazuh-states-inventory-networks"
    "wazuh-states-inventory-groups"
    "wazuh-states-inventory-packages"
    "wazuh-states-inventory-hardware"
    "wazuh-states-fim-registry-values"
    "wazuh-states-vulnerabilities"
    "wazuh-states-inventory-browser-extensions"
    "wazuh-states-inventory-services"
    "wazuh-states-inventory-protocols"
    "wazuh-states-fim-registry-keys"
    "wazuh-states-inventory-processes"
    "wazuh-states-sca"
)

fields_to_check=(
    "agent.properties.host.properties.architecture"
    "agent.properties.host.properties.hostname"
    "agent.properties.host.properties.os.properties.name"
    "agent.properties.host.properties.os.properties.type"
    "agent.properties.host.properties.os.properties.platform"
    "agent.properties.host.properties.os.properties.version"
    "agent.properties.version"
    "agent.properties.name"
    "agent.properties.id"
    "agent.properties.groups"
    "state.properties.modified_at"
    "state.properties.document_version"
    "wazuh"
)

# Check mappings ensuring all fields are present
for index in "${indices[@]}"; do
    echo "Checking index: $index"
    mapping=$(curl -s "http://localhost:9200/$index/_mapping" | jq -r ".[\"$index\"].mappings.properties")
    for field in "${fields_to_check[@]}"; do
        if ! echo "$mapping" | jq -e ".$field" > /dev/null; then
            echo "Field '$field' is missing in index '$index'"
            exit 1
        fi
    done
    echo "All required fields are present in index '$index'"
done