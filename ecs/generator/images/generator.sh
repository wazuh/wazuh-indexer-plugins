#!/bin/bash

set -euo pipefail

# SPDX-License-Identifier: Apache-2.0
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.

# Default values
ECS_VERSION="${ECS_VERSION:-v9.1.0}"
ECS_SOURCE="${ECS_SOURCE:-/source}"

# Function to display usage information
show_usage() {
  echo "Usage: $0"
  echo "Environment Variables:"
  echo "  * ECS_MODULE:   Module to generate mappings for"
  echo "  * ECS_VERSION:  (Optional) ECS version to generate mappings for (default: v9.1.0)"
  echo "  * ECS_SOURCE:   (Optional) Path to the wazuh-indexer repository (default: /source)"
  echo "Example: docker run -e ECS_MODULE=stateless -e ECS_VERSION=v9.1.0 ecs-generator"
}

# Ensure ECS_MODULE is provided
if [ -z "${ECS_MODULE:-}" ]; then
  show_usage
  exit 1
fi

# Function to get the OpenTelemetry semantic conventions version for a given ECS version
# Required since ECS v9.0.0.
get_otel_version() {
  curl -s "https://raw.githubusercontent.com/elastic/ecs/refs/tags/${ECS_VERSION}/otel-semconv-version"
}

# Function to generate mappings
generate_mappings() {
  local ecs_module="$1"
  local indexer_path="$2"
  local ecs_version="$3"

  local in_files_dir="$indexer_path/ecs/$ecs_module/fields"
  local out_dir="$indexer_path/ecs/$ecs_module/mappings/$ecs_version"

  # Ensure the output directory exists
  mkdir -p "$out_dir"

  # Include the common WCS fields if the module is an integration (e.g., stateless/aws)
  local include_wcs=""
  if [[ "$ecs_module" == stateless/* && "$ecs_module" != stateless/main ]]; then
    include_wcs="$indexer_path/ecs/stateless/main/fields/custom"
  fi

  # Generate mappings
  python scripts/generator.py --strict \
    --semconv-version "$(get_otel_version)" \
    --include "$in_files_dir/custom/" "${include_wcs}" \
    --subset "$in_files_dir/subset.yml" \
    --template-settings "$in_files_dir/template-settings.json" \
    --template-settings-legacy "$in_files_dir/template-settings-legacy.json" \
    --mapping-settings "$in_files_dir/mapping-settings.json" \
    --out "$out_dir"

  local in_file="$out_dir/generated/elasticsearch/legacy/template.json"

  # Transform legacy index template for OpenSearch compatibility
  if [[ "$ecs_module" =~ "stateless/" ]]; then
    # Transform time-series templates to use data streams
    jq '{
      "index_patterns": .index_patterns,
      "priority": .order,
      "data_stream": {},
      "template": {
        "settings": .settings,
        "mappings": .mappings
      }
    }' "$in_file" >"$out_dir/generated/elasticsearch/legacy/opensearch-template.json"
  else
    # Stateful templates remain unchanged except for the formatting
    jq '{
      "index_patterns": .index_patterns,
      "priority": .order,
      "template": {
        "settings": .settings,
        "mappings": .mappings
      }
    }' "$in_file" >"$out_dir/generated/elasticsearch/legacy/opensearch-template.json"
  fi

  # Remove 'message' field from cti/ioc template
  if [[ "$ecs_module" == "cti/ioc" ]]; then
    jq 'del(.template.mappings.properties.message?)' "$in_file" >"$out_dir/generated/elasticsearch/legacy/opensearch-template.json"
  fi

  echo "Mappings saved to $out_dir"
}

# Generate mappings
generate_mappings "$ECS_MODULE" "$ECS_SOURCE" "$ECS_VERSION"
