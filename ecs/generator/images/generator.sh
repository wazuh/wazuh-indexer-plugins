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

# Function to remove multi-fields from the generated index template
remove_multi_fields() {
  echo "Removing multi-fields from the index template"
  local in_file="$1"
  local out_file="$2"

  jq 'del(
    .mappings.properties.agent.properties.host.properties.os.properties.full.fields,
    .mappings.properties.agent.properties.host.properties.os.properties.name.fields,
    .mappings.properties.host.properties.os.properties.full.fields,
    .mappings.properties.host.properties.os.properties.name.fields,
    .mappings.properties.vulnerability.properties.description.fields,
    .mappings.properties.process.properties.command_line.fields,
    .mappings.properties.process.properties.name.fields,
    .mappings.properties.vulnerability.properties.description.fields,
    .mappings.properties.file.properties.path.fields,
    .mappings.properties.user.properties.name.fields,
    .mappings.properties.user.properties.full_name.fields,
    .mappings.properties.process.properties.user.properties.name.fields,
    .mappings.properties.process.properties.executable.fields,
    .mappings.properties.process.properties.working_directory.fields
  )' "$in_file" >"$out_file"
  mv "$out_file" "$in_file"
}

# Function to get the OpenTelemetry semantic conventions version for a given ECS version
# Required since ECS v9.0.0.
get_otel_version() {
  curl -s "https://raw.githubusercontent.com/elastic/ecs/refs/tags/${ECS_VERSION}/otel-semconv-version"
}

# Nested fields under the gen_ai.request and gen_ai.response are set to nested
# type, but do not contain any sub-fields. This causes failures when creating a
# detector in the Security Analytics plugin. We change their type to keyword array,
# following the OpenTelemetry documentation for gen_ai fields.
# Reference: https://github.com/wazuh/wazuh-indexer-plugins/issues/607
fix_gen_ai_nested_fields() {
  local in_file="$1"
  local csv_file="$2"

  echo "Fixing gen_ai nested fields in $in_file"
  jq '(.mappings.properties.gen_ai.properties.request.properties.encoding_formats.type) = "keyword" |
      (.mappings.properties.gen_ai.properties.request.properties.stop_sequences.type) = "keyword" |
      (.mappings.properties.gen_ai.properties.response.properties.finish_reasons.type) = "keyword"' "$in_file" >"${in_file}.tmp"
  mv "${in_file}.tmp" "$in_file"

  echo "Fixing gen_ai nested fields in $csv_file"
  sed -i 's/encoding_formats,nested,extended,,/encoding_formats,keyword,extended,array,/g' "$csv_file"
  sed -i 's/stop_sequences,nested,extended,,/stop_sequences,keyword,extended,array,/g' "$csv_file"
  sed -i 's/finish_reasons,nested,extended,,/finish_reasons,keyword,extended,array,/g' "$csv_file"
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

  # Include the common WCS fields if the module is an integration (e.g., stateless-aws)
  local include_wcs=""
  if [[ "$ecs_module" == stateless/* && "$ecs_module" != stateless/main ]]; then
    include_wcs="$indexer_path/ecs/stateless/main/fields/custom"
  fi

  # Generate mappings
  python scripts/generator.py --strict --ref "$ecs_version" \
    --semconv-version "$(get_otel_version)" \
    --include "$in_files_dir/custom/" "${include_wcs}" \
    --subset "$in_files_dir/subset.yml" \
    --template-settings "$in_files_dir/template-settings.json" \
    --template-settings-legacy "$in_files_dir/template-settings-legacy.json" \
    --mapping-settings "$in_files_dir/mapping-settings.json" \
    --out "$out_dir"

  # Replace unsupported types
  echo "Replacing unsupported types in generated mappings"
  find "$out_dir" -type f -exec sed -i 's/constant_keyword/keyword/g' {} \;
  find "$out_dir" -type f -exec sed -i 's/wildcard/keyword/g' {} \;
  find "$out_dir" -type f -exec sed -i 's/match_only_text/keyword/g' {} \;
  find "$out_dir" -type f -exec sed -i 's/flattened/flat_object/g' {} \;
  #   find "$out_dir" -type f -exec sed -i 's/scaled_float/float/g' {} \;
  #   find "$out_dir" -type f -exec sed -i '/scaling_factor/d' {} \;

  local in_file="$out_dir/generated/elasticsearch/legacy/template.json"
  local out_file="$out_dir/generated/elasticsearch/legacy/template-tmp.json"
  local csv_file="$out_dir/generated/csv/fields.csv"

  # Remove multi-fields from the generated index template
  remove_multi_fields "$in_file" "$out_file"

  # Delete "synthetic_source_keep" from the index template
  echo "Deleting \"synthetic_source_keep\" mappings setting from the index template"
  sed -i '/synthetic_source_keep/d' "$in_file"


  # Only apply fix_gen_ai_nested_fields to stateless/* modules (not to stateful/* or others)
  if [[ "$ecs_module" == stateless/* ]]; then
    fix_gen_ai_nested_fields "$in_file" "$csv_file"
  fi

  if [[ "$ecs_module" != stateless* ]]; then
    # Delete the "tags" field from the index template
    echo "Deleting the \"tags\" field from the index template"
    jq 'del(.mappings.properties.tags)' "$in_file" >"$out_file"
    mv "$out_file" "$in_file"

    # Delete the "@timestamp" field from the index template
    echo "Deleting the \"@timestamp\" field from the index template"
    jq 'del(.mappings.properties."@timestamp")' "$in_file" >"$out_file"
    mv "$out_file" "$in_file"

    # Delete the "@timestamp" field from the csv file
    echo "Deleting the \"@timestamp\" and \"tags\" fields from the CSV file"
    sed -i '/@timestamp/d; /tags/d' "$csv_file"
  # The stateless module is the one for the "wazuh-alerts" index template
  # We need to generate another template for "wazuh-archives" index
  elif [[ "$ecs_module" == "stateless" ]]; then
    # Generate the template for `wazuh-archives`
    echo "Generating template for 'wazuh-archives'"
    archives_file="$out_dir/generated/elasticsearch/legacy/template-archives.json"
    cp "$in_file" "$archives_file"
    sed -i 's/wazuh-alerts/wazuh-archives/g' "$archives_file"
  fi

  # Transform legacy index template for OpenSearch compatibility
  jq '{
    "index_patterns": .index_patterns,
    "priority": .order,
    "template": {
      "settings": .settings,
      "mappings": .mappings
    }
  }' "$in_file" >"$out_dir/generated/elasticsearch/legacy/opensearch-template.json"

  echo "Mappings saved to $out_dir"
}

# Generate mappings
generate_mappings "$ECS_MODULE" "$ECS_SOURCE" "$ECS_VERSION"
