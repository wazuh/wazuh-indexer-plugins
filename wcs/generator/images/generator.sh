#!/bin/bash

set -euo pipefail

# SPDX-License-Identifier: Apache-2.0
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.

# Default values
ECS_VERSION="${ECS_VERSION:-v9.1.0}"
ECS_SOURCE="${ECS_SOURCE:-/source}"

# Temporary files, removed on exit by the cleanup function
PROBE_DIR=""
EXCLUDE_FILE=""

# Function to remove the temporary files. Runs on every exit, successful or not,
# so nothing is left behind when the generation fails halfway through. Always
# returns 0: the status of an EXIT trap becomes the status of the script.
cleanup() {
  rm -rf "${PROBE_DIR:-}" "${EXCLUDE_FILE:-}"
  return 0
}
trap cleanup EXIT

# Fields removed from every generated module, as flat paths.
# ECS copies all the fields of a field set into each of its reuses.
#
# Current list of excluded fields:
#   * file.diff belongs to the root file object only, not to the file reuses
#     under threat.indicator, threat.enrichments.indicator and their
#     wazuh.threat counterparts.
EXCLUDED_FIELDS=(
  "threat.indicator.file.diff"
  "threat.enrichments.indicator.file.diff"
  "wazuh.threat.indicator.file.diff"
  "wazuh.threat.enrichments.indicator.file.diff"
)

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
  # Fail on HTTP errors (-f) and report them (-S), so an error page is never
  # taken for a version, without the progress meter (-s)
  curl -fSs "https://raw.githubusercontent.com/elastic/ecs/refs/tags/${ECS_VERSION}/otel-semconv-version"
}

# Function to write an ECS exclusion file with the EXCLUDED_FIELDS entries that
# the module has. The ones it doesn't have must be left out: the ECS exclusion
# filter fails when asked to remove a field it can't find. Presence is read from
# the flat field list of the intermediate files, where every line is the flat
# name of a field followed by a colon. Nothing is written when no entry applies
# to the module.
# Arguments: flat field list, exclusion file to write.
write_exclude_file() {
  local flat_file="$1"
  local exclude_file="$2"
  local path
  local field
  local field_set
  local -a fields
  # Fields to remove grouped by field set, as expected by the exclusion file
  # format: a list of field sets, each with the fields to remove from it
  local -A fields_by_set=()

  for path in "${EXCLUDED_FIELDS[@]}"; do
    if grep -qxF "${path}:" "$flat_file"; then
      fields_by_set["${path%%.*}"]+=" ${path#*.}"
      echo "Excluding field: $path"
    fi
  done

  for field_set in "${!fields_by_set[@]}"; do
    printf -- '- name: %s\n  fields:\n' "$field_set" >>"$exclude_file"
    # Split the space separated list into an array, to write one entry per field
    read -r -a fields <<<"${fields_by_set[$field_set]}"
    for field in "${fields[@]}"; do
      printf -- '    - name: %s\n' "$field" >>"$exclude_file"
    done
  done
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
  if [[ "$ecs_module" == stateless/events* && "$ecs_module" != stateless/events/main ]]; then
    include_wcs="$indexer_path/ecs/stateless/events/main/fields/custom"
  fi

  local otel_version
  otel_version=$(get_otel_version)

  PROBE_DIR=$(mktemp -d)
  EXCLUDE_FILE=$(mktemp --suffix=.yml)

  # First pass: generate the intermediate files only, to find out which of the
  # EXCLUDED_FIELDS this module has
  python scripts/generator.py --strict \
    --semconv-version "$otel_version" \
    --include "$in_files_dir/custom/" "${include_wcs}" \
    --subset "$in_files_dir/subset.yml" \
    --intermediate-only \
    --out "$PROBE_DIR"

  local exclude_args=()
  write_exclude_file "$PROBE_DIR/generated/ecs/ecs_flat.yml" "$EXCLUDE_FILE"
  if [[ -s "$EXCLUDE_FILE" ]]; then
    exclude_args=(--exclude "$EXCLUDE_FILE")
  fi

  # Second pass: generate mappings, without the excluded fields
  python scripts/generator.py --strict \
    --semconv-version "$otel_version" \
    --include "$in_files_dir/custom/" "${include_wcs}" \
    --subset "$in_files_dir/subset.yml" \
    "${exclude_args[@]+"${exclude_args[@]}"}" \
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

  echo "Mappings saved to $out_dir"
}

# Generate mappings
generate_mappings "$ECS_MODULE" "$ECS_SOURCE" "$ECS_VERSION"
