#!/usr/bin/env bash

# Count fields and nested fields in a generated index template and update mapping limits
# This script analyzes OpenSearch index templates to:
# - Count total fields and update mapping.total_fields.limit
# - Count nested fields and update mapping.nested_fields.limit
# - Count date fields and update index.max_docvalue_fields_search (the dashboard requests one
#   docvalue_field per date field of the index pattern, so this limit must exceed the date count)
# Usage:
#   ./count_and_update_total_fields.sh <module|all> [--apply]
# If --apply is not passed the script runs in dry-run mode and prints proposed values.

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <module|all> [--apply]" >&2
  exit 1
fi

ARG1="$1"
APPLY=false
if [[ ${2:-} == "--apply" ]] || [[ ${3:-} == "--apply" ]]; then
  APPLY=true
fi

# If ARG1 is 'all' we will read module names from wcs/module_list.txt
PROCESS_ALL=false
if [[ "$ARG1" == "all" ]]; then
  PROCESS_ALL=true
fi

# Navigate to repository root
function navigate_to_project_root() {
  local repo_root_marker=".github"
  local script_path
  script_path=$(dirname "$(realpath "$0")")

  while [[ "$script_path" != "/" ]] && [[ ! -d "$script_path/$repo_root_marker" ]]; do
    script_path=$(dirname "$script_path")
  done

  if [[ "$script_path" == "/" ]]; then
    echo "Error: Unable to find the repository root." >&2
    exit 1
  fi

  cd "$script_path"
}

navigate_to_project_root
REPO_ROOT="$(pwd)"

# process a single module name
process_module() {
  local MODULE="$1"

  MODULE_LIST_FILE="$REPO_ROOT/wcs/module_list.txt"
  if [[ -f "$MODULE_LIST_FILE" ]]; then
    match=$(grep -E "\[${MODULE//./\.}\]=" "$MODULE_LIST_FILE" || true)
    if [[ -n "$match" ]]; then
      rhs=$(echo "$match" | sed -E 's/^[^=]*=//')
      rhs=$(echo "$rhs" | tr -d ' "')
      if [[ -n "$rhs" ]]; then
        INDEX_TEMPLATE_BASENAME="$rhs"
      fi
    fi
  fi

  INDEX_TEMPLATE_PATH="plugins/setup/src/main/resources/$INDEX_TEMPLATE_BASENAME"
  TEMPLATE_SETTINGS="wcs/${MODULE}/fields/template-settings.json"
  TEMPLATE_SETTINGS_LEGACY="wcs/${MODULE}/fields/template-settings-legacy.json"

  if ! command -v jq &>/dev/null; then
    echo "Error: 'jq' is required but not installed." >&2
    exit 1
  fi

  if [[ -z "$MODULE" ]]; then
    echo "Usage: $0 <module|all> [--apply]" >&2
    return 1
  fi

  if [[ ! -f "$REPO_ROOT/$INDEX_TEMPLATE_PATH" ]]; then
    echo "Warning: Index template not found at $INDEX_TEMPLATE_PATH" >&2
    return 0
  fi

  # jq filter to count fields
  JQ_FILTER='def count_fields: (keys_unsorted | length) + ( map( if type == "object" then (.properties | select(.) | count_fields) // 0 + (.fields | select(.) | count_fields) // 0 else 0 end ) | add ); .template.mappings.properties | count_fields'

  # jq filter to count nested fields
  JQ_NESTED_FILTER='def count_nested: [ .. | objects | select(.type == "nested") ] | length; .template.mappings.properties | count_nested'

  # jq filter to count date fields (includes multi-fields, which the dashboard also maps)
  JQ_DATE_FILTER='[ .template.mappings.properties | .. | objects | select(.type == "date" or .type == "date_nanos") ] | length'

  TOTAL_FIELDS=$(jq -r "$JQ_FILTER" "$REPO_ROOT/$INDEX_TEMPLATE_PATH" 2>/tmp/jq_error.log) || {
    echo "Error: Could not parse JSON or find .template.mappings.properties in $INDEX_TEMPLATE_PATH" >&2
    cat /tmp/jq_error.log >&2 || true
    rm -f /tmp/jq_error.log
    return 1
  }
  rm -f /tmp/jq_error.log

  NESTED_FIELDS=$(jq -r "$JQ_NESTED_FILTER" "$REPO_ROOT/$INDEX_TEMPLATE_PATH" 2>/tmp/jq_nested_error.log) || {
    echo "Error: Could not count nested fields in $INDEX_TEMPLATE_PATH" >&2
    cat /tmp/jq_nested_error.log >&2 || true
    rm -f /tmp/jq_nested_error.log
    return 1
  }
  rm -f /tmp/jq_nested_error.log

  DATE_FIELDS=$(jq -r "$JQ_DATE_FILTER" "$REPO_ROOT/$INDEX_TEMPLATE_PATH" 2>/tmp/jq_date_error.log) || {
    echo "Error: Could not count date fields in $INDEX_TEMPLATE_PATH" >&2
    cat /tmp/jq_date_error.log >&2 || true
    rm -f /tmp/jq_date_error.log
    return 1
  }
  rm -f /tmp/jq_date_error.log

  # compute next multiple of 500 for total fields
  PROPOSED_TOTAL=$((((TOTAL_FIELDS + 499) / 500) * 500))
  # Cap at minimum of 1000
  if [[ $PROPOSED_TOTAL -lt 1000 ]]; then
    PROPOSED_TOTAL=1000
  fi

  # compute next multiple of 50 for nested fields (smaller increment due to lower typical counts)
  PROPOSED_NESTED=$((((NESTED_FIELDS + 49) / 50) * 50))

  # Ensure minimum of 50 for nested fields if any nested fields exist
  if [[ $NESTED_FIELDS -gt 0 && $PROPOSED_NESTED -lt 50 ]]; then
    PROPOSED_NESTED=50
  fi

  # compute strictly-next multiple of 100 for docvalue fields, so there is always headroom
  # for new date fields (a count equal to the limit is legal but leaves no margin)
  PROPOSED_DOCVALUE=$(((DATE_FIELDS / 100 + 1) * 100))

  cat <<EOF
Module: $MODULE
Index template: $INDEX_TEMPLATE_PATH
Total fields: $TOTAL_FIELDS
Proposed mapping.total_fields.limit: $PROPOSED_TOTAL
Nested fields: $NESTED_FIELDS
Proposed mapping.nested_fields.limit: $PROPOSED_NESTED
Date fields: $DATE_FIELDS
Proposed index.max_docvalue_fields_search: $PROPOSED_DOCVALUE
EOF

  if ! $APPLY; then
    echo "Dry-run mode. To apply the change add --apply" >&2
    return 0
  fi

  # Build the jq clause that raises index.max_docvalue_fields_search, or nothing if the file
  # already allows at least the proposed value. The limit is never lowered, since an explicit
  # higher value may have been set on purpose.
  docvalue_clause() {
    local file="$1"
    local prefix="$2" # ".template.settings" or ".settings"
    local current flat_key

    flat_key=false
    if jq -e "${prefix}[\"index.max_docvalue_fields_search\"]" "$file" >/dev/null 2>&1; then
      flat_key=true
    fi

    current=$(jq -r "${prefix}[\"index.max_docvalue_fields_search\"] // ${prefix}.index[\"max_docvalue_fields_search\"] // empty" "$file" 2>/dev/null || true)
    if [[ -n "$current" && $current -ge $PROPOSED_DOCVALUE ]]; then
      return 0
    fi

    if $flat_key; then
      echo "${prefix}[\"index.max_docvalue_fields_search\"] = $PROPOSED_DOCVALUE"
    else
      echo "${prefix}.index[\"max_docvalue_fields_search\"] = $PROPOSED_DOCVALUE"
    fi
  }

  # Update JSON files in place using jq
  update_file() {
    local file="$1"
    if [[ ! -f "$REPO_ROOT/$file" ]]; then
      echo "Skipping missing file: $file" >&2
      return
    fi

    local updated=false
    local dv_clause=""

    # Handle .template.settings structure
    if jq -e '.template? and .template.settings?' "$REPO_ROOT/$file" >/dev/null 2>&1; then
      tmpfile=$(mktemp)
      last_hex=$(tail -c1 "$REPO_ROOT/$file" 2>/dev/null | od -An -t x1 | tr -d ' \t\n' || true)

      # Update total_fields.limit, only update nested_fields.limit if proposed value is greater than 50
      jq_update_cmd=".template.settings[\"mapping.total_fields.limit\"] = $PROPOSED_TOTAL"
      if [[ $NESTED_FIELDS -gt 0 && $PROPOSED_NESTED -gt 50 ]]; then
        jq_update_cmd="$jq_update_cmd | .template.settings[\"mapping.nested_fields.limit\"] = $PROPOSED_NESTED"
      fi
      dv_clause=$(docvalue_clause "$REPO_ROOT/$file" ".template.settings")
      if [[ -n "$dv_clause" ]]; then
        jq_update_cmd="$jq_update_cmd | $dv_clause"
      fi

      jq "$jq_update_cmd" "$REPO_ROOT/$file" >"$tmpfile"
      if [[ -n "$last_hex" && "$last_hex" != "0a" ]]; then
        perl -0777 -pe 's/\n\z//' "$tmpfile" >"${tmpfile}.fix" && mv "${tmpfile}.fix" "$tmpfile"
      fi
      mv "$tmpfile" "$REPO_ROOT/$file"
      echo "Updated $file -> total_fields: $PROPOSED_TOTAL, nested_fields: $PROPOSED_NESTED${dv_clause:+, max_docvalue_fields_search: $PROPOSED_DOCVALUE}"
      updated=true
    # Handle .settings structure
    elif jq -e '.settings?' "$REPO_ROOT/$file" >/dev/null 2>&1; then
      tmpfile=$(mktemp)
      last_hex=$(tail -c1 "$REPO_ROOT/$file" 2>/dev/null | od -An -t x1 | tr -d ' \t\n' || true)

      # Update total_fields.limit, only update nested_fields.limit if proposed value is greater than 50
      jq_update_cmd=".settings[\"mapping.total_fields.limit\"] = $PROPOSED_TOTAL"
      if [[ $NESTED_FIELDS -gt 0 && $PROPOSED_NESTED -gt 50 ]]; then
        jq_update_cmd="$jq_update_cmd | .settings[\"mapping.nested_fields.limit\"] = $PROPOSED_NESTED"
      fi
      dv_clause=$(docvalue_clause "$REPO_ROOT/$file" ".settings")
      if [[ -n "$dv_clause" ]]; then
        jq_update_cmd="$jq_update_cmd | $dv_clause"
      fi

      jq "$jq_update_cmd" "$REPO_ROOT/$file" >"$tmpfile"
      if [[ -n "$last_hex" && "$last_hex" != "0a" ]]; then
        perl -0777 -pe 's/\n\z//' "$tmpfile" >"${tmpfile}.fix" && mv "${tmpfile}.fix" "$tmpfile"
      fi
      mv "$tmpfile" "$REPO_ROOT/$file"
      echo "Updated $file -> total_fields: $PROPOSED_TOTAL, nested_fields: $PROPOSED_NESTED${dv_clause:+, max_docvalue_fields_search: $PROPOSED_DOCVALUE}"
      updated=true
    fi

    if [[ "$updated" == "false" ]]; then
      echo "No mapping limits found in $file. Skipping." >&2
    fi
  }

  update_file "$TEMPLATE_SETTINGS"
  update_file "$TEMPLATE_SETTINGS_LEGACY"
  update_file "$INDEX_TEMPLATE_PATH"

  echo "Done. Files updated."
}

# If PROCESS_ALL, read module_list and process only stateless/ , cti/ and filters/ modules
if $PROCESS_ALL; then
  MODULE_LIST_FILE="$REPO_ROOT/wcs/module_list.txt"
  if [[ ! -f "$MODULE_LIST_FILE" ]]; then
    echo "Error: $MODULE_LIST_FILE not found" >&2
    exit 1
  fi

  modules_block=$(awk 'BEGIN{inside=0} /module_to_file=\(/ {inside=1; next} inside && /^\)/ {exit} inside {print}' "$MODULE_LIST_FILE" || true)
  if [[ -z "$modules_block" ]]; then
    echo "Error: Could not find module_to_file(...) block in $MODULE_LIST_FILE" >&2
    exit 1
  fi

  mapfile -t MODULES < <(echo "$modules_block" | grep -oP '\[\K[^\]]+(?=\])' || true)
  # Keep only stateless/ and cti/ modules
  filtered=()
  for m in "${MODULES[@]:-}"; do
    if [[ "$m" == stateless/* || "$m" == cti/* || "$m" == filters || "$m" == cve ]]; then
      filtered+=("$m")
    fi
  done
  MODULES=("${filtered[@]}")

  if [[ ${#MODULES[@]} -eq 0 ]]; then
    echo "No stateless/* or cti/* modules found in $MODULE_LIST_FILE" >&2
    exit 1
  fi

  for m in "${MODULES[@]}"; do
    process_module "$m"
  done
  exit 0
fi

# Otherwise process the single module provided as ARG1
MODULE="$ARG1"
process_module "$MODULE" || exit $?
