#!/usr/bin/env bash

# Count fields in a generated index template and update mapping.total_fields.limit
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

# If ARG1 is 'all' we will read module names from ecs/module_list.txt
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

  MODULE_LIST_FILE="$REPO_ROOT/ecs/module_list.txt"
  INDEX_TEMPLATE_BASENAME="index-template-${MODULE}.json"
  if [[ "$MODULE" == stateless-* ]]; then
    short=${MODULE#stateless-}
    INDEX_TEMPLATE_BASENAME="index-template-${short}.json"
  fi
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
  TEMPLATE_SETTINGS="ecs/${MODULE}/fields/template-settings.json"
  TEMPLATE_SETTINGS_LEGACY="ecs/${MODULE}/fields/template-settings-legacy.json"

  if ! command -v jq &> /dev/null; then
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
  JQ_FILTER='def count_fields: (keys_unsorted | length) + ( map( if type == "object" then (.properties | select(.) | count_fields) // 0 + (.fields | select(.) | count_fields) // 0 else 0 end ) | add ); .mappings.properties | count_fields'

  TOTAL_FIELDS=$(jq -r "$JQ_FILTER" "$REPO_ROOT/$INDEX_TEMPLATE_PATH" 2> /tmp/jq_error.log) || {
    echo "Error: Could not parse JSON or find .mappings.properties in $INDEX_TEMPLATE_PATH" >&2
    cat /tmp/jq_error.log >&2 || true
    rm -f /tmp/jq_error.log
    return 1
  }
  rm -f /tmp/jq_error.log

  # compute next multiple of 500
  PROPOSED=$(( ( (TOTAL_FIELDS + 499) / 500 ) * 500 ))

  cat <<EOF
Module: $MODULE
Index template: $INDEX_TEMPLATE_PATH
Total fields: $TOTAL_FIELDS
Proposed mapping.total_fields.limit: $PROPOSED
EOF

  if ! $APPLY; then
    echo "Dry-run mode. To apply the change add --apply" >&2
    return 0
  fi

  # Update JSON files in place using jq
  update_file() {
    local file="$1"
    if [[ ! -f "$REPO_ROOT/$file" ]]; then
      echo "Skipping missing file: $file" >&2
      return
    fi
    if jq -e '.template? and .template.settings? and .template.settings["mapping.total_fields.limit"]' "$REPO_ROOT/$file" > /dev/null 2>&1; then
      tmpfile=$(mktemp)
      last_hex=$(tail -c1 "$REPO_ROOT/$file" 2> /dev/null | od -An -t x1 | tr -d ' \t\n' || true)
      jq ".template.settings[\"mapping.total_fields.limit\"] = $PROPOSED" "$REPO_ROOT/$file" > "$tmpfile"
      if [[ -n "$last_hex" && "$last_hex" != "0a" ]]; then
        perl -0777 -pe 's/\n\z//' "$tmpfile" > "${tmpfile}.fix" && mv "${tmpfile}.fix" "$tmpfile"
      fi
      mv "$tmpfile" "$REPO_ROOT/$file"
      echo "Updated $file -> $PROPOSED"
    elif jq -e '.settings? and .settings["mapping.total_fields.limit"]' "$REPO_ROOT/$file" > /dev/null 2>&1; then
      tmpfile=$(mktemp)
      last_hex=$(tail -c1 "$REPO_ROOT/$file" 2> /dev/null | od -An -t x1 | tr -d ' \t\n' || true)
      jq ".settings[\"mapping.total_fields.limit\"] = $PROPOSED" "$REPO_ROOT/$file" > "$tmpfile"
      if [[ -n "$last_hex" && "$last_hex" != "0a" ]]; then
        perl -0777 -pe 's/\n\z//' "$tmpfile" > "${tmpfile}.fix" && mv "${tmpfile}.fix" "$tmpfile"
      fi
      mv "$tmpfile" "$REPO_ROOT/$file"
      echo "Updated $file -> $PROPOSED"
    else
      echo "No mapping.total_fields.limit key found in $file. Skipping." >&2
    fi
  }

  update_file "$TEMPLATE_SETTINGS"
  update_file "$TEMPLATE_SETTINGS_LEGACY"
  update_file "$INDEX_TEMPLATE_PATH"

  echo "Done. Files updated."
}

# If PROCESS_ALL, read module_list and process only stateless-* modules
if $PROCESS_ALL; then
  MODULE_LIST_FILE="$REPO_ROOT/ecs/module_list.txt"
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
  # Keep only stateless- modules
  filtered=()
  for m in "${MODULES[@]:-}"; do
    if [[ "$m" == stateless-* ]]; then
      filtered+=("$m")
    fi
  done
  MODULES=("${filtered[@]}")

  if [[ ${#MODULES[@]} -eq 0 ]]; then
    echo "No stateless-* modules found in $MODULE_LIST_FILE" >&2
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

