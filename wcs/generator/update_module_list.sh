#!/bin/bash

set -e

declare -A all_modules
declare -A content_cm_mappings

# ====
# Checks that the script is run from the intended location
# ====
function navigate_to_project_root() {
  local repo_root_marker
  local script_path
  repo_root_marker=".github"
  script_path=$(dirname "$(realpath "$0")")

  while [[ "$script_path" != "/" ]] && [[ ! -d "$script_path/$repo_root_marker" ]]; do
    script_path=$(dirname "$script_path")
  done

  if [[ "$script_path" == "/" ]]; then
    echo "Error: Unable to find the repository root."
    exit 1
  fi

  cd "$script_path"
}

# ====
# Map stateful modules (only main module directories, not all subdirectories)
# ====
function map_stateful_modules() {
  # Map inventory modules
  if [[ -d "wcs/stateful/inventory" ]]; then
    for dir in wcs/stateful/inventory/*/; do
      if [[ -d "$dir" ]]; then
        local module_name
        module_name=$(basename "$dir")
        all_modules["stateful/inventory/$module_name"]="templates/states/inventory-${module_name}.json"
      fi
    done
  fi

  # Map FIM modules
  if [[ -d "wcs/stateful/fim" ]]; then
    for dir in wcs/stateful/fim/*/; do
      if [[ -d "$dir" ]]; then
        local module_name
        module_name=$(basename "$dir")
        # Special handling for windows-registry modules
        if [[ "$module_name" == "windows-registry-keys" ]]; then
          all_modules["stateful/fim/$module_name"]="templates/states/fim-registry-keys.json"
        elif [[ "$module_name" == "windows-registry-values" ]]; then
          all_modules["stateful/fim/$module_name"]="templates/states/fim-registry-values.json"
        else
          all_modules["stateful/fim/$module_name"]="templates/states/fim-${module_name}.json"
        fi
      fi
    done
  fi

  # Map other stateful modules (sca, vulnerabilities)
  for dir in wcs/stateful/*/; do
    if [[ -d "$dir" ]]; then
      local module_name
      module_name=$(basename "$dir")
      # Skip inventory and fim as they're handled above
      if [[ "$module_name" != "inventory" && "$module_name" != "fim" ]]; then
        all_modules["stateful/$module_name"]="templates/states/${module_name}.json"
      fi
    fi
  done
}

# ====
# Map third-party stateless modules (only main module directories, not subdirectories)
# ====
function map_stateless_modules() {
  # Map events submodules explicitly
  if [[ -d "wcs/stateless/events/main" ]]; then
    all_modules["stateless/events/main"]="templates/streams/events.json"
  fi
  if [[ -d "wcs/stateless/events/raw" ]]; then
    all_modules["stateless/events/raw"]="templates/streams/raw.json"
  fi
  if [[ -d "wcs/stateless/events/findings" ]]; then
    all_modules["stateless/events/findings"]="templates/streams/findings.json"
  fi

  # Map active-responses module explicitly
  if [[ -d "wcs/stateless/active-responses" ]]; then
    all_modules["stateless/active-responses"]="templates/streams/active-responses.json"
  fi

  # Map metrics submodules explicitly
  if [[ -d "wcs/stateless/metrics/agents" ]]; then
    all_modules["stateless/metrics/agents"]="templates/streams/metrics-agents.json"
  fi
  if [[ -d "wcs/stateless/metrics/comms" ]]; then
    all_modules["stateless/metrics/comms"]="templates/streams/metrics-comms.json"
  fi
  if [[ -d "wcs/stateless/metrics/engine" ]]; then
    all_modules["stateless/metrics/engine"]="templates/streams/metrics-normalization.json"
  fi
}

# ====
# Map AI assistant modules
# ====
function map_ai_assistant_modules() {
  if [[ -d "wcs/ai-assistant/sessions" ]]; then
    all_modules["ai-assistant/sessions"]="templates/streams/ai-assistant-sessions.json"
  fi
}

# ====
# Map internal-state module. Unlike every other module, its generated template
# is consumed by the content-manager plugin (CredentialsIndex), not by setup, so
# the mapped value is a full repo-relative path rather than a bare filename under
# plugins/setup/src/main/resources/templates/.
# ====
function map_internal_state_module() {
  if [[ -d "wcs/internal-state" ]]; then
    all_modules["internal-state"]="plugins/content-manager/src/main/resources/mappings/internal-state-mapping.json"
  fi
}

# ====
# Map settings module
# ====
function map_settings_modules() {
  local module_name="settings"
  all_modules["$module_name"]="templates/${module_name}.json"
}

# ====
# Map content modules. These describe the wazuh-threatintel-* indices the setup plugin creates
# and the Content Manager fills from CTI. Every directory under wcs/content/ is picked up, so a
# new content module needs no change here.
#
# Their mappings are consumed twice: the setup plugin creates the index from the generated index
# template, and the Content Manager keeps a bare mappings document so it can create the
# blue/green shadow index during a content swap without setup intervention. The second
# destination is recorded in content_cm_mappings and emitted as module_to_cm_mapping.
# ====
function map_content_modules() {
  local module_name
  local cm_file
  for dir in wcs/content/*/; do
    [[ -d "$dir" ]] || continue
    module_name=$(basename "$dir")
    all_modules["content/$module_name"]="templates/content/${module_name}.json"
    # The Content Manager named its CVE mappings after the content, not the module.
    case "$module_name" in
      vulnerabilities) cm_file="cti-cve-mappings.json" ;;
      *) cm_file="cti-${module_name}-mappings.json" ;;
    esac
    content_cm_mappings["content/$module_name"]="plugins/content-manager/src/main/resources/mappings/${cm_file}"
  done
}

# ====
# Map CVE module
# ====
function map_cve_module() {
  local module_name="cve"
  all_modules["$module_name"]="templates/${module_name}.json"
}

# ====
# Sort modules by type and name
# ====
function sort_and_output_modules() {
  local output_file="$1"

  echo "module_to_file=(" >"$output_file"
  echo "  # Wazuh modules" >>"$output_file"

  # Output stateful modules first (sorted)
  for key in $(printf '%s\n' "${!all_modules[@]}" | grep "^stateful/" | sort); do
    echo "  [$key]=${all_modules[$key]}" >>"$output_file"
  done

  echo "  # Stateless modules" >>"$output_file"
  # Output stateless events/main module first
  if [[ -n "${all_modules[stateless/events/main]}" ]]; then
    echo "  [stateless/events/main]=${all_modules[stateless/events/main]}" >>"$output_file"
  fi

  # Output remaining stateless modules (sorted, excluding events/main)
  for key in $(printf '%s\n' "${!all_modules[@]}" | grep "^stateless/" | grep -v "^stateless/events/main$" | sort); do
    echo "  [$key]=${all_modules[$key]}" >>"$output_file"
  done

  # Other modules
  if [[ -n "${all_modules[settings]}" ]]; then
    echo "  # Settings module" >>"$output_file"
    echo "  [settings]=${all_modules[settings]}" >>"$output_file"
  fi

  local content_keys
  content_keys=$(printf '%s\n' "${!all_modules[@]}" | grep "^content/" | sort)
  if [[ -n "$content_keys" ]]; then
    echo "  # Content modules" >>"$output_file"
    for key in $content_keys; do
      echo "  [$key]=${all_modules[$key]}" >>"$output_file"
    done
  fi

  if [[ -n "${all_modules[cve]}" ]]; then
    echo "  # CVE module" >>"$output_file"
    echo "  [cve]=${all_modules[cve]}" >>"$output_file"
  fi

  # AI assistant modules
  local ai_assistant_keys
  ai_assistant_keys=$(printf '%s\n' "${!all_modules[@]}" | grep "^ai-assistant/" | sort)
  if [[ -n "$ai_assistant_keys" ]]; then
    echo "  # AI assistant modules" >>"$output_file"
    for key in $ai_assistant_keys; do
      echo "  [$key]=${all_modules[$key]}" >>"$output_file"
    done
  fi

  if [[ -n "${all_modules[internal-state]}" ]]; then
    echo "  # Internal state module" >>"$output_file"
    echo "  [internal-state]=${all_modules[internal-state]}" >>"$output_file"
  fi

  echo ")" >>"$output_file"

  # Second destination for the content modules: the Content Manager's own copy of the mappings,
  # derived from the generated index template by sync_content_mappings.py.
  if [[ -n "$content_keys" ]]; then
    {
      echo
      echo "# Content modules whose mappings the Content Manager also needs. It keeps a bare mappings"
      echo "# document so it can create the blue/green shadow index during a content swap without setup"
      echo "# intervention, so both copies must describe the same index. Only the setup index template"
      echo "# above is authored; generate_schema.sh derives these from it via sync_content_mappings.py."
      echo "module_to_cm_mapping=("
      for key in $content_keys; do
        echo "  [$key]=${content_cm_mappings[$key]}"
      done
      echo ")"
    } >>"$output_file"
  fi
}

# ====
# Main function
# ====
function main() {
  navigate_to_project_root
  output_file="wcs/module_list.txt"

  # Clear the associative array
  unset all_modules content_cm_mappings
  declare -A all_modules
  declare -A content_cm_mappings

  # Map all modules
  map_stateful_modules

  map_stateless_modules

  map_settings_modules

  map_content_modules

  map_cve_module

  map_ai_assistant_modules

  map_internal_state_module

  # Sort and output
  sort_and_output_modules "$output_file"

  echo "Module list written to $output_file"
}

main "$@"
