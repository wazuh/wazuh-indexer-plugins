#!/bin/bash

set -e

declare -A all_modules

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
  if [[ -d "wcs/stateless/events/unclassified" ]]; then
    all_modules["stateless/events/unclassified"]="templates/streams/unclassified.json"
  fi
  if [[ -d "wcs/stateless/events/findings" ]]; then
    all_modules["stateless/events/findings"]="templates/findings-mappings.json"
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
}

# ====
# Map settings module
# ====
function map_settings_modules() {
  local module_name="settings"
  all_modules["$module_name"]="templates/${module_name}.json"
}

# ====
# Map IoC module
# ====
function map_ioc_module() {
  local module_name="content/ioc"
  all_modules["$module_name"]="templates/${module_name}.json"
}

# ====
# Map Engine Filter module
# ====
function map_engine_filter_module() {
  local module_name="content/filters"
  all_modules["$module_name"]="templates/${module_name}.json"
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

  if [[ -n "${all_modules[content/filters]}" ]]; then
    echo "  # Engine filter module" >>"$output_file"
    echo "  [content/filters]=${all_modules[content/filters]}" >>"$output_file"
  fi

  if [[ -n "${all_modules[content/ioc]}" ]]; then
    echo "  # IoC module" >>"$output_file"
    echo "  [content/ioc]=${all_modules[content/ioc]}" >>"$output_file"
  fi

  if [[ -n "${all_modules[cve]}" ]]; then
    echo "  # CVE module" >>"$output_file"
    echo "  [cve]=${all_modules[cve]}" >>"$output_file"
  fi

  echo ")" >>"$output_file"
}

# ====
# Main function
# ====
function main() {
  navigate_to_project_root
  output_file="wcs/module_list.txt"

  # Clear the associative array
  unset all_modules
  declare -A all_modules

  # Map all modules
  map_stateful_modules

  map_stateless_modules

  map_settings_modules

  map_ioc_module

  map_engine_filter_module

  map_cve_module

  # Sort and output
  sort_and_output_modules "$output_file"

  echo "Module list written to $output_file"
}

main "$@"
