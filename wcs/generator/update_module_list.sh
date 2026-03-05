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
# Map third-party stateless modules (only main module)
# ====
function map_stateless_modules() {
  if [[ -d "wcs/stateless/main" ]]; then
    all_modules["stateless/main"]="templates/streams/main.json"
  fi
}

# ====
# Map settings module
# ====
function map_settings_modules() {
  if [[ -d "wcs/settings/fields" ]]; then
    all_modules["settings"]="templates/settings.json"
  fi
}

# ====
# Map CTI IoC modules
# ====
function map_cti_modules() {
  # Map first-level directories in stateless (excluding special directories)
  for dir in wcs/cti/*; do
    if [[ -d "$dir" ]]; then
      local module_name
      module_name=$(basename "$dir")

      # Skip special directories
      if [[ "$module_name" == "main" || "$module_name" == "template" || "$module_name" == "mappings" ]]; then
        continue
      fi
      # Regular stateless module
      all_modules["cti/$module_name"]="templates/cti/${module_name}.json"
    fi
  done
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
  
  # Output settings module
  echo "  # Settings modules" >>"$output_file"

  if [[ -n "${all_modules["settings"]}" ]]; then
    echo "  [settings]=${all_modules["settings"]}" >>"$output_file"
  fi

  echo "  # CTI stateless modules" >>"$output_file"

  # Output CTI IoC modules (sorted, excluding main)
  for key in $(printf '%s\n' "${!all_modules[@]}" | grep "^cti/" | grep -v "^cti/main$" | sort); do
    echo "  [$key]=${all_modules[$key]}" >>"$output_file"
  done

  echo "  # Third-party stateless modules" >>"$output_file"

  # Output only the main stateless module
  if [[ -n "${all_modules["stateless/main"]}" ]]; then
    echo "  [stateless/main]=${all_modules["stateless/main"]}" >>"$output_file"
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

  map_cti_modules

  # Sort and output
  sort_and_output_modules "$output_file"

  echo "Module list written to $output_file"
}

main "$@"
