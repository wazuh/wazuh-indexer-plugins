#!/usr/bin/env bash

# Generates index templates for modified ECS modules.
# Requirements (required by run_generator.sh):
#   - Docker
#   - Docker Compose

# Constants
ECS_VERSION=${ECS_VERSION:-v9.1.0}
BASE_BRANCH=${BASE_BRANCH:-main}

set -euo pipefail

# Global variables
declare -a modules_to_update
declare -A module_to_file
declare force_update=false

# ====
# Checks that the script is run from the intended location
# ====
function navigate_to_project_root() {
  local script_path
  script_path=$(dirname "$(realpath "$0")")

  while [[ "$script_path" != "/" ]] && [[ ! -d "$script_path/.github" ]]; do
    script_path=$(dirname "$script_path")
  done

  if [[ "$script_path" == "/" ]]; then
    echo "Error: Unable to find the repository root."
    exit 1
  fi

  cd "$script_path"
  echo "$script_path"
}

# ====
# Detect modified modules by comparing the current branch with the base branch.
# ====
function detect_modified_modules() {
  echo "---> Modules"
  for ecs_module in "${!module_to_file[@]}"; do
    echo "  - $ecs_module -> ${module_to_file[$ecs_module]}"
  done

  echo
  echo "Detecting changes..."
  git fetch origin +refs/heads/main:refs/remotes/origin/main
  local modified_files
  local modified_modules=()
  modified_files=$(git diff --name-only origin/"$BASE_BRANCH")
  for file in $modified_files; do
    if [[ $file == ecs/state* && ( $file == *.yml || $file == *.json ) ]]; then
      matched=false
      # Try to match the file to one of the known module keys for exact detection
      for key in "${!module_to_file[@]}"; do
        if [[ $file == ecs/$key/* || $file == ecs/$key ]]; then
          ecs_module="$key"
          matched=true
          break
        fi
      done

      # Ignore the template folder "stateless/template" from modified modules
      if [[ "$ecs_module" == "stateless/template" ]]; then
        continue
      fi

      # Add only if not already present
      found=false
      for m in "${modified_modules[@]}"; do
        if [[ "$m" == "$ecs_module" ]]; then
          found=true
          break
        fi
      done
      if [[ "$found" == false ]]; then
        modified_modules+=("$ecs_module")
      fi
    fi
  done

  echo
  echo "---> Modified modules"
  modules_to_update=()

  local is_main_module_modified=false

  for ecs_module in "${modified_modules[@]}"; do
    echo "  - $ecs_module"
    if [[ "$ecs_module" == "stateless/main" ]]; then
      is_main_module_modified=true
    fi
    if [[ ! -v module_to_file[$ecs_module] ]]; then
      echo "Warning: Module '$ecs_module' not found in module list. Probably removed. Skipping."
      continue
    fi
    if [[ -n "${module_to_file[$ecs_module]}" ]]; then
      modules_to_update+=("$ecs_module")
    fi
  done
  if [[ "$is_main_module_modified" == true ]]; then
    # Add all module keys starting with 'stateless/' to modules_to_update (avoid duplicates)
    for key in "${!module_to_file[@]}"; do
      if [[ "$key" == stateless/* ]]; then
        skip=false
        for exist in "${modules_to_update[@]}"; do
          if [[ "$exist" == "$key" ]]; then
            skip=true
            break
          fi
        done
        if [[ "$skip" == false ]]; then
          modules_to_update+=("$key")
        fi
      fi
    done
  fi
}

# ====
# Run the mappings generator for each modified module.
# ====
function update_modified_modules() {
  echo
  echo "---> Running WCS generator..."
  if [[ ${#modules_to_update[@]} -gt 0 ]]; then
    for ecs_module in "${modules_to_update[@]}"; do
      echo "  - $ecs_module"
      if ! bash ecs/generator/run_generator.sh run "$ecs_module"; then
        echo "Error: Failed to run WCS generator for module: $ecs_module"
        bash ecs/generator/run_generator.sh down
        exit 1
      fi
      bash ecs/generator/run_generator.sh down
    done
  else
    echo "No relevant modifications detected in ecs/ directory."
    bash ecs/generator/run_generator.sh down
    exit 0
  fi
  bash ecs/generator/run_generator.sh down
}

# ====
# Copy index templates and CSV documentation to their corresponding folders.
#  - Index templates are copied to plugins/setup/src/main/resources/
#  - CSV documentation is copied to ecs/<module>/docs/
# ====
function copy_files() {
  local repo_path="$1"
  echo
  echo "Copying files..."

  echo "---> Index templates"
  local destination_file
  local resources_path="plugins/setup/src/main/resources"
  local mappings_path="mappings/${ECS_VERSION}/generated/elasticsearch/legacy/template.json"
  for ecs_module in "${modules_to_update[@]}"; do
    # Copying index templates to the initialization plugin resources folder
    destination_file=${module_to_file[$ecs_module]}
    cp "$repo_path/ecs/$ecs_module/$mappings_path" "$resources_path/$destination_file"
    echo "  - '$destination_file' updated"

    # Generate archives index template from the alerts one
    if [ "$ecs_module" == "stateless/main" ]; then
      destination_file="$resources_path/templates/streams/archives.json"
      echo "  - Generate template for module '$ecs_module/archives' to '$destination_file'"
      cp "$repo_path/ecs/$ecs_module/$mappings_path" "$destination_file"
      sed -i 's/wazuh-alerts/wazuh-archives/g' "$destination_file"
    fi
  done

  echo "---> CSV documentation"
  local docs_path
  local csv_path="mappings/${ECS_VERSION}/generated/csv/fields.csv"
  for ecs_module in "${modules_to_update[@]}"; do
    # Copying CSV documentation to the ecs/<module>/docs/ folder
    docs_path="$repo_path/ecs/$ecs_module/docs"
    mkdir -p "$docs_path"
    cp "$repo_path/ecs/$ecs_module/$csv_path" "$docs_path/fields.csv"
    echo "  - '$ecs_module' docs"
  done
}

# ====
# Display usage information.
# ====
function usage() {
  echo "Usage: $0
  Options:
    -h            Show this help message
    -f            Force update all modules"
  exit 1
}

# ====
# Main function.
# ====
function main() {
  while getopts ":fh" arg; do
    case ${arg} in
    f)
      # Force update all modules
      force_update=true
      ;;
    h)
      usage
      ;;
    ?)
      echo "Invalid option: -${arg}"
      exit 1
      ;;
    esac
  done
  local repo_path
  repo_path=$(navigate_to_project_root)

  # Read the module list generated by update_module_list.sh
  module_list="$repo_path/ecs/module_list.txt"
  if [[ ! -f "${module_list}" ]]; then
    echo "Error: Module list file not found at ${module_list}"
    exit 1
  fi
  echo "Loading module list from ${module_list}"
  # shellcheck source=module_list.txt
  # shellcheck disable=SC1091
  source "${module_list}"
  if [[ ${#module_to_file[@]} -eq 0 ]]; then
    echo "Error: No modules found in the module list."
    exit 1
  fi

  navigate_to_project_root
  if [ "$force_update" = true ]; then
    echo "Force update enabled. All modules will be updated."
    modules_to_update=("${!module_to_file[@]}")
  else
    detect_modified_modules
  fi
  update_modified_modules
  copy_files "$repo_path"
}

main "$@"
