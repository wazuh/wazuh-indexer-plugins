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

# Modules whose generated template must be converted from static properties to
# dynamic_templates, to keep the field mapping count of the wazuh-events and
# wazuh-findings data streams low. See convert_to_dynamic_templates.py.
declare -a dynamic_template_modules=("stateless/events/main" "stateless/events/findings")

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
    if [[ ($file == wcs/state* || $file == wcs/content* || $file == wcs/settings* || $file == wcs/cve* || $file == wcs/ai-assistant* || $file == wcs/internal-state*) && ($file == *.yml || $file == *.json) ]]; then
      # Try to match the file to one of the known module keys for exact detection
      for key in "${!module_to_file[@]}"; do
        if [[ $file == wcs/$key/* || $file == wcs/$key ]]; then
          ecs_module="$key"
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

  # If stateless/events/main is modified, add all other stateless modules
  local main_modified=false
  for m in "${modified_modules[@]}"; do
    if [[ "$m" == "stateless/events/main" ]]; then
      main_modified=true
      break
    fi
  done

  if [[ "$main_modified" == true ]]; then
    echo
    echo "---> stateless/events/main modified: adding all stateless/events modules"
    for key in "${!module_to_file[@]}"; do
      if [[ "$key" == stateless/events/* && "$key" != "stateless/events/main" ]]; then
        # Add only if not already present
        found=false
        for m in "${modified_modules[@]}"; do
          if [[ "$m" == "$key" ]]; then
            found=true
            break
          fi
        done
        if [[ "$found" == false ]]; then
          modified_modules+=("$key")
          echo "  - $key (added)"
        fi
      fi
    done
  fi

  echo
  echo "---> Modified modules"
  modules_to_update=()

  for ecs_module in "${modified_modules[@]}"; do
    echo "  - $ecs_module"
    if [[ ! -v module_to_file[$ecs_module] ]]; then
      echo "Warning: Module '$ecs_module' not found in module list. Probably removed. Skipping."
      continue
    fi
    if [[ -n "${module_to_file[$ecs_module]}" ]]; then
      modules_to_update+=("$ecs_module")
    fi
  done
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
      if ! bash wcs/generator/run_generator.sh run "$ecs_module"; then
        echo "Error: Failed to run WCS generator for module: $ecs_module"
        bash wcs/generator/run_generator.sh down
        exit 1
      fi
      bash wcs/generator/run_generator.sh down
    done
  else
    echo "No relevant modifications detected in wcs/ directory."
    bash wcs/generator/run_generator.sh down
    exit 0
  fi
  bash wcs/generator/run_generator.sh down
}

# ====
# Copy index templates and CSV documentation to their corresponding folders.
#  - Index templates are copied to plugins/setup/src/main/resources/
#  - Content Manager mappings are derived from those templates, for the content modules whose
#    mappings that plugin also needs, at a path derived from the module name
#  - CSV documentation is copied to wcs/<module>/docs/
# ====
function copy_files() {
  local repo_path="$1"
  echo
  echo "Copying files..."

  echo "---> Index templates"
  local destination_file
  local destination_path
  local resources_path="plugins/setup/src/main/resources"
  local mappings_path="mappings/${ECS_VERSION}/generated/elasticsearch/legacy/opensearch-template.json"
  for ecs_module in "${modules_to_update[@]}"; do
    # Skip modules without a template mapping
    destination_file=${module_to_file[$ecs_module]}
    if [[ -z "$destination_file" ]]; then
      echo "  - '$ecs_module' skipped (no index template)"
      continue
    fi
    # Most modules map to a bare filename copied under the setup plugin's resources.
    # A module whose value is already a full repo-relative path (starts with
    # "plugins/") is consumed by a different plugin (e.g. internal-state, read by
    # content-manager's CredentialsIndex), so copy it there directly instead.
    if [[ "$destination_file" == plugins/* ]]; then
      destination_path="$destination_file"
    else
      destination_path="$resources_path/$destination_file"
    fi
    cp "$repo_path/wcs/$ecs_module/$mappings_path" "$destination_path"
    echo "  - '$destination_path' updated"
  done

  echo "---> Dynamic templates"
  for ecs_module in "${modules_to_update[@]}"; do
    for dynamic_module in "${dynamic_template_modules[@]}"; do
      if [[ "$ecs_module" == "$dynamic_module" ]]; then
        destination_path="$resources_path/${module_to_file[$ecs_module]}"
        python3 "$repo_path/wcs/generator/convert_to_dynamic_templates.py" "$destination_path" "$destination_path"
        echo "  - '$destination_path' converted to dynamic_templates"
      fi
    done
  done

  echo "---> Content Manager mappings"
  local cm_mapping
  local content_name
  for ecs_module in "${modules_to_update[@]}"; do
    # Only the content modules have a second consumer. The path is derived rather than mapped: a
    # second entry per module in module_list.txt breaks the tools that grep it for a module's
    # index template, count_and_update_total_fields.sh among them.
    if [[ "$ecs_module" != content/* ]]; then
      continue
    fi
    content_name=${ecs_module#content/}
    case "$content_name" in
      # The Content Manager named its CVE mappings after the content, not the module.
      vulnerabilities) cm_mapping="cti-cve-mappings.json" ;;
      *) cm_mapping="cti-${content_name}-mappings.json" ;;
    esac
    cm_mapping="plugins/content-manager/src/main/resources/mappings/${cm_mapping}"
    if [[ ! -f "$cm_mapping" ]]; then
      echo "  - '$ecs_module' skipped (no Content Manager copy at $cm_mapping)"
      continue
    fi
    destination_path="$resources_path/${module_to_file[$ecs_module]}"
    python3 "$repo_path/wcs/generator/sync_content_mappings.py" "$destination_path" "$cm_mapping"
    echo "  - '$cm_mapping' derived from '$destination_path'"
  done

  echo "---> CSV documentation"
  local docs_path
  local csv_path="mappings/${ECS_VERSION}/generated/csv/fields.csv"
  for ecs_module in "${modules_to_update[@]}"; do
    # Copying CSV documentation to the wcs/<module>/docs/ folder
    docs_path="$repo_path/wcs/$ecs_module/docs"
    mkdir -p "$docs_path"
    cp "$repo_path/wcs/$ecs_module/$csv_path" "$docs_path/fields.csv"
    echo "  - '$ecs_module' docs"
  done

  echo "---> Flat WCS template"
  local docs_ecs_path
  local flat_ecs_path="mappings/${ECS_VERSION}/generated/ecs/ecs_flat.yml"
  for ecs_module in "${modules_to_update[@]}"; do
    # Flat WCS is only required for the stateless, AI assistant and internal-state modules
    if [[ "$ecs_module" =~ stateless/* || "$ecs_module" =~ ai-assistant/* || "$ecs_module" == "internal-state" ]]; then
      # Copying flat WCS template to the wcs/<module>/docs/ folder
      docs_ecs_path="$repo_path/wcs/$ecs_module/docs"
      mkdir -p "$docs_ecs_path"
      cp "$repo_path/wcs/$ecs_module/$flat_ecs_path" "$docs_ecs_path/wcs_flat.yml"
      echo "  - '$ecs_module' wcs_flat.yml"
    fi
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
  module_list="$repo_path/wcs/module_list.txt"
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
