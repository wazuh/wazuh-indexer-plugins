#!/bin/bash

set -e

module_sets=(
    "states"     # Wazuh state modules (inventory)
    "stateless"  # Wazuh stateless modules (alerts, archives)
    "stateless-" # Third-party log sources (aws, cisco, etc.)
)

declare -A wazuh_modules
declare -A third_party_modules

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
# Initializes the module list by scanning the ecs/ directory
# ====
function init_module_list() {
    for set in "${module_sets[@]}"; do
        map_modules_in_set "$set"
    done
}

# ====
# Map modules in a given set to their corresponding template files
# ====
function map_modules_in_set() {
    local set="$1"
    local modules

    case "$set" in
        states)
            for module in ecs/states-*; do
                module_name=$(basename "$module")
                wazuh_modules["$module_name"]="index-template-${module_name/states-/}.json"
            done
            ;;
        stateless)
            wazuh_modules["stateless"]="index-template-alerts.json"
            ;;
        stateless-*)
            modules=$(find ecs -type d -name "stateless-*" ! -name "stateless-template*" -printf "%f\n")
            for module in $modules; do
                third_party_modules["$module"]="index-template-${module/stateless-/}.json"
            done
            ;;
        *)
            echo "Unknown module set: $set"
            ;;
    esac
}

# ====
# Main function
# ====
function main() {
    navigate_to_project_root
    output_file="ecs/module_list.txt"
    init_module_list

    # Print in Bash associative array format
    echo "module_to_file=(" > "$output_file"
    echo "  # Wazuh modules" >> "$output_file"
    for key in "${!wazuh_modules[@]}"; do
        echo "  [$key]=${wazuh_modules[$key]}" >> "$output_file"
    done
    echo "  # Third-party stateless modules" >> "$output_file"
    for key in "${!third_party_modules[@]}"; do
        echo "  [$key]=${third_party_modules[$key]}" >> "$output_file"
    done
    echo ")" >> "$output_file"
    echo "Module list written to $output_file"
}

main "$@"
