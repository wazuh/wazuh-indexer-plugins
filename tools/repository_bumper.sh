#!/bin/bash

# =========================
# Repository Bumper Script
# =========================
# Updates VERSION.json for a new version release, then (depending on flags)
# reinitializes CHANGELOG.md and pins workflow references to the right
# branch/tag.
#
# Usage: repository_bumper.sh --version VERSION --stage STAGE [--tag] [--set-as-main]

set -euo pipefail

function usage() {
    echo "Usage: $0 --version VERSION --stage STAGE [--tag] [--set-as-main]"
    echo "  --version VERSION   The new version to set in VERSION.json (e.g., 4.5.0)"
    echo "  --stage STAGE       The new stage to set in VERSION.json (alpha0, beta1, rc1, stable...)"
    echo "  --tag               Pin workflow references using tag format (v{version}-{stage})"
    echo "                      instead of branch format ({version})"
    echo "  --set-as-main       Enable main branch mode: bump version values only, keep"
    echo "                      workflow references pointing to main"
    exit 1
}

# ====
# Initialize logging
# Globals:
#   LOG_FILE
# ====
function init_logging() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local timestamp
    timestamp=$(date +"%Y-%m-%d_%H-%M-%S-%3N")
    LOG_FILE="$script_dir/repository_bumper_${timestamp}.log"
    exec > >(tee -a "$LOG_FILE") 2>&1
    log "Logging initialized. Log file: $LOG_FILE"
}

# ====
# Log messages with timestamp
# Arguments:
#   $1 - Message to log
# ====
function log() {
    echo "[$(date +"%Y-%m-%d %H:%M:%S")] $1"
}

# ====
# Navigate to the root of the repository
# Searches for a folder named `.github` as a marker
# Exits if root is not found
# ====
function navigate_to_project_root() {
    local repo_root_marker=".github"
    local script_path
    script_path=$(dirname "$(realpath "$0")")

    while [[ "$script_path" != "/" ]] && [[ ! -d "$script_path/$repo_root_marker" ]]; do
        script_path=$(dirname "$script_path")
    done

    if [[ "$script_path" == "/" ]]; then
        log "Error: Unable to find the repository root."
        exit 1
    fi

    cd "$script_path"
    log "Moved to repository root: $script_path"
}

# ====
# Validate input parameters
# Arguments:
#   $1 - version
#   $2 - stage
# ====
function validate_inputs() {
    local version="$1"
    local stage="$2"

    if ! [[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log "Error: Invalid version format '$version'."
        exit 1
    fi

    local normalized_stage
    normalized_stage=$(echo "$stage" | tr '[:upper:]' '[:lower:]')
    if ! [[ $normalized_stage =~ ^(alpha[0-9]*|beta[0-9]*|rc[0-9]*|stable)$ ]]; then
        log "Error: Invalid stage format '$stage'."
        exit 1
    fi
}

# ====
# Check if jq is installed
# ====
function check_jq_installed() {
    if ! command -v jq &>/dev/null; then
        log "Error: 'jq' is not installed. Please install it to use this script."
        exit 1
    fi
}

# ====
# Print the version currently set in VERSION.json
# ====
function current_version() {
    jq -r '.version' VERSION.json
}

# ====
# Update the VERSION.json file with the new version and stage
# Arguments:
#   $1 - version
#   $2 - stage
# ====
function update_version_file() {
    local version="$1"
    local stage="$2"
    local file="VERSION.json"

    if [[ ! -f "$file" ]]; then
        log "Error: $file not found in the current directory: $(pwd)"
        exit 1
    fi

    jq --arg v "$version" --arg s "$stage" \
        '.version = $v | .stage = $s' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"

    log "Updated $file with version=$version and stage=$stage"
}

# ====
# Parse command-line arguments
# Globals:
#   arg_version, arg_stage, arg_tag, arg_set_as_main
# ====
function parse_args() {
    declare -g arg_version=""
    declare -g arg_stage=""
    declare -g arg_tag=""
    declare -g arg_set_as_main=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --version)
                arg_version="$2"
                shift 2
                ;;
            --stage)
                arg_stage="$2"
                shift 2
                ;;
            --tag)
                arg_tag="yes"
                shift 1
                ;;
            --set-as-main)
                arg_set_as_main="yes"
                shift 1
                ;;
            *)
                log "Error: Unknown argument '$1'."
                usage
                ;;
        esac
    done

    if [[ -z "$arg_version" || -z "$arg_stage" ]]; then
        log "Error: --version and --stage are both required."
        usage
    fi

    if [[ -n "$arg_tag" && -n "$arg_set_as_main" ]]; then
        log "Error: --set-as-main cannot be used with --tag. --set-as-main keeps workflow" \
             "references pointing to main; --tag exists to convert them to a tag reference," \
             "which is never done on main."
        exit 1
    fi
}

# ====
# Main logic
# ====
function main() {
    parse_args "$@"

    init_logging
    log "Starting update for VERSION.json with version=$arg_version, stage=$arg_stage"

    navigate_to_project_root
    check_jq_installed
    validate_inputs "$arg_version" "$arg_stage"

    local old_version
    old_version="$(current_version)"

    update_version_file "$arg_version" "$arg_stage"

    if [[ "$arg_version" != "$old_version" ]]; then
        log "Version changed: $old_version -> $arg_version"
        bash "$(dirname "${BASH_SOURCE[0]}")/changelog_sync.sh" "$arg_version"
    else
        log "Version unchanged ($arg_version); stage-only bump."
    fi

    if [[ -z "$arg_set_as_main" ]]; then
        local refs_args=("$arg_version" "$arg_stage")
        [[ -n "$arg_tag" ]] && refs_args+=("--tag")
        bash "$(dirname "${BASH_SOURCE[0]}")/workflow_refs_sync.sh" "${refs_args[@]}"
    else
        log "Main branch mode enabled: workflow references left pointing to main."
    fi

    log "Update complete."
}

main "$@"
