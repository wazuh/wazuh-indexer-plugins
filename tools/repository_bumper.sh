#!/bin/bash

# =========================
# Repository Bumper Script
# =========================
# Updates VERSION.json for a new release, and, when --set-as-main is used,
# records the outgoing version under CHANGELOG.md's "## Prior versions".
#
# Arguments:
# 1. The new version to set (e.g., 4.5.0)
# 2. The new stage to set (alpha, beta, rc, stable)
#

set -euo pipefail

# ====
# Print usage instructions
# ====
function usage() {
    echo "Usage: $0 <version> <stage>"
    echo "  version:  The new version to set in VERSION.json (e.g., 4.5.0)"
    echo "  stage:    The new stage to set in VERSION.json (alpha, beta, rc, stable)"
    echo "  --set-as-main: (Optional) Enable main branch mode: bump version values only,"
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
# Determine the "org/repo" slug from the origin remote URL.
# ====
function get_repo_slug() {
    local remote_url
    remote_url=$(git remote get-url origin)
    remote_url="${remote_url%.git}"
    remote_url="${remote_url#*github.com/}"
    remote_url="${remote_url#*github.com:}"
    echo "$remote_url"
}

# ====
# Add the outgoing version to CHANGELOG.md's "## Prior versions" section.
# Only called when main moves to a new version (--set-as-main).
# Arguments:
#   $1 - previous version
# ====
function update_changelog_prior_versions() {
    local prev_version="$1"
    local file="CHANGELOG.md"
    local repo_slug
    repo_slug=$(get_repo_slug)
    local entry="- [${prev_version}](https://github.com/${repo_slug}/blob/${prev_version}/CHANGELOG.md)"

    if [[ ! -f "$file" ]]; then
        log "Warning: $file not found; skipping Prior versions update."
        return 0
    fi

    if grep -qF -- "$entry" "$file"; then
        log "Prior versions already contains an entry for $prev_version; skipping."
        return 0
    fi

    if grep -qE "^## Prior versions?$" "$file"; then
        # Matches singular or plural heading; replaces the "- []()" placeholder if present.
        awk -v entry="$entry" '
            /^## Prior versions?$/ && !done {
                print "## Prior versions"
                print entry
                done = 1
                skip_placeholder = 1
                next
            }
            skip_placeholder {
                skip_placeholder = 0
                if ($0 == "- []()") next
            }
            { print }
        ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
    else
        {
            echo ""
            echo "## Prior versions"
            echo "$entry"
        } >> "$file"
    fi

    log "Added $prev_version to Prior versions in $file"
}

# ====
# Main logic
# ====
function main() {
    if [ "$#" -lt 2 ]; then
        log "Error: Invalid number of arguments. Expected at least 2, got $#."
        usage
    fi

    if [[ $# -gt 3 ]]; then
        log "Error: Too many arguments. Expected at most 3, got $#."
        usage
    fi

    local version="$1"
    local stage="$2"
    local set_as_main=""

    # Parse optional flags
    shift 2
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --set-as-main)
                set_as_main="yes"
                shift 1
                ;;
            *)
                log "Error: Unknown argument '$1'."
                usage
                ;;
        esac
    done

    init_logging
    log "Starting update for VERSION.json with version=$version, stage=$stage"

    navigate_to_project_root
    check_jq_installed
    validate_inputs "$version" "$stage"
    local old_version
    old_version=$(jq -r '.version' VERSION.json)
    update_version_file "$version" "$stage"
    if [[ "$set_as_main" == "yes" ]] && [[ "$old_version" != "$version" ]]; then
        update_changelog_prior_versions "$old_version"
    fi

    log "Update complete."
}

main "$@"
