#!/bin/bash

set -euo pipefail
shopt -s nullglob

# === Default Config ===
BASE_DIR="ecs"
GENERATED_DATA_FILE="generatedData.json"
SLEEP_TIME="${SLEEP_TIME:-6}"
USERNAME="${USERNAME:-admin}"
PASSWORD="${PASSWORD:-admin}"
MAX_RETRIES=5
IP="127.0.0.1"
PROTOCOL="http"
PORT="${PORT:-9200}"
NUMBER_OF_EVENTS="100"

# === Logging Helpers ===
log()    { echo -e "\n\033[1;34m[INFO]\033[0m $*"; }
warn()   { echo -e "\n\033[1;33m[WARN]\033[0m $*"; }
error()  { echo -e "\n\033[1;31m[ERROR]\033[0m $*" >&2; }

# === Usage ===
usage() {
    echo "Usage: $0 [--ip <ip>] [--protocol <http|https>] [--amount <n>]"
    echo "Defaults: --ip 127.0.0.1, --port 9200, --protocol http --amount 100"
    exit 1
}

# === Parse Optional Arguments ===
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --ip)
                IP="$2"
                shift 2
                ;;
            --port)
                PORT="$2"
                shift 2
                ;;
            --protocol)
                PROTOCOL="$2"
                shift 2
                ;;
            --amount)
                if [[ "$2" =~ ^[0-9]+$ ]]; then
                    NUMBER_OF_EVENTS="$2"
                    shift 2
                else
                    error "Invalid value for --amount: $2. Must be a positive integer."
                    usage
                fi
                ;;
            -h|--help)
                usage
                ;;
            *)
                error "Unknown argument: $1"
                usage
                ;;
        esac
    done
}

# === Ensure Script Runs from Project Root ===
navigate_to_project_root() {
    local repo_root_marker=".github"
    local script_path
    script_path=$(dirname "$(realpath "$0")")

    while [[ "$script_path" != "/" ]] && [[ ! -d "$script_path/$repo_root_marker" ]]; do
        script_path=$(dirname "$script_path")
    done

    if [[ "$script_path" == "/" ]]; then
        error "Unable to find the repository root (missing $repo_root_marker)"
        exit 1
    fi

    cd "$script_path" || exit
    log "Changed directory to project root: $script_path"
}

# === Ensure Required Tools Are Installed ===
check_dependencies() {
    for cmd in python3 curl jq; do
        command -v "$cmd" >/dev/null || {
            error "$cmd is not installed or not in PATH"
            exit 1
        }
    done

    if ! python3 -c "import requests" 2>/dev/null; then
        error "Python module 'requests' is not installed. Install it with: pip3 install requests"
        exit 1
    fi
}

# === Generate Events ===
generate_events() {
    local dir="$1"
    local index_name="$2"
    log "Generating events for index: $dir"

    python3 "$dir/event-generator/event_generator.py" --protocol "$PROTOCOL" <<EOF
$NUMBER_OF_EVENTS
y
$IP
$PORT
$index_name
$USERNAME
$PASSWORD
EOF
}

# === Wait for Indexing and Fetch Last Event ===
fetch_last_event() {
    local index_name="$1"

    log "Waiting $SLEEP_TIME seconds for indexing..."
    sleep "$SLEEP_TIME"

    log "Fetching last event from index: $index_name"

    local attempt result
    for attempt in $(seq 1 "$MAX_RETRIES"); do
        if result=$(curl -sku "$USERNAME:$PASSWORD" -s "$PROTOCOL://$IP:$PORT/${index_name}/_search" \
            -H 'Content-Type: application/json' \
            -d '{"query": {"match_all": {} }, "size":1 }'); then
            echo "$result" | jq '.hits.hits[0]._source'
            return 0
        else
            warn "Attempt $attempt failed. Retrying in 2s..."
            sleep 2
        fi
    done

    error "Failed to fetch from index $index_name after $MAX_RETRIES attempts."
}

# === Clean Up Generated Data ===
clean_generated_data() {
    if [[ -f "$GENERATED_DATA_FILE" ]]; then
        log "Removing generated data file: $GENERATED_DATA_FILE"
        rm "$GENERATED_DATA_FILE"
    fi
}

# === Main Function ===
main() {
    parse_args "$@"
    navigate_to_project_root
    check_dependencies

    local state_dirs=("$BASE_DIR"/states-*)
    if [[ ${#state_dirs[@]} -eq 0 ]]; then
        error "No matching directories found in '$BASE_DIR' (e.g., states-*)."
        exit 1
    fi

    for dir in "${state_dirs[@]}"; do
        [[ -d "$dir" ]] || continue
        local index_name
        index_name="wazuh-$(basename "$dir")"

        generate_events "$dir" "$index_name"
        fetch_last_event "$index_name"
        clean_generated_data
    done
}

main "$@"
