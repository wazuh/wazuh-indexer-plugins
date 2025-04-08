#!/bin/bash

# Constants and Configuration
ENDPOINT="_plugins/_content_manager/updater"
USERNAME="admin"
PASSWORD="admin"
IP="127.0.0.1"
PORT="9200"

# Default number of documents to index
from_offset=0
to_offset=999
log_dir="tmp/logs"
log_file="$log_dir/populate-cve-index.log"

# Function to check if URL is up
function wait_for_cluster() {
    local max_retries=12
    local sleep_interval=5 # seconds
    local url="http://$IP:$PORT/_cluster/health"

    for ((i = 1; i <= max_retries; i++)); do
        response=$(curl -s -o /dev/null -w "%{http_code}" -u $USERNAME:$PASSWORD $url)
        if [[ $response -eq 200 ]]; then
            echo "Cluster is up and running."
            return 0
        else
            echo "Cluster not available yet. Waiting..."
            sleep $sleep_interval
        fi
    done

    echo "Failed to connect to the cluster after $max_retries retries."
    return 1
}

# Index initial offsets
function load_initial_offsets() {
    url="http://$IP:$PORT/$ENDPOINT?from_offset=${from_offset}&to_offset=${to_offset}"
    response=$(curl -s -o /dev/null -w "%{http_code}" -u $USERNAME:$PASSWORD -H 'Content-Type: application/json'  -X GET "$url")
    if [[ $response -ne 201 ]]; then
        echo "Error: $response"
    fi
}

function parse_args() {
    while getopts ":f:t:o:h" opt; do
        case ${opt} in
        h)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  -f <from_offset>  (Optional) Starting offset for the range. Default: 0"
            echo "  -t <to_offset>    (Optional) Ending offset for the range. Default: 999"
            echo "  -o <log_output>   (Optional) Directory to store the output log. Default: 'tmp/logs/'"
            echo "  -h                (Optional) Display this help message"
            echo "Example: $0 -n 100"
            echo
            exit 0
            ;;
        f)
            from_offset=$OPTARG
            ;;
        t)
            to_offset=$OPTARG
            ;;
        o)
            log_dir=$OPTARG
            log_file="$log_dir/populate-cve-index.log"
            ;;
        \?)
            echo "Invalid option: $OPTARG" 1>&2
            exit 1
            ;;
        esac
    done
}

# Main function
function populate_index() {

    echo "Waiting for the cluster to be up and running..."
    if ! wait_for_cluster; then
        echo "Cluster did not start in time. Exiting."
        exit 1
    fi

    echo "Starting initial offset supplying..."
    echo "Using from_offset: $from_offset"
    echo "Using to_offset: $to_offset"
    echo "Using log_dir: $log_dir"
    echo "Using log_file: $log_file"
    load_initial_offsets
    echo "Data generation completed."
}

parse_args "$@"

if [[ ! -d "$log_dir" ]]; then
    mkdir -p "$log_dir"
fi

# Run the populate_index function in the background and redirect output to log file
(populate_index) >"$log_file" 2>&1 &
