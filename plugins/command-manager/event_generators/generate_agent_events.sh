#!/bin/bash

# Constants and Configuration
INDEX_NAME=".agents"
USERNAME="admin"
PASSWORD="admin"
IP="127.0.0.1"
PORT="9200"

# Default number of events to generate
number=0

# Function to check if URL is up
function wait_for_cluster() {
    local max_retries=12
    local sleep_interval=5  # seconds
    local url="http://$IP:$PORT/_cluster/health"

    for i in $(seq 1 $max_retries); do
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

# Function to generate random date
function generate_random_date() {
    local start_date
    local end_date
    local random_date

    start_date=$(date -u +%s)
    end_date=$((start_date - 864000))
    random_date=$((start_date - RANDOM % (start_date - end_date)))

    date -u -r "$random_date" '+%Y-%m-%dT%H:%M:%S.%3NZ'
}

# Function to generate random groups
function generate_random_groups() {
    local groups=()
    for i in $(seq 1 $((RANDOM % 5 + 1))); do
        groups+=("group00$((RANDOM % 6))")
    done
    printf '%s\n' "$(printf '%s,' "${groups[@]}")"
}

# Function to generate random agent
function generate_random_agent() {
    local agent
    agent=$(
        cat <<EOF
{
  "id": "agent$((RANDOM % 100))",
  "name": "Agent$((RANDOM % 100))",
  "type": "$(shuf -e windows linux macos -n 1)",
  "version": "v$((RANDOM % 10))-stable",
  "status": "$(shuf -e active inactive -n 1)",
  "last_login": "$(generate_random_date)",
  "groups": ["$(generate_random_groups | sed 's/,$//')"],
  "key": "key$((RANDOM % 1000))",
  "host": $(generate_random_host)
}
EOF
    )
    echo "$agent"
}

# Function to generate random host
function generate_random_host() {
    local family
    family=$(shuf -e debian ubuntu macos ios android RHEL -n 1)
    local version
    version="$((RANDOM % 100)).$((RANDOM % 100))"
    local host
    host=$(
        cat <<EOF
{
  "architecture": "$(shuf -e x86_64 arm64 -n 1)",
  "boot": {"id": "boot$((RANDOM % 10000))"},
  "cpu": {"usage": $(echo "scale=2; $RANDOM % 100" | bc)},
  "disk": {"read": {"bytes": $((RANDOM % 1000001))}, "write": {"bytes": $((RANDOM % 1000001))}},
  "domain": "domain$((RANDOM % 1000))",
  "geo": {
    "city_name": "$(shuf -e 'San Francisco' 'New York' Berlin Tokyo -n 1)",
    "continent_code": "$(shuf -e NA EU AS -n 1)",
    "continent_name": "$(shuf -e 'North America' Europe Asia -n 1)",
    "country_iso_code": "$(shuf -e US DE JP -n 1)",
    "country_name": "$(shuf -e 'United States' Germany Japan -n 1)",
    "location": {"lat": $(echo "scale=6; $RANDOM % 180 - 90" | bc), "lon": $(echo "scale=6; $RANDOM % 360 - 180" | bc)},
    "name": "geo$((RANDOM % 1000))",
    "postal_code": "$((10000 + RANDOM % 90000))",
    "region_iso_code": "region$((RANDOM % 1000))",
    "region_name": "Region $((RANDOM % 1000))",
    "timezone": "$(shuf -e PST EST CET JST -n 1)"
  },
  "hostname": "host$((RANDOM % 10000))",
  "id": "hostid$((RANDOM % 10000))",
  "ip": "$((RANDOM % 256)).$((RANDOM % 256)).$((RANDOM % 256)).$((RANDOM % 256))",
  "mac": "$(printf '%02x:%02x:%02x:%02x:%02x:%02x' $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)))",
  "name": "hostname$((RANDOM % 10000))",
  "network": {"egress": {"bytes": $((RANDOM % 1000001)), "packets": $((RANDOM % 1000001))}, "ingress": {"bytes": $((RANDOM % 1000001)), "packets": $((RANDOM % 1000001))}},
  "os": {"family": "$family", "full": "$family $version", "kernel": "kernel$((RANDOM % 1000))", "name": "$family", "platform": "$(shuf -e linux windows macos -n 1)", "type": "$family", "version": "$version"},
  "pid_ns_ino": "$((1000000 + RANDOM % 9000000))",
  "risk": {"calculated_level": "$(shuf -e low medium high -n 1)", "calculated_score": $(echo "scale=2; $RANDOM % 100" | bc), "calculated_score_norm": $(echo "scale=2; $RANDOM % 100 / 100" | bc), "static_level": "$(shuf -e low medium high -n 1)", "static_score": $(echo "scale=2; $RANDOM % 100" | bc), "static_score_norm": $(echo "scale=2; $RANDOM % 100 / 100" | bc)},
  "uptime": $((RANDOM % 1000001))
}
EOF
    )
    echo "$host"
}

# Function to inject events
function inject_events() {
    local data=$1
    url="http://$IP:$PORT/$INDEX_NAME/_doc"
    response=$(curl -s -o /dev/null -w "%{http_code}" -u $USERNAME:$PASSWORD -H 'Content-Type: application/json' -d "$data" -X POST $url)
    if [[ $response -ne 201 ]]; then
        echo "Error: $response"
    fi
}

function parse_args() {
    while getopts ":n:h" opt; do
        case ${opt} in
        h)
            echo "Usage: $0 [-n <number>]"
            echo "Options:"
            echo "  -n <number>  Number of events to generate. If not provided, the script will prompt for the number of events to generate."
            echo "  -h           Display this help message"
            echo "Example: $0 -n 100"
            echo
            exit 0
            ;;
        n)
            number=$OPTARG
            ;;
        \?)
            echo "Invalid option: $OPTARG" 1>&2
            exit 1
            ;;
        esac
    done
}

# Main function
main() {
    parse_args "$@"
    if [[ $number -lt 1 ]]; then
        echo -n "How many events do you want to generate? "
        read -r number
        if ! [[ "$number" =~ ^[0-9]+$ ]]; then
            echo "Invalid input. Please enter a valid number."
            return
        fi
    fi

    echo "Waiting for the cluster to be up and running..."
    if ! wait_for_cluster; then
        echo "Cluster did not start in time. Exiting."
        exit 1
    fi

    echo "Generating $number events..."

    for i in $(seq 1 "$number"); do
        event_data=$(generate_random_agent)
        inject_events "$event_data"
    done

    echo "Data generation completed."
}

# Run the main function in the background and redirect output to log file
(main "$@") > generate_log.txt 2>&1 &
