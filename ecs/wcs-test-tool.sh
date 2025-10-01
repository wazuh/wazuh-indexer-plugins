#!/bin/bash

# WCS Test Tool - Wazuh Common Schema Test Tool
# Tests index templates by indexing sample events from intelligence-data repository

set -uo pipefail

# Default values
INDEXER_URL=""
USERNAME=""
PASSWORD=""
INTELLIGENCE_DATA_PATH=""
LOG_FILE="wcs-test-tool.log"
INTEGRATIONS_MAP=""
CURL_OPTS="-s"
STRICT_MAPPING=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Usage function
usage() {
    echo "Usage: $0 -p <intelligence-data-path> -i <integrations-map> -u <indexer-url> [-c <username:password>] [-l <log-file>] [-s]"
    echo
    echo "Parameters:"
    echo "  -p, --path            Path to the intelligence-data repository"
    echo "  -i, --integrations    Comma-separated list of integration:index pairs (e.g., 'azure:wazuh-events-azure,aws:wazuh-events-aws')"
    echo "  -u, --url             URL of the Indexer instance (e.g., https://localhost:9200)"
    echo "  -c, --credentials     Username and password separated by colon (optional)"
    echo "  -l, --log-file        Log file path (default: wcs-test-tool.log)"
    echo "  -s, --strict          Enable strict mapping mode (validates all document fields against index template)"
    echo "  -h, --help            Show this help message"
    echo
    echo "Example:"
    echo "  $0 -p /path/to/intelligence-data -i 'amazon-security-lake:wazuh-events-amazon-security-lake' -u https://localhost:9200 -c admin:admin -s"
    exit 1
}

# Logging functions
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

log_info() {
    log "INFO" "$@"
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    log "SUCCESS" "$@"
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warning() {
    log "WARNING" "$@"
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

log_error() {
    log "ERROR" "$@"
    echo -e "${RED}[ERROR]${NC} $*"
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -p|--path)
                INTELLIGENCE_DATA_PATH="$2"
                shift 2
                ;;
            -i|--integrations)
                INTEGRATIONS_MAP="$2"
                shift 2
                ;;
            -u|--url)
                INDEXER_URL="$2"
                shift 2
                ;;
            -c|--credentials)
                local creds="$2"
                USERNAME="${creds%%:*}"
                PASSWORD="${creds#*:}"
                shift 2
                ;;
            -l|--log-file)
                LOG_FILE="$2"
                shift 2
                ;;
            -s|--strict)
                STRICT_MAPPING=true
                shift
                ;;
            -h|--help)
                usage
                ;;
            *)
                echo "Unknown option: $1"
                usage
                ;;
        esac
    done

    # Validate required parameters
    if [[ -z "$INTELLIGENCE_DATA_PATH" ]]; then
        log_error "Intelligence data path is required"
        usage
    fi

    if [[ -z "$INTEGRATIONS_MAP" ]]; then
        log_error "Integrations map is required"
        usage
    fi

    if [[ -z "$INDEXER_URL" ]]; then
        log_error "Indexer URL is required"
        usage
    fi

    # Validate paths
    if [[ ! -d "$INTELLIGENCE_DATA_PATH" ]]; then
        log_error "Intelligence data path does not exist: $INTELLIGENCE_DATA_PATH"
        exit 1
    fi

    if [[ ! -d "$INTELLIGENCE_DATA_PATH/ruleset/integrations" ]]; then
        log_error "Invalid intelligence-data repository structure. Expected: $INTELLIGENCE_DATA_PATH/ruleset/integrations"
        exit 1
    fi

    # Set up curl authentication if credentials provided
    if [[ -n "$USERNAME" && -n "$PASSWORD" ]]; then
        CURL_OPTS="$CURL_OPTS -u $USERNAME:$PASSWORD"
    fi

    # Add timeout and other robustness options to curl
    CURL_OPTS="$CURL_OPTS --connect-timeout 10 --max-time 30 -k"

    # Remove trailing slash from URL
    INDEXER_URL="${INDEXER_URL%/}"
}

# Check if indexer is accessible
check_indexer() {
    log_info "Checking connection to indexer: $INDEXER_URL"
    
    local response
    local http_code
    
    response=$(curl $CURL_OPTS -w "\n%{http_code}" "$INDEXER_URL" 2>&1)
    local curl_exit_code=$?
    
    if [[ $curl_exit_code -ne 0 ]]; then
        log_error "Failed to connect to indexer. Curl exit code: $curl_exit_code"
        log_error "Response: $response"
        exit 1
    fi
    
    http_code=$(echo "$response" | tail -n1)
    
    log_info "Connection test HTTP code: $http_code"
    
    if [[ "$http_code" != "200" ]]; then
        log_error "Failed to connect to indexer. HTTP code: $http_code"
        log_error "Response: $(echo "$response" | head -n -1)"
        exit 1
    fi
    
    log_success "Successfully connected to indexer"
    
    # Test if we can access the cluster info
    log_info "Testing cluster access..."
    local cluster_response
    cluster_response=$(curl $CURL_OPTS "$INDEXER_URL/_cluster/health" 2>/dev/null || echo "{}")
    log_info "Cluster health response: $cluster_response"
}

# Find all _expected.json files for an integration
find_test_files() {
    local integration="$1"
    local integration_path="$INTELLIGENCE_DATA_PATH/ruleset/integrations/$integration"
    
    if [[ ! -d "$integration_path" ]]; then
        log_warning "Integration directory not found: $integration_path"
        return 1
    fi
    
    if [[ ! -d "$integration_path/test" ]]; then
        log_warning "Test directory not found for integration: $integration"
        return 1
    fi
    
    # Find all _expected.json files recursively in the test directory
    find "$integration_path/test" -name "*_expected.json" -type f 2>/dev/null || true
}

# Count JSON documents in a file
count_documents() {
    local file="$1"
    
    if [[ ! -f "$file" ]]; then
        echo "0"
        return
    fi
    
    # Use jq to count array elements, fallback to basic counting if jq fails
    local count
    count=$(jq '. | length' "$file" 2>/dev/null || echo "0")
    echo "$count"
}

# Update index mapping to strict mode
update_mapping_to_strict() {
    local index_name="$1"
    
    log_info "Updating mapping to strict mode for index: $index_name"
    
    local response
    local http_code
    local mapping_json='{"dynamic": "strict"}'
    
    response=$(curl $CURL_OPTS -w "\n%{http_code}" -X PUT \
        -H "Content-Type: application/json" \
        -d "$mapping_json" \
        "$INDEXER_URL/$index_name/_mapping" 2>&1)
    
    local curl_exit_code=$?
    
    if [[ $curl_exit_code -ne 0 ]]; then
        log_error "Failed to update mapping. Curl exit code: $curl_exit_code"
        log_error "Response: $response"
        return 1
    fi
    
    http_code=$(echo "$response" | tail -n1)
    local response_body=$(echo "$response" | head -n -1)
    
    log_info "Mapping update HTTP response code: $http_code"
    
    if [[ "$http_code" =~ ^20[0-9]$ ]]; then
        log_success "Successfully updated mapping to strict mode"
        return 0
    else
        log_error "Failed to update mapping. HTTP code: $http_code"
        log_error "Response body: $response_body"
        return 1
    fi
}

# Restore index mapping to false mode
restore_mapping_to_false() {
    local index_name="$1"
    
    log_info "Restoring mapping to false mode for index: $index_name"
    
    local response
    local http_code
    local mapping_json='{"dynamic": "false"}'
    
    response=$(curl $CURL_OPTS -w "\n%{http_code}" -X PUT \
        -H "Content-Type: application/json" \
        -d "$mapping_json" \
        "$INDEXER_URL/$index_name/_mapping" 2>&1)
    
    local curl_exit_code=$?
    
    if [[ $curl_exit_code -ne 0 ]]; then
        log_error "Failed to restore mapping. Curl exit code: $curl_exit_code"
        log_error "Response: $response"
        return 1
    fi
    
    http_code=$(echo "$response" | tail -n1)
    local response_body=$(echo "$response" | head -n -1)
    
    log_info "Mapping restore HTTP response code: $http_code"
    
    if [[ "$http_code" =~ ^20[0-9]$ ]]; then
        log_success "Successfully restored mapping to false mode"
        return 0
    else
        log_error "Failed to restore mapping. HTTP code: $http_code"
        log_error "Response body: $response_body"
        return 1
    fi
}

# Index a single document
index_document() {
    local index_name="$1"
    local document="$2"
    local doc_id="$3"
    
    local response
    local http_code
    local response_body
    
    # Index the document with automatic ID generation if doc_id is empty
    local url="$INDEXER_URL/$index_name/_doc"
    if [[ -n "$doc_id" ]]; then
        url="$url/$doc_id"
    fi
    
    log_info "Indexing document to: $url"
    
    # Make the curl request with better error handling
    response=$(curl $CURL_OPTS -w "\n%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -d "$document" \
        "$url" 2>&1)
    
    local curl_exit_code=$?
    
    if [[ $curl_exit_code -ne 0 ]]; then
        log_error "Curl command failed with exit code: $curl_exit_code"
        log_error "Response: $response"
        return 1
    fi
    
    http_code=$(echo "$response" | tail -n1)
    response_body=$(echo "$response" | head -n -1)
    
    log_info "HTTP response code: $http_code"
    
    if [[ "$http_code" =~ ^20[0-9]$ ]]; then
        log_info "Document indexed successfully"
        return 0
    else
        log_error "Failed to index document. HTTP code: $http_code"
        log_error "URL: $url"
        log_error "Response body: $response_body"
        log_error "Document (first 200 chars): $(echo "$document" | cut -c1-200)..."
        return 1
    fi
}

# Process a single test file
process_test_file() {
    local file="$1"
    local index_name="$2"
    
    log_info "Processing file: $file"
    log_info "Target index: $index_name"
    
    local total_docs
    local indexed_docs=0
    local failed_docs=0
    
    total_docs=$(count_documents "$file")
    
    if [[ "$total_docs" -eq 0 ]]; then
        log_warning "No documents found in file: $file"
        return
    fi
    
    log_info "Found $total_docs documents in file"
    
    # Process each document in the array
    for ((i=0; i<total_docs; i++)); do
        log_info "Processing document $((i+1))/$total_docs"
        
        local document
        document=$(jq -c ".[$i]" "$file" 2>/dev/null)
        
        if [[ -z "$document" || "$document" == "null" ]]; then
            log_warning "Skipping empty or invalid document at index $i"
            ((failed_docs++))
            continue
        fi
        
        log_info "Document size: $(echo "$document" | wc -c) characters"
        
        # Try to index the document
        if index_document "$index_name" "$document" ""; then
            ((indexed_docs++))
            log_success "Document $((i+1)) indexed successfully"
        else
            ((failed_docs++))
            log_error "Failed to index document $((i+1))"
        fi
        
        # Add a small delay between requests to avoid overwhelming the server
        sleep 0.1
    done
    
    log_success "File processing complete: $indexed_docs/$total_docs documents indexed successfully"
    
    if [[ "$failed_docs" -gt 0 ]]; then
        log_warning "$failed_docs documents failed to index"
    fi
    
    # Log summary for this file
    echo "$file,$total_docs,$indexed_docs,$failed_docs" >> "${LOG_FILE}.summary.csv"
}

# Process a single integration
process_integration() {
    local integration="$1"
    local index_name="$2"
    
    log_info "Processing integration: $integration -> $index_name"
    
    # Update mapping to strict mode if requested
    if [[ "$STRICT_MAPPING" == "true" ]]; then
        if ! update_mapping_to_strict "$index_name"; then
            log_warning "Failed to update mapping to strict mode, but continuing with indexing..."
        fi
    fi
    
    local test_files
    test_files=$(find_test_files "$integration")
    
    if [[ -z "$test_files" ]]; then
        log_warning "No test files found for integration: $integration"
        return
    fi
    
    local file_count
    file_count=$(echo "$test_files" | wc -l)
    log_info "Found $file_count test files for integration: $integration"
    
    # Process each test file
    while IFS= read -r file; do
        if [[ -n "$file" ]]; then
            process_test_file "$file" "$index_name"
        fi
    done <<< "$test_files"
    
    # Restore mapping to false mode if strict mode was used
    if [[ "$STRICT_MAPPING" == "true" ]]; then
        if ! restore_mapping_to_false "$index_name"; then
            log_warning "Failed to restore mapping to false mode"
        fi
    fi
    
    log_success "Integration processing complete: $integration"
}

# Main function
main() {
    echo "WCS Test Tool - Wazuh Common Schema Test Tool"
    echo "=============================================="
    echo
    
    # Initialize log file
    echo "# WCS Test Tool Log - $(date)" > "$LOG_FILE"
    echo "file,total_docs,indexed_docs,failed_docs" > "${LOG_FILE}.summary.csv"
    
    parse_args "$@"
    
    log_info "Starting WCS test tool"
    log_info "Intelligence data path: $INTELLIGENCE_DATA_PATH"
    log_info "Indexer URL: $INDEXER_URL"
    log_info "Log file: $LOG_FILE"
    log_info "Strict mapping mode: $(if [[ "$STRICT_MAPPING" == "true" ]]; then echo "enabled"; else echo "disabled"; fi)"
    
    check_indexer
    
    # Parse integrations map and process each integration
    IFS=',' read -ra INTEGRATION_PAIRS <<< "$INTEGRATIONS_MAP"
    
    local total_integrations=${#INTEGRATION_PAIRS[@]}
    local processed_integrations=0
    
    log_info "Processing $total_integrations integrations"
    
    for pair in "${INTEGRATION_PAIRS[@]}"; do
        if [[ "$pair" =~ ^([^:]+):(.+)$ ]]; then
            local integration="${BASH_REMATCH[1]}"
            local index_name="${BASH_REMATCH[2]}"
            
            process_integration "$integration" "$index_name"
            ((processed_integrations++))
        else
            log_error "Invalid integration:index pair format: $pair"
            log_error "Expected format: integration:index"
        fi
    done
    
    log_success "WCS test tool completed successfully"
    log_success "Processed $processed_integrations/$total_integrations integrations"
    log_info "Summary report available at: ${LOG_FILE}.summary.csv"
    
    # Display summary
    echo
    echo "Summary Report:"
    echo "==============="
    if [[ -f "${LOG_FILE}.summary.csv" ]]; then
        column -t -s ',' "${LOG_FILE}.summary.csv"
    fi
}

# Run main function with all arguments
main "$@"