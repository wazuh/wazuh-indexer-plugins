#!/bin/bash

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGES_DIR="$SCRIPT_DIR/images"
CERTS_DIR="$IMAGES_DIR/nginx/certs"

usage() {
    echo -e "${BLUE}Usage: $0 {up|stop|down}${NC}"
    echo -e "${BLUE}  up   - Start the Imposter environment${NC}"
    echo -e "${BLUE}  stop - Stop the Imposter environment without removing containers${NC}"
    echo -e "${BLUE}  down - Remove the Imposter environment${NC}"
    exit 1
}

generate_certs() {
    # Create certs directory if it doesn't exist
    mkdir -p "$CERTS_DIR"

    # Generate self-signed certificates if they don't exist
    if [ ! -f "$CERTS_DIR/cert.pem" ] || [ ! -f "$CERTS_DIR/key.pem" ]; then
        echo -e "${GREEN}Generating self-signed SSL certificates for localhost...${NC}"
        openssl req -x509 -newkey rsa:4096 -nodes \
            -keyout "$CERTS_DIR/key.pem" \
            -out "$CERTS_DIR/cert.pem" \
            -days 365 \
            -subj "/C=US/ST=State/L=City/O=Wazuh/CN=localhost"

        # Set proper permissions
        chmod 644 "$CERTS_DIR/cert.pem"
        chmod 600 "$CERTS_DIR/key.pem"

        echo -e "${GREEN}Certificates generated successfully${NC}"
    else
        echo -e "${GREEN}Using existing certificates${NC}"
    fi
}

start_environment() {
    echo -e "${BLUE}Setting up SSL environment for Imposter...${NC}"

    generate_certs

    # Change directory to images folder
    cd "$IMAGES_DIR"

    # Stop any running containers
    echo -e "${GREEN}Stopping existing containers...${NC}"
    docker compose down 2>/dev/null || true

    # Start the environment
    echo -e "${GREEN}Starting Docker Compose environment...${NC}"
    docker compose up -d

    # Wait for services to be ready
    echo -e "${BLUE}Waiting for services to start...${NC}"
    sleep 5

    # Test the endpoint
    echo -e "${GREEN}Testing endpoint...${NC}"
    if curl -k -s -o /dev/null -w "%{http_code}" https://localhost:8443/api/v1/instances/me | grep -q "200\|401"; then
        echo -e "${GREEN}✓ Environment is up and running!${NC}"
        echo -e "${BLUE}Access your mock at: https://localhost:8443${NC}"
    else
        echo -e "${BLUE}Environment started. Verify manually at: https://localhost:8443${NC}"
    fi

    echo -e "${GREEN}Done!${NC}"
}

stop_environment() {
    echo -e "${GREEN}Stopping Imposter environment...${NC}"
    cd "$IMAGES_DIR"
    docker compose stop
    echo -e "${GREEN}Done!${NC}"
}

remove_environment() {
    echo -e "${GREEN}Removing Imposter environment...${NC}"
    cd "$IMAGES_DIR"
    docker compose down
    echo -e "${GREEN}Done!${NC}"
}

# Check if at least one argument is provided
if [ $# -eq 0 ]; then
    usage
fi

# Parse command line arguments
case $1 in
    up)
        start_environment
        ;;
    stop)
        stop_environment
        ;;
    down)
        remove_environment
        ;;
    *)
        echo -e "${RED}Error: Unknown command '$1'${NC}"
        usage
        ;;
esac

