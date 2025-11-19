#!/bin/bash

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGES_DIR="$SCRIPT_DIR/images"
CERTS_DIR="$IMAGES_DIR/nginx/certs"
ENABLE_SSL=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --enable-ssl)
            ENABLE_SSL=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--enable-ssl]"
            exit 1
            ;;
    esac
done

if [ "$ENABLE_SSL" = true ]; then
    echo -e "${BLUE}Setting up SSL environment for Imposter...${NC}"

    # Create certs directory if it doesn't exist
    echo -e "${GREEN}Creating certificates directory...${NC}"
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

        echo -e "${GREEN}Certificates generated successfully in $CERTS_DIR${NC}"
    else
        echo -e "${GREEN}Using existing certificates${NC}"
    fi
    export COMPOSE_FILE="docker-compose.yml:docker-compose.ssl.yml"  # Relative paths
else
    echo -e "${BLUE}Starting Imposter with HTTP...${NC}"
    export COMPOSE_FILE="docker-compose.yml"
fi

# Change directory to images folder
cd "$IMAGES_DIR"

# Stop any running containers
echo -e "${GREEN}Stopping existing containers...${NC}"
docker-compose down 2>/dev/null || true

# Start the environment
echo -e "${GREEN}Starting Docker Compose environment...${NC}"
docker-compose up -d

# Wait for services to be ready
echo -e "${BLUE}Waiting for services to start...${NC}"
sleep 5

# Test the endpoint
echo -e "${GREEN}Testing endpoint...${NC}"
if [ "$ENABLE_SSL" = true ]; then
    if curl -k -s -o /dev/null -w "%{http_code}" https://localhost:8443/api/v1/instances/me | grep -q "200\|401"; then
        echo -e "${GREEN}✓ Environment is up and running!${NC}"
        echo -e "${BLUE}Access your mock at: https://localhost:8443${NC}"
    else
        echo -e "${BLUE}Environment started. Verify manually at: https://localhost:8443${NC}"
    fi
else
    if curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/v1/instances/me | grep -q "200\|401"; then
        echo -e "${GREEN}✓ Environment is up and running!${NC}"
        echo -e "${BLUE}Access your mock at: http://localhost:8080${NC}"
    else
        echo -e "${BLUE}Environment started. Verify manually at: http://localhost:8080${NC}"
    fi
fi

echo -e "${GREEN}Done!${NC}"
