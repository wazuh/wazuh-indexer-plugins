# Imposter Mock Server

This directory contains the configuration for an Imposter mock server.

## Prerequisites

- Docker installed on your machine
- Ports 8080 & 8443 available

## Directory Structure

```
imposter/
├── start-imposter.sh                   # Startup script for HTTP/HTTPS modes
├── README.md                           # This file
├── imposter-config.yml                 # Main Imposter configuration
├── openapi.yml                         # OpenAPI specification
├── images/                             # Docker Compose configurations
│   ├── docker-compose.yml              # Base HTTP configuration
│   ├── docker-compose.ssl.yml          # SSL/HTTPS override configuration
│   └── nginx/                          # nginx reverse proxy for SSL
│       └── nginx.conf                  # nginx SSL configuration
└── scripts/                            # Groovy response scripts
    ├── tokenResponse.groovy            # Token request logic
    ├── tokenExchangeResponse.groovy    # Token exchange logic
    ├── instanceMeResponse.groovy       # Instance me logic
    └── catalogResponse.groovy          # Catalog endpoint logic
```

## Quick Start

### Option 1: Using the Startup Script (Recommended)

#### HTTP Mode (Default)

From the `imposter/` directory, run:
```bash
./start-imposter.sh
```

The server will start on `http://localhost:8080`.

#### HTTPS Mode with SSL

For HTTPS with self-signed certificates:
```bash
./start-imposter.sh --enable-ssl
```

The server will start on `https://localhost:8443`.

> [!NOTE]
> The SSL mode will automatically:
> - Generate self-signed certificates for localhost
> - Start nginx as a reverse proxy with SSL termination
> - Proxy requests to the Imposter container

### Option 2: Using Docker Directly

From the `imposter/` directory, run:
```bash
docker run -it --rm -p 8080:8080 \
  -v $(pwd):/opt/imposter/config \
  outofcoffee/imposter
```
> [!NOTE]
> The container could be executed from any directory, but ensure the paths to the configuration and definitions are correct.

The server will start on `http://localhost:8080`.

### 2. Verify the Server is Running

**HTTP Mode:**
```bash
curl http://localhost:8080/system/status
```

**HTTPS Mode:**
```bash
curl -k https://localhost:8443/system/status
```

## Available Endpoints

> [!NOTE]
> All examples below use HTTP (`http://localhost:8080`). If running in HTTPS mode, replace with `https://localhost:8443` and add the `-k` flag to curl commands.

### 1. Token Request (CTI Authentication)

Request an CTI access token:

```bash
curl -X POST http://localhost:8080/api/v1/instances/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "client_id=a17c21ed" \
  -d "device_code=NGU5OWFiNjQ5YmQwNGY3YTdmZTEyNzQ3YzQ1YSA"
```

**Expected Response (200 OK):**
```json
{
  "access_token": "AYjcyMzY3ZDhiNmJkNTY",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### 2. Token Exchange (Get Signed URL)

Exchange an access token for a signed URL:

```bash
curl -X POST http://localhost:8080/api/v1/instances/token/exchange \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Bearer AYjcyMzY3ZDhiNmJkNTY" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "requested_token_type=urn:wazuh:params:oauth:token-type:signed_url" \
  -d "resource=https://localhost:4040/api/v1/catalog/contexts/misp/consumer/virustotal/changes"
```

**Expected Response (200 OK):**
```json
{
  "issued_token_type": "urn:wazuh:params:oauth:token-type:signed_url",
  "access_token": "https://localhost:4040/api/v1/catalog/contexts/misp/consumers/virustotal/changes?from_offset=0&to_offset=1000&with_empties=true&verify=1761383411-kJ9b8w%2BQ7kzRmF",
  "token_type": "N_A",
  "expires_in": 3600
}
```

### 3. Instance Me (Get Plan Details)

Get current instance details and plan information:

**Pro Plan Response:**
```bash
curl -X GET http://localhost:8080/api/v1/instances/me \
  -H "Authorization: Bearer pro_token" \
  -H "Content-Type: application/json"
```

**Expected Response (200 OK):**
```json
{
  "data": {
    "organization": {
      "avatar": "https://acme.sl/avatar.png",
      "name": "ACME S.L."
    },
    "plans": [
      {
        "name": "Pro Plan Deluxe",
        "description": "Lorem ipsum…",
        "products": [
          {
            "type": "catalog:consumer:vulnerabilities",
            "identifier": "vulnerabilities-pro",
            "name": "Vulnerabilities Pro",
            "description": "Vulnerabilities updated as soon as they are added to the catalog",
            "resource": "https://localhost:8080/api/v1/catalog/plans/pro/contexts/vulnerabilities/consumer/realtime"
          },
          {
            "type": "catalog:consumer:iocs",
            "identifier": "bad-guy-ips-pro",
            "name": "Bad Guy IPs",
            "description": "Dolor sit amet…",
            "resource": "https://localhost:8080/api/v1/catalog/plans/pro/contexts/bad-guy-ips/consumer/realtime"
          }
        ]
      }
    ]
  }
}
```

**Cloud Plan Response:**
```bash
curl -X GET http://localhost:8080/api/v1/instances/me \
  -H "Authorization: Bearer cloud_token" \
  -H "Content-Type: application/json"
```

**Expected Response (200 OK):**
```json
{
  "data": {
    "organization": {
      "avatar": "https://acme.sl/avatar.png",
      "name": "ACME S.L."
    },
    "plans": [
      {
        "name": "Wazuh Cloud",
        "description": "Managed instances in AWS by Wazuh's professional staf that…",
        "products": [
          {
            "identifier": "assistance-24h",
            "type": "cloud:assistance:wazuh",
            "name": "Technical assistance 24h",
            "email": "cloud@wazuh.com",
            "phone": "+34 123 456 789"
          },
          {
            "identifier": "vulnerabilities-pro",
            "type": "catalog:consumer:vulnerabilities",
            "name": "Vulnerabilities Pro",
            "description": "Vulnerabilities updated as soon as they are added to the catalog",
            "resource": "https://localhost:8080/api/v1/catalog/plans/pro/contexts/vulnerabilities/consumer/realtime"
          },
          {
            "identifier": "bad-guy-ips-pro",
            "type": "catalog:consumer:iocs",
            "name": "Bad Guy IPs",
            "description": "Dolor sit amet…",
            "resource": "https://localhost:8080/api/v1/catalog/plans/pro/contexts/bad-guy-ips/consumer/realtime"
          }
        ]
      }
    ]
  }
}
```

### 4. Catalog Download (Use Token)

Download catalog using a signed URL:

```bash
curl -X GET "http://localhost:8080/api/v1/catalog/contexts/misp/consumers/virustotal/changes?from_offset=0&to_offset=1000&with_empties=true&verify=1761383411-kJ9b8w%2BQ7kzRmF"
```

**Expected Response (200 OK):**
```json
{
  "content_type": "application/zip",
  "signature": "kJ9b8w+Q7kzRmF",
  "url": "https://cdn.wazuh.com/misp/virustotal/changes_0_1000.zip"
}
```

## Testing Different Scenarios

### Authorization Pending

```bash
curl -X POST http://localhost:8080/api/v1/instances/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "client_id=test_client" \
  -d "device_code=pending_code"
```

**Expected Response (400 Bad Request):**
```json
{
  "error": "authorization_pending",
  "error_description": "The authorization request is still pending"
}
```

### Invalid Token Exchange

```bash
curl -X POST http://localhost:8080/api/v1/instances/token/exchange \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Bearer invalid_token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
```

**Expected Response (401 Unauthorized):**
```json
{
  "error": "invalid_token",
  "error_description": "The access token is invalid or expired"
}
```

### Missing Authorization Header (Instance Me)

```bash
curl -X GET http://localhost:8080/api/v1/instances/me \
  -H "Content-Type: application/json"
```

**Expected Response (401 Unauthorized):**
```json
{
  "error": "unauthorized_client",
  "error_description": "The provided token is invalid or expired"
}
```

## Stopping the Server

Press `Ctrl+C` in the terminal where the Docker container is running, or run:

```bash
docker stop $(docker ps -q --filter ancestor=outofcoffee/imposter)
```

## Customization

To modify the mock responses:

1. Edit the OpenAPI specifications
2. Update examples or add new response scenarios
3. Restart the Docker container

## Troubleshooting

**Port 8080 already in use:**
```bash
# Use a different port
docker run -it --rm -p 9090:8080 \
  -v $(pwd):/opt/imposter/config \
  -v $(pwd)/definitions:/opt/imposter/definitions \
  outofcoffee/imposter
```

**Cannot find OpenAPI spec:**
- Ensure both `config` and `definitions` directories are mounted
- Verify the relative path in `imposter-config.yml` matches your structure

## Resources

- [Imposter Documentation](https://docs.imposter.sh/)
- [OpenAPI Specification](https://swagger.io/specification/)
