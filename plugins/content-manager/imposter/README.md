# Imposter Mock Server

This directory contains the configuration for an Imposter mock server.

## Prerequisites

- Docker installed on your machine
- Port 8080 available

## Directory Structure

```
imposter/
├── README.md
├── imposter-config.yml          # Main Imposter configuration
├── test-scenarios.sh            # Automated test script
├── definitions/
│   └── cti-auth.yml            # OpenAPI specification
└── scripts/
    ├── token-response.groovy           # Token request logic
    ├── token-exchange-response.groovy  # Token exchange logic
    └── catalog-response.groovy         # Catalog endpoint logic
```

## Quick Start

### 1. Start the Mock Server

From the `imposter/` directory, run:

```bash
docker run -it --rm -p 8080:8080 \
  -v $(pwd):/opt/imposter/config \
  -v $(pwd)/definitions:/opt/imposter/definitions \
  outofcoffee/imposter
```

The server will start on `http://localhost:8080`.

### 2. Verify the Server is Running

```bash
curl http://localhost:8080/_status
```

## Available Endpoints

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
  -d "resource=https://cti.wazuh.com/api/v1/catalog/contexts/misp/consumer/virustotal/changes"
```

**Expected Response (200 OK):**
```json
{
  "issued_token_type": "urn:wazuh:params:oauth:token-type:signed_url",
  "access_token": "https://cti.wazuh.com/api/v1/catalog/contexts/misp/consumers/virustotal/changes?from_offset=0&to_offset=1000&with_empties=true&verify=1761383411-kJ9b8w%2BQ7kzRmF...",
  "token_type": "N_A",
  "expires_in": 3600
}
```

### 3. Catalog Download (Consumer Changes)

Download consumer changes using a signed URL:

```bash
curl -X GET "http://localhost:8080/api/v1/catalog/contexts/misp/consumers/virustotal/changes?from_offset=0&to_offset=1000&with_empties=true&verify=1761383411-kJ9b8w%2BQ7kzRmF..."
```

**Expected Response (200 OK):**
```json
{
  "content_type": "application/zip",
  "signature": "kJ9b8w+Q7kzRmF...",
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
