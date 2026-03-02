# Imposter Mock Server

This directory contains the configuration for an Imposter mock server.

## Prerequisites

- Docker installed on your machine
- Ports 8443 available

## Directory Structure

```
imposter/
├── imposter.sh                         # Helper script to start/stop/remove the server
├── README.md                           # This file
├── imposter-config.yml                 # Main Imposter configuration
├── openapi.yml                         # OpenAPI specification
├── images/                             # Docker Compose configurations
│   ├── compose.yml                     # Docker Compose file
│   └── nginx/                          # nginx reverse proxy for SSL
│       └── nginx.conf                  # nginx SSL configuration
└── scripts/                            # Groovy response scripts
    ├── tokenResponse.groovy            # Token request logic
    ├── tokenExchangeResponse.groovy    # Token exchange logic
    ├── instanceMeResponse.groovy       # Instance me logic
    └── catalogResponse.groovy          # Catalog endpoint logic
```

## Quick Start

### 1. Start the Server (Recommended)

From the `imposter/` directory, run:
```bash
./imposter.sh up
```

The server will start on `https://localhost:8443`.

> [!NOTE]
> This environment automatically:
> - Generates self-signed certificates for localhost (if not already present)
> - Starts nginx as a reverse proxy with SSL termination
> - Proxies requests to the Imposter container on port 8443

### 2. Verify the Server is Running

```bash
curl -k https://localhost:8443/system/status
```

### 3. Managing the Server

**Stop the server (without removing containers):**
```bash
./imposter.sh stop
```

**Stop and remove the server:**
```bash
./imposter.sh down
```

## Available Endpoints

> [!NOTE]
> All endpoints are served via HTTPS on `https://localhost:8443`. Use the `-k` flag with curl commands to bypass SSL certificate verification (since we use self-signed certificates).

### 1. Token Request (CTI Authentication)

Request an CTI access token:

```bash
curl -k -X POST https://localhost:8443/api/v1/instances/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "client_id=a17c21ed" \
  -d "device_code=NGU5OWFiNjQ5YmQwNGY3YTdmZTEyNzQ3YzQ1YSA"
```

Note that as it follows the real implementation, it returns the "pending" state a few times before returning the access token.

**Expected Response (200 OK):**
```json
{
  "access_token": "AYjcyMzY3ZDhiNmJkNTY",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

> [!TIP]
> Use different `device_code` values to test different authentication flows:
>
> | `device_code`      | Behavior                                                                                     |
> |--------------------|----------------------------------------------------------------------------------------------|
> | `` (default)       | Returns `authorization_pending` for the first 4 requests, then grants the token.             |
> | `pending_rejected` | Returns `authorization_pending` for the first 4 requests, then returns `access_denied`       |
> | `pending`          | Always returns `authorization_pending` (simulates a user who hasn't completed authorization) |
> | `expired`          | Always returns `expired_token` error                                                         |
> | `granted`          | Immediately returns an access token without pending state                                    |

### 2. Token Exchange (Get Signed URL)

Exchange an access token for a signed URL:

```bash
curl -k -X POST https://localhost:8443/api/v1/instances/token/exchange \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Bearer AYjcyMzY3ZDhiNmJkNTY" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "requested_token_type=urn:wazuh:params:oauth:token-type:signed_url" \
  -d "resource=https://localhost:8443/api/v1/catalog/contexts/misp/consumer/virustotal/changes"
```

**Expected Response (200 OK):**
```json
{
  "issued_token_type": "urn:wazuh:params:oauth:token-type:signed_url",
  "access_token": "https://localhost:8443/api/v1/catalog/contexts/misp/consumers/virustotal/changes?from_offset=0&to_offset=1000&with_empties=true&verify=1761383411-kJ9b8w%2BQ7kzRmF",
  "token_type": "N_A",
  "expires_in": 3600
}
```

### 3. Instance Me (Get Plan Details)

Get current instance details and plan information:

**Pro Plan Response:**
```bash
curl -k -X GET https://localhost:8443/api/v1/instances/me \
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
            "resource": "https://localhost:8443/api/v1/catalog/plans/pro/contexts/vulnerabilities/consumer/realtime"
          },
          {
            "type": "catalog:consumer:iocs",
            "identifier": "bad-guy-ips-pro",
            "name": "Bad Guy IPs",
            "description": "Dolor sit amet…",
            "resource": "https://localhost:8443/api/v1/catalog/plans/pro/contexts/bad-guy-ips/consumer/realtime"
          }
        ]
      }
    ]
  }
}
```

**Cloud Plan Response:**
```bash
curl -k -X GET https://localhost:8443/api/v1/instances/me \
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
            "resource": "https://localhost:8443/api/v1/catalog/plans/pro/contexts/vulnerabilities/consumer/realtime"
          },
          {
            "identifier": "bad-guy-ips-pro",
            "type": "catalog:consumer:iocs",
            "name": "Bad Guy IPs",
            "description": "Dolor sit amet…",
            "resource": "https://localhost:8443/api/v1/catalog/plans/pro/contexts/bad-guy-ips/consumer/realtime"
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
curl -k -X GET "https://localhost:8443/api/v1/catalog/contexts/misp/consumers/virustotal/changes?from_offset=0&to_offset=1000&with_empties=true&verify=1761383411-kJ9b8w%2BQ7kzRmF"
```

**Expected Response (200 OK):**
```json
{
  "data": [
    {
      "type": "create",
      "context": "misp",
      "resource": "indicator/12345",
      "offset": 42,
      "version": 1,
      "payload": {
        "type": "ip-address",
        "value": "192.168.1.100",
        "threat_level": "high",
        "timestamp": "2025-11-17T10:30:00Z"
      }
    },
    {
      "type": "update",
      "context": "misp",
      "resource": "indicator/12345",
      "offset": 43,
      "version": 2,
      "operations": [
        {
          "op": "replace",
          "path": "/threat_level",
          "value": "critical"
        }
      ]
    },
    {
      "type": "delete",
      "context": "misp",
      "resource": "indicator/12345",
      "offset": 44,
      "version": 3
    }
  ]
}
```

## Testing Different Scenarios

### Authorization Pending

```bash
curl -k -X POST https://localhost:8443/api/v1/instances/token \
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
curl -k -X POST https://localhost:8443/api/v1/instances/token/exchange \
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
curl -k -X GET https://localhost:8443/api/v1/instances/me \
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

To stop the server, use the helper script:

```bash
./imposter.sh stop    # Stop containers without removing them
./imposter.sh down    # Stop and remove containers
```

## Customization

To modify the mock responses:

1. Edit the OpenAPI specifications
2. Update examples or add new response scenarios
3. Restart the Docker container

## Troubleshooting

**Port 8443 already in use:**

Check what's using the port and stop it:
```bash
lsof -i :8443
# Or change the port in images/compose.yml under nginx ports section
```

**SSL Certificate Issues:**

If you need to regenerate certificates:
```bash
rm -rf images/nginx/certs/*
./imposter.sh up  # Will regenerate certificates automatically
```

**Containers not starting:**

Check the logs:
```bash
cd images/
docker compose logs
```

## Resources

- [Imposter Documentation](https://docs.imposter.sh/)
- [OpenAPI Specification](https://swagger.io/specification/)
