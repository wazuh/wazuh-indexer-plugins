// Instance Me Response Logic
// Returns different responses based on Authorization header token

def authHeader = context.request.headers['Authorization']?.toString()

// Check if Authorization header is present
if (!authHeader || !authHeader.startsWith('Bearer ')) {
    respond()
        .withStatusCode(401)
        .withHeader("Content-Type", "application/json")
        .withContent('{"error": "unauthorized_client", "error_description": "The provided token is invalid or expired"}')
    return
}

// Extract token from Authorization header
def token = authHeader.substring(7) // Remove "Bearer " prefix

// Cloud plan scenario - token contains "cloud"
if (token.toLowerCase().contains('cloud')) {
    respond()
        .withStatusCode(200)
        .withHeader("Content-Type", "application/json")
        .withContent('''
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
''')
}
// Pro plan scenario - default for any other valid token
else {
    respond()
        .withStatusCode(200)
        .withHeader("Content-Type", "application/json")
        .withContent('''
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
''')
}

