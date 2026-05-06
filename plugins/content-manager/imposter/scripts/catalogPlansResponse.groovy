// Catalog Plans Response Logic
// Returns the list of public and non-public plans. No authentication required.

// Log the incoming user-agent for validation
def userAgent = context.request.headers['User-Agent']?.toString()
logger.info("[catalogPlans] User-Agent: ${userAgent}")

respond()
    .withStatusCode(200)
    .withHeader("Content-Type", "application/json")
    .withContent('''
{
  "plans": [
    {
      "name": "Free",
      "is_public": true,
      "features": [
        {
          "name": "public-vulnerabilities-5",
          "type": "cti:catalog:consumer:vulnerabilities",
          "description": "Free vulnerabilities feed",
          "resource": "https://localhost:8443/api/v1/catalog/contexts/t1-vulnerabilities-5/consumers/public-vulnerabilities-5"
        },
        {
          "name": "public-iocs-5",
          "type": "cti:catalog:consumer:iocs",
          "description": "Free iocs",
          "resource": "https://localhost:8443/api/v1/catalog/contexts/t1-iocs-5/consumers/public-iocs-5"
        },
        {
          "name": "public-ruleset-5",
          "type": "cti:catalog:consumer:ruleset",
          "description": "Free ruleset 5",
          "resource": "https://localhost:8443/api/v1/catalog/contexts/t1-ruleset-5/consumers/public-ruleset-5"
        }
      ]
    },
    {
      "name": "Pro Plan",
      "is_public": false,
      "features": [
        {
          "name": "t0-private-vulnerabilities",
          "type": "cti:catalog:consumer:vulnerabilities",
          "description": "Tier 0 paid vulnerabilities",
          "resource": "https://localhost:8443/api/v1/catalog/contexts/t0-vulnerabilities-5/consumers/private-vulnerabilities-5"
        },
        {
          "name": "t0-private-iocs",
          "type": "cti:catalog:consumer:iocs",
          "description": "Tier 0 private IOCs",
          "resource": "https://localhost:8443/api/v1/catalog/contexts/t0-iocs-5/consumers/private-iocs-5"
        },
        {
          "name": "t0-private-ruleset-5",
          "type": "cti:catalog:consumer:ruleset",
          "description": "Private ruleset 5",
          "resource": "https://localhost:8443/api/v1/catalog/contexts/t0-ruleset-5/consumers/private-ruleset-5"
        }
      ]
    }
  ]
}
''')
