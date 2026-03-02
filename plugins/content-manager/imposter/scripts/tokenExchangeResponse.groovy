// Token Exchange Response Logic
// Returns different responses based on Authorization header

def authHeader = context.request.headers.Authorization?.toString()
def resource = context.request.formParams.resource?.toString()

// Check for missing Authorization header
if (!authHeader) {
    respond()
        .withStatusCode(401)
        .withHeader("Content-Type", "application/json")
        .withContent('{"error": "unauthorized_client", "error_description": "The provided token is invalid or expired"}')
}
// Check for invalid token
else if (authHeader == "Bearer invalid_token" || authHeader == "Bearer expired_token") {
    respond()
        .withStatusCode(401)
        .withHeader("Content-Type", "application/json")
        .withContent('{"error": "unauthorized_client", "error_description": "The provided token is invalid or expired"}')
}
// Check for missing resource parameter
else if (!resource) {
    respond()
        .withStatusCode(400)
        .withHeader("Cache-Control", "no-store")
        .withHeader("Pragma", "no-cache")
        .withHeader("Content-Type", "application/json")
        .withContent('{"error": "invalid_request", "error_description": "Missing required parameter resource"}')
}
// Check for invalid resource endpoint
else if (resource && resource.contains("invalid_target")) {
    respond()
        .withStatusCode(400)
        .withHeader("Cache-Control", "no-store")
        .withHeader("Pragma", "no-cache")
        .withHeader("Content-Type", "application/json")
        .withContent('{"error": "invalid_target", "error_description": "The resource parameter refers to an invalid endpoint"}')
}
// Success scenario
else {
    respond()
        .withStatusCode(200)
        .withHeader("Cache-Control", "no-store")
        .withHeader("Content-Type", "application/json")
        .withContent('{"access_token": "https://localhost:8443/api/v1/catalog/contexts/misp/consumers/virustotal/changes?from_offset=0&to_offset=1000&with_empties=true&verify=1761383411-kJ9b8w%2BQ7kzRmF", "issued_token_type": "urn:wazuh:params:oauth:token-type:signed_url", "expires_in": 300}')
}
