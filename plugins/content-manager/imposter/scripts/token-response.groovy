// Token Request Response Logic
// Returns different responses based on device_code parameter

def deviceCode = context.request.formParams.device_code?.toString()

// Check for authorization_pending scenario
if (deviceCode == "pending_code" || deviceCode == "auth_pending") {
    respond()
        .withStatusCode(400)
        .withHeader("Cache-Control", "no-store")
        .withHeader("Pragma", "no-cache")
        .withHeader("Content-Type", "application/json")
        .withContent('{"error": "authorization_pending"}')
}
// Check for expired_token scenario
else if (deviceCode == "expired_code" || deviceCode == "expired") {
    respond()
        .withStatusCode(400)
        .withHeader("Cache-Control", "no-store")
        .withHeader("Pragma", "no-cache")
        .withHeader("Content-Type", "application/json")
        .withContent('{"error": "expired_token", "error_description": "The device code has expired"}')
}
// Success scenario - valid device code
else {
    respond()
        .withStatusCode(200)
        .withHeader("Cache-Control", "no-store")
        .withHeader("Content-Type", "application/json")
        .withContent('{"access_token": "AYjcyMzY3ZDhiNmJkNTY", "refresh_token": "RjY2NjM5NzA2OWJjuE7c", "token_type": "Bearer", "expires_in": 3600}')
}
