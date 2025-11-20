// Token Request Response Logic
// Returns different responses based on device_code parameter and request count

def deviceCode = context.request.formParams.device_code?.toString()
def stores = context.stores

// Handle pending/granted/rejected flow
if (deviceCode == "pending_code" || deviceCode == "auth_pending") {
    def countStore = stores.open("token_requests")
    def count = countStore.load(deviceCode) as Integer ?: 0
    count++
    countStore.save(deviceCode, count)

    // Return authorization_pending for first 4-5 attempts
    if (count <= 4) {
        respond()
            .withStatusCode(400)
            .withHeader("Cache-Control", "no-store")
            .withHeader("Pragma", "no-cache")
            .withHeader("Content-Type", "application/json")
            .withContent('{"error": "authorization_pending"}')
    } else {
        // Grant token after 4 attempts
        respond()
            .withStatusCode(200)
            .withHeader("Cache-Control", "no-store")
            .withHeader("Content-Type", "application/json")
            .withContent('{"access_token": "AYjcyMzY3ZDhiNmJkNTY", "refresh_token": "RjY2NjM5NzA2OWJjuE7c", "token_type": "Bearer", "expires_in": 3600}')
    }
}
// Handle rejected flow
else if (deviceCode == "pending_rejected") {
    def countStore = stores.open("token_requests")
    def count = countStore.load(deviceCode) as Integer ?: 0
    count++
    countStore.save(deviceCode, count)

    if (count <= 4) {
        respond()
            .withStatusCode(400)
            .withHeader("Cache-Control", "no-store")
            .withHeader("Pragma", "no-cache")
            .withHeader("Content-Type", "application/json")
            .withContent('{"error": "authorization_pending"}')
    } else {
        // Reject after 4 attempts
        respond()
            .withStatusCode(400)
            .withHeader("Cache-Control", "no-store")
            .withHeader("Pragma", "no-cache")
            .withHeader("Content-Type", "application/json")
            .withContent('{"error": "access_denied", "error_description": "Token authorization denied"}')
    }
}
// Expired token scenario
else if (deviceCode == "expired_code" || deviceCode == "expired") {
    respond()
        .withStatusCode(400)
        .withHeader("Cache-Control", "no-store")
        .withHeader("Pragma", "no-cache")
        .withHeader("Content-Type", "application/json")
        .withContent('{"error": "expired_token", "error_description": "The device code has expired"}')
}
// Success scenario - immediate grant
else {
    respond()
        .withStatusCode(200)
        .withHeader("Cache-Control", "no-store")
        .withHeader("Content-Type", "application/json")
        .withContent('{"access_token": "AYjcyMzY3ZDhiNmJkNTY", "refresh_token": "RjY2NjM5NzA2OWJjuE7c", "token_type": "Bearer", "expires_in": 3600}')
}
