// Token Request Response Logic
// Returns different responses based on device_code parameter and request count

import java.util.concurrent.ConcurrentHashMap

// Use a static map to track request counts across invocations
@groovy.transform.Field
static ConcurrentHashMap<String, Integer> requestCounts = new ConcurrentHashMap<>()

def deviceCode = context.request.formParams.device_code?.toString()

// Expired token scenario
if (deviceCode == "expired") {
    respond()
        .withStatusCode(400)
        .withHeader("Cache-Control", "no-store")
        .withHeader("Pragma", "no-cache")
        .withHeader("Content-Type", "application/json")
        .withContent('{"error": "expired_token", "error_description": "The device code has expired"}')
}
// Pending authorization codes
else if (deviceCode == "pending") {
    respond()
        .withStatusCode(400)
        .withHeader("Cache-Control", "no-store")
        .withHeader("Pragma", "no-cache")
        .withHeader("Content-Type", "application/json")
        .withContent('{"error": "authorization_pending"}')
}
// Success scenario - immediate grant
else if (deviceCode == "granted") {
    respond()
        .withStatusCode(200)
        .withHeader("Cache-Control", "no-store")
        .withHeader("Content-Type", "application/json")
        .withContent('{"access_token": "AYjcyMzY3ZDhiNmJkNTY", "refresh_token": "RjY2NjM5NzA2OWJjuE7c", "token_type": "Bearer", "expires_in": 3600}')
}
// Handle pending/rejected flow
else if (deviceCode == "pending_rejected") {
    def count = requestCounts.getOrDefault(deviceCode, 0) + 1
    requestCounts.put(deviceCode, count)

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
// Handle pending/granted flow
else {
    def count = requestCounts.getOrDefault(deviceCode, 0) + 1
    requestCounts.put(deviceCode, count)

    // Return authorization_pending for first 4 attempts
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
