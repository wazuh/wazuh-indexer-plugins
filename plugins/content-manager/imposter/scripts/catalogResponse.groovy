// Catalog Response Logic
// Returns different responses based on verify parameter and query params

def verify = context.request.queryParams.verify?.toString()
def fromOffsetStr = context.request.queryParams.from_offset?.toString()
def toOffsetStr = context.request.queryParams.to_offset?.toString()
def fromOffset = fromOffsetStr ? fromOffsetStr.toInteger() : null
def toOffset = toOffsetStr ? toOffsetStr.toInteger() : null

// Check for missing verify parameter (401 Unauthorized)
if (!verify) {
    respond()
        .withStatusCode(401)
        .withHeader("Content-Type", "application/json")
        .withContent('{"error": "unauthorized_client", "error_description": "The provided token is invalid or expired"}')
}
// Check for invalid signature (403 Forbidden)
else if (verify == "invalid" || verify == "expired" || verify.startsWith("0000")) {
    respond()
        .withStatusCode(403)
        .withHeader("Content-Type", "application/json")
        .withContent('{"error": "access_denied", "error_description": "Invalid or expired HMAC signature"}')
}
// Check for invalid offset range (422 Unprocessable Entity)
else if (fromOffset != null && toOffset != null && fromOffset >= toOffset) {
    respond()
        .withStatusCode(422)
        .withHeader("Content-Type", "application/json")
        .withContent('{"errors": {"from_offset": ["must be less than to_offset"]}}')
}
// Check if range exceeds maximum (422 Unprocessable Entity)
else if (fromOffset != null && toOffset != null && (toOffset - fromOffset) > 1000) {
    respond()
        .withStatusCode(422)
        .withHeader("Content-Type", "application/json")
        .withContent('{"errors": {"to_offset": ["range exceeds maximum of 1000 changes"]}}')
}
// Success scenario
else {
    respond()
        .withStatusCode(200)
        .withHeader("Content-Type", "application/json")
        .withContent('{"data": [{"type": "create", "context": "misp", "resource": "indicator/12345", "offset": 42, "version": 1, "payload": {"type": "ip-address", "value": "192.168.1.100", "threat_level": "high", "timestamp": "2025-11-17T10:30:00Z"}}, {"type": "update", "context": "misp", "resource": "indicator/12345", "offset": 43, "version": 2, "operations": [{"op": "replace", "path": "/threat_level", "value": "critical"}]}, {"type": "delete", "context": "misp", "resource": "indicator/12345", "offset": 44, "version": 3}]}')
}
