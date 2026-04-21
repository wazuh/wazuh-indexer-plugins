// Releases Updates Response Logic
// Returns mock release updates based on the version tag in the path.
// Simulates the CTI API GET /api/v1/releases/:tag/updates endpoint.

def tag = context.request.pathParams['tag']

// Validate tag format (must start with 'v')
if (!tag || !tag.startsWith('v')) {
    respond()
        .withStatusCode(400)
        .withHeader("Content-Type", "application/json")
        .withContent('{"errors": {"tag": ["is invalid"]}}')
    return
}

// For v5.0.0 — simulate the current version with available updates
if (tag == 'v5.0.0') {
    respond()
        .withStatusCode(200)
        .withHeader("Content-Type", "application/json")
        .withContent('''
{
  "data": {
    "major": [
      {
        "tag": "v6.0.0",
        "title": "Wazuh v6.0.0",
        "description": "The 6.0.0 major release introduces a new architecture and platform improvements.",
        "published_date": "2026-11-01T10:00:00Z",
        "semver": { "major": 6, "minor": 0, "patch": 0 }
      }
    ],
    "minor": [
      {
        "tag": "v5.1.0",
        "title": "Wazuh v5.1.0",
        "description": "The 5.1.0 release includes minor improvements and enhancements.",
        "published_date": "2026-06-15T10:00:00Z",
        "semver": { "major": 5, "minor": 1, "patch": 0 }
      },
      {
        "tag": "v5.2.0",
        "title": "Wazuh v5.2.0",
        "description": "The 5.2.0 release includes new features and improvements.",
        "published_date": "2026-09-01T10:00:00Z",
        "semver": { "major": 5, "minor": 2, "patch": 0 }
      }
    ],
    "patch": [
      {
        "tag": "v5.0.1",
        "title": "Wazuh v5.0.1",
        "description": "Wazuh version 5.0.1 is a patch update focusing on bug fixes.",
        "published_date": "2026-05-10T10:00:00Z",
        "semver": { "major": 5, "minor": 0, "patch": 1 }
      }
    ]
  }
}
''')
    return
}

// For any other valid tag — simulate no updates available
respond()
    .withStatusCode(200)
    .withHeader("Content-Type", "application/json")
    .withContent('{"data": {"major": [], "minor": [], "patch": []}}')
