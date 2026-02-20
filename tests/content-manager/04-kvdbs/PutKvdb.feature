@content-manager @kvdbs @requires-integration
Feature: Update KVDB
  As a Wazuh user
  I want to update an existing key-value database in draft space
  So that I can modify its content and metadata

  Background:
    Given Wazuh Indexer is running
    And all draft kvdbs have been cleaned up
    And a KVDB exists in draft space with a known ID

  Scenario: Successfully update a KVDB
    When I send a PUT request to "/_plugins/_content_manager/kvdbs/{kvdb_id}" with body:
      """
      {
        "resource": {
          "name": "test-UPDATED",
          "enabled": true,
          "author": "Wazuh.",
          "content": {
            "non_standard_timezones": {
              "AEST": "Australia/Sydney",
              "CEST": "Europe/Berlin",
              "CST": "America/Chicago",
              "EDT": "America/New_York",
              "EST": "America/New_York",
              "IST": "Asia/Kolkata",
              "MST": "America/Denver",
              "PKT": "Asia/Karachi",
              "SST": "Asia/Singapore",
              "WEST": "Europe/London"
            }
          },
          "description": "UPDATE",
          "documentation": "UPDATE.doc",
          "references": [
            "https://wazuh.com"
          ],
          "title": "non_standard_timezones-2"
        }
      }
      """
    Then the response status code should be 200
    And the response body should contain the KVDB ID
    And the KVDB document should be correctly updated in the ".cti-kvdbs" index
    And the document "space.name" field should still be "draft"
    And the document "hash.sha256" field should have been updated
    And the draft policy "space.hash.sha256" should have been updated

  Scenario: Update a KVDB with missing required fields
    When I send a PUT request to "/_plugins/_content_manager/kvdbs/{kvdb_id}" with body:
      """
      {
        "resource": {
          "name": "updated"
        }
      }
      """
    Then the response status code should be 400

  Scenario: Update a KVDB that does not exist
    When I send a PUT request to "/_plugins/_content_manager/kvdbs/00000000-0000-0000-0000-000000000000" with a valid payload
    Then the response status code should be 404

  Scenario: Update a KVDB with an invalid UUID
    When I send a PUT request to "/_plugins/_content_manager/kvdbs/not-a-uuid" with a valid payload
    Then the response status code should be 400
    And the response body should contain "is not a valid UUID"

  Scenario: Update a KVDB not in draft space
    Given the KVDB exists only in test or custom space
    When I send a PUT request to "/_plugins/_content_manager/kvdbs/{kvdb_id}" with a valid payload
    Then the response status code should be 400
    And the response body should contain "is not in draft space"

  Scenario: Update a KVDB with empty body
    When I send a PUT request to "/_plugins/_content_manager/kvdbs/{kvdb_id}" with an empty body
    Then the response status code should be 400

  Scenario: Update a KVDB without authentication
    Given I have no credentials
    When I send a PUT request to "/_plugins/_content_manager/kvdbs/{kvdb_id}" with a valid payload
    Then the response status code should be 401
