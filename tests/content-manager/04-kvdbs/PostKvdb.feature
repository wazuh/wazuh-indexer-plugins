@content-manager @kvdbs @requires-integration
Feature: Create KVDB
  As a Wazuh user
  I want to create a new key-value database linked to an integration in draft space
  So that the engine can use it for lookups

  Background:
    Given Wazuh Indexer is running
    And all draft kvdbs have been cleaned up
    And an integration exists in draft space with a known ID

  Scenario: Successfully create a KVDB
    When I send a POST request to "/_plugins/_content_manager/kvdbs" with body:
      """
      {
        "integration": "{integration_id}",
        "resource": {
          "name": "test",
          "enabled": true,
          "author": "Wazuh Inc.",
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
          "description": "",
          "documentation": "",
          "references": [
            "https://wazuh.com"
          ],
          "title": "non_standard_timezones"
        }
      }
      """
    Then the response status code should be 201
    And the response body should contain the KVDB ID
    And the KVDB should exist in the ".cti-kvdbs" index in the "draft" space

  Scenario: Create a KVDB with missing title
    When I send a POST request to "/_plugins/_content_manager/kvdbs" with body:
      """
      {
        "integration": "{integration_id}",
        "resource": {
          "name": "test",
          "author": "Wazuh Inc.",
          "content": { "key": "value" }
        }
      }
      """
    Then the response status code should be 400
    And the response body should contain "Missing [title] field."

  Scenario: Create a KVDB with missing author
    When I send a POST request to "/_plugins/_content_manager/kvdbs" with body:
      """
      {
        "integration": "{integration_id}",
        "resource": {
          "name": "test",
          "title": "Test KVDB",
          "content": { "key": "value" }
        }
      }
      """
    Then the response status code should be 400
    And the response body should contain "Missing [author] field."

  Scenario: Create a KVDB with missing content
    When I send a POST request to "/_plugins/_content_manager/kvdbs" with body:
      """
      {
        "integration": "{integration_id}",
        "resource": {
          "name": "test",
          "title": "Test KVDB",
          "author": "Wazuh Inc."
        }
      }
      """
    Then the response status code should be 400
    And the response body should contain "Missing [content] field."

  Scenario: Create a KVDB without an integration reference
    When I send a POST request to "/_plugins/_content_manager/kvdbs" with body:
      """
      {
        "resource": {
          "name": "test",
          "title": "Test KVDB",
          "author": "Wazuh Inc.",
          "content": { "key": "value" }
        }
      }
      """
    Then the response status code should be 400

  Scenario: Create a KVDB with an explicit id in the resource
    When I send a POST request to "/_plugins/_content_manager/kvdbs" with body:
      """
      {
        "integration": "{integration_id}",
        "resource": {
          "id": "custom-id",
          "name": "test",
          "title": "Test KVDB",
          "author": "Wazuh Inc.",
          "content": { "key": "value" }
        }
      }
      """
    Then the response status code should be 400

  Scenario: Create a KVDB with an integration not in draft space
    When I send a POST request to "/_plugins/_content_manager/kvdbs" with body:
      """
      {
        "integration": "{non_draft_integration_id}",
        "resource": {
          "name": "test",
          "title": "Test KVDB",
          "author": "Wazuh Inc.",
          "content": { "key": "value" }
        }
      }
      """
    Then the response status code should be 400
    And the response body should contain "is not in draft space"

  Scenario: Create a KVDB with empty body
    When I send a POST request to "/_plugins/_content_manager/kvdbs" with an empty body
    Then the response status code should be 400

  Scenario: Create a KVDB without authentication
    Given I have no credentials
    When I send a POST request to "/_plugins/_content_manager/kvdbs" with a valid payload
    Then the response status code should be 401

  Scenario: Verify KVDB appears in draft space index
    Given a KVDB has been created with a known ID
    When I send a GET request to "/.cti-kvdbs/_doc/{kvdb_id}"
    Then the response status code should be 200
    And the document "space.name" field should be "draft"
