@content-manager @integrations
Feature: Update Integration
  As a Wazuh user
  I want to update an existing integration in draft space
  So that I can modify its data while preserving resource associations

  Background:
    Given Wazuh Indexer is running
    And all draft integrations have been cleaned up
    And an integration exists in draft space with a known ID

  Scenario: Successfully update an integration
    When I send a PUT request to "/_plugins/_content_manager/integrations/{integration_id}" with body:
      """
      {
        "resource": {
          "title": "test-integration-updated",
          "author": "Wazuh Inc.",
          "category": "cloud-services",
          "description": "Updated integration description.",
          "documentation": "updated documentation",
          "references": [],
          "enabled": true,
          "rules": [],
          "decoders": [],
          "kvdbs": []
        }
      }
      """
    Then the response status code should be 200
    And the response body should contain the integration ID

  Scenario: Update an integration with missing required fields
    When I send a PUT request to "/_plugins/_content_manager/integrations/{integration_id}" with body:
      """
      {
        "resource": {
          "title": "updated-title"
        }
      }
      """
    Then the response status code should be 400

  Scenario: Update an integration that does not exist
    When I send a PUT request to "/_plugins/_content_manager/integrations/00000000-0000-0000-0000-000000000000" with body:
      """
      {
        "resource": {
          "title": "nonexistent",
          "author": "Test",
          "category": "cloud-services",
          "description": "",
          "documentation": "",
          "references": [],
          "rules": [],
          "decoders": [],
          "kvdbs": []
        }
      }
      """
    Then the response status code should be 404

  Scenario: Update an integration with an invalid UUID
    When I send a PUT request to "/_plugins/_content_manager/integrations/not-a-uuid" with a valid payload
    Then the response status code should be 400
    And the response body should contain "is not a valid UUID"

  Scenario: Update an integration with an id in the request body
    When I send a PUT request to "/_plugins/_content_manager/integrations/{integration_id}" with body:
      """
      {
        "resource": {
          "id": "some-id",
          "title": "test",
          "author": "Test",
          "category": "cloud-services",
          "description": "",
          "documentation": "",
          "references": [],
          "rules": [],
          "decoders": [],
          "kvdbs": []
        }
      }
      """
    Then the response status code should be 400

  Scenario: Update an integration attempting to add/remove dependency lists
    Given the integration has associated decoders, rules, or kvdbs
    When I send a PUT request with modified dependency lists (rules, decoders, or kvdbs)
    Then the response status code should be 400
    And the response body should indicate dependency lists cannot be modified via PUT

  Scenario: Update an integration without authentication
    Given I have no credentials
    When I send a PUT request to "/_plugins/_content_manager/integrations/{integration_id}" with a valid payload
    Then the response status code should be 401
