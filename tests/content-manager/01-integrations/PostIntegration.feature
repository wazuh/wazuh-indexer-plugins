@content-manager @integrations
Feature: Create Integration
  As a Wazuh user
  I want to create a new integration in draft space
  So that I can associate decoders, rules, and kvdbs to it

  Background:
    Given Wazuh Indexer is running
    And all draft integrations have been cleaned up
    And an update has been executed successfully

  Scenario: Successfully create an integration
    When I send a POST request to "/_plugins/_content_manager/integrations" with body:
      """
      {
        "resource": {
          "title": "test-integration",
          "author": "Wazuh Inc.",
          "category": "cloud-services",
          "description": "This integration supports something.",
          "documentation": "test1234",
          "references": [
            "https://wazuh.com"
          ],
          "enabled": true
        }
      }
      """
    Then the response status code should be 201
    And the response body should contain a generated resource ID
    And the integration should exist in the ".cti-integrations"
    And the document "space.name" field should be "draft"

  Scenario: Create an integration with missing title
    When I send a POST request to "/_plugins/_content_manager/integrations" with body:
      """
      {
        "resource": {
          "author": "Wazuh Inc.",
          "category": "cloud-services"
        }
      }
      """
    Then the response status code should be 400
    And the response body should contain "Missing [title] field."

  Scenario: Create an integration with missing author
    When I send a POST request to "/_plugins/_content_manager/integrations" with body:
      """
      {
        "resource": {
          "title": "test-integration",
          "category": "cloud-services"
        }
      }
      """
    Then the response status code should be 400
    And the response body should contain "Missing [author] field."

  Scenario: Create an integration with missing category
    When I send a POST request to "/_plugins/_content_manager/integrations" with body:
      """
      {
        "resource": {
          "title": "test-integration",
          "author": "Wazuh Inc."
        }
      }
      """
    Then the response status code should be 400
    And the response body should contain "Missing [category] field."

  Scenario: Create an integration with an explicit id in the resource
    When I send a POST request to "/_plugins/_content_manager/integrations" with body:
      """
      {
        "resource": {
          "id": "custom-id",
          "title": "test-integration",
          "author": "Wazuh Inc.",
          "category": "cloud-services"
        }
      }
      """
    Then the response status code should be 400

  Scenario: Create an integration with missing resource object
    When I send a POST request to "/_plugins/_content_manager/integrations" with body:
      """
      {}
      """
    Then the response status code should be 400

  Scenario: Create an integration with empty body
    When I send a POST request to "/_plugins/_content_manager/integrations" with an empty body
    Then the response status code should be 400

  Scenario: Create an integration without authentication
    Given I have no credentials
    When I send a POST request to "/_plugins/_content_manager/integrations" with a valid payload
    Then the response status code should be 401
