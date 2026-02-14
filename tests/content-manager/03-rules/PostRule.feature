@content-manager @rules @requires-integration
Feature: Create Rule
  As a Wazuh user
  I want to create a new rule linked to an integration in draft space
  So that the engine can use it for threat detection

  Background:
    Given Wazuh Indexer is running
    And all draft rules have been cleaned up
    And an integration exists in draft space with a known ID

  Scenario: Successfully create a rule
    When I send a POST request to "/_plugins/_content_manager/rules" with body:
      """
      {
        "integration": "{integration_id}",
        "resource": {
          "title": "Test Hash Generation Rule",
          "description": "A rule to verify that SHA-256 hashes are calculated correctly upon creation.",
          "author": "Tester",
          "sigma_id": "string",
          "references": [
            "https://wazuh.com"
          ],
          "enabled": true,
          "status": "experimental",
          "logsource": {
            "product": "system",
            "category": "system"
          },
          "detection": {
            "condition": "selection",
            "selection": {
              "event.action": [
                "hash_test_event"
              ]
            }
          },
          "level": "low"
        }
      }
      """
    Then the response status code should be 201
    And the response body should contain the rule ID
    And the rule should exist in the ".cti-rules"
    And the document "space.name" field should be "draft"

  Scenario: Create a rule with missing title
    When I send a POST request to "/_plugins/_content_manager/rules" with body:
      """
      {
        "integration": "{integration_id}",
        "resource": {
          "description": "A rule without title",
          "author": "Tester",
          "logsource": {
            "product": "system",
            "category": "system"
          },
          "detection": {
            "condition": "selection",
            "selection": {
              "event.action": ["test"]
            }
          },
          "level": "low"
        }
      }
      """
    Then the response status code should be 400
    And the response body should contain "Missing [title] field."

  Scenario: Create a rule without an integration reference
    When I send a POST request to "/_plugins/_content_manager/rules" with body:
      """
      {
        "resource": {
          "title": "Orphan Rule",
          "logsource": {
            "product": "system",
            "category": "system"
          },
          "detection": {
            "condition": "selection",
            "selection": {
              "event.action": ["test"]
            }
          },
          "level": "low"
        }
      }
      """
    Then the response status code should be 400

  Scenario: Create a rule with an explicit id in the resource
    When I send a POST request to "/_plugins/_content_manager/rules" with body:
      """
      {
        "integration": "{integration_id}",
        "resource": {
          "id": "custom-id",
          "title": "Rule with ID",
          "logsource": {
            "product": "system",
            "category": "system"
          },
          "detection": {
            "condition": "selection",
            "selection": {
              "event.action": ["test"]
            }
          },
          "level": "low"
        }
      }
      """
    Then the response status code should be 400

  Scenario: Create a rule with an integration not in draft space
    When I send a POST request to "/_plugins/_content_manager/rules" with body:
      """
      {
        "integration": "{non_draft_integration_id}",
        "resource": {
          "title": "Rule with non-draft integration",
          "logsource": {
            "product": "system",
            "category": "system"
          },
          "detection": {
            "condition": "selection",
            "selection": {
              "event.action": ["test"]
            }
          },
          "level": "low"
        }
      }
      """
    Then the response status code should be 400
    And the response body should contain "is not in draft space"

  Scenario: Create a rule with empty body
    When I send a POST request to "/_plugins/_content_manager/rules" with an empty body
    Then the response status code should be 400

  Scenario: Create a rule without authentication
    Given I have no credentials
    When I send a POST request to "/_plugins/_content_manager/rules" with a valid payload
    Then the response status code should be 401
