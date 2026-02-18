@content-manager @rules @requires-integration
Feature: Update Rule
  As a Wazuh user
  I want to update an existing rule in draft space
  So that I can modify its detection logic and metadata

  Background:
    Given Wazuh Indexer is running
    And all draft rules have been cleaned up
    And a rule exists in draft space with a known ID

  Scenario: Successfully update a rule
    When I send a PUT request to "/_plugins/_content_manager/rules/{rule_id}" with body:
      """
      {
        "type": "rule",
        "resource": {
          "title": "Test Hash Generation Rule UPDATED",
          "description": "A rule to verify that SHA-256 hashes are calculated correctly upon creation.",
          "author": "Tester",
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
    Then the response status code should be 200
    And the response body should contain the rule ID
    And the rule document should be correctly updated in the ".cti-rules" index
    And the document "space.name" field should still be "draft"
    And the document "hash.sha256" field should have been updated
    And the rule should be updated in the SAP rules with source "Draft"
    And the draft policy "space.hash.sha256" should have been updated

  Scenario: Update a rule with missing title
    When I send a PUT request to "/_plugins/_content_manager/rules/{rule_id}" with body:
      """
      {
        "type": "rule",
        "resource": {
          "description": "Updated without title",
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

  Scenario: Update a rule that does not exist
    When I send a PUT request to "/_plugins/_content_manager/rules/00000000-0000-0000-0000-000000000000" with a valid payload
    Then the response status code should be 404

  Scenario: Update a rule with an invalid UUID
    When I send a PUT request to "/_plugins/_content_manager/rules/not-a-uuid" with a valid payload
    Then the response status code should be 400
    And the response body should contain "is not a valid UUID"

  Scenario: Update a rule not in draft space
    Given the rule exists only in test or custom space
    When I send a PUT request to "/_plugins/_content_manager/rules/{rule_id}" with a valid payload
    Then the response status code should be 400
    And the response body should contain "is not in draft space"

  Scenario: Update a rule with empty body
    When I send a PUT request to "/_plugins/_content_manager/rules/{rule_id}" with an empty body
    Then the response status code should be 400

  Scenario: Update a rule without authentication
    Given I have no credentials
    When I send a PUT request to "/_plugins/_content_manager/rules/{rule_id}" with a valid payload
    Then the response status code should be 401
