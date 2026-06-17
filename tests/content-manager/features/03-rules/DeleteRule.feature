@content-manager @rules @requires-integration
Feature: Delete Rule
  As a Wazuh user
  I want to delete a rule from draft space
  So that it is removed from the content catalog

  Background:
    Given Wazuh Indexer is running
    And all draft rules have been cleaned up
    And a rule exists in draft space with a known ID

  Scenario: Successfully delete a rule
    When I send a DELETE request to "/_plugins/_content_manager/rules/{rule_id}"
    Then the response status code should be 200
    And the response body should contain the rule ID
    And the rule should no longer exist in the ".cti-rules" index
    And the rule should no longer exist in the SAP rules with source "Draft"
    And the rule ID should no longer be listed in the integration's "rules" list
    And the integration's "hash.sha256" field should have been updated
    And the draft policy "space.hash.sha256" should have been updated

  Scenario: Delete a rule that does not exist
    When I send a DELETE request to "/_plugins/_content_manager/rules/00000000-0000-0000-0000-000000000000"
    Then the response status code should be 404

  Scenario: Delete a rule with an invalid UUID
    When I send a DELETE request to "/_plugins/_content_manager/rules/not-a-uuid"
    Then the response status code should be 400
    And the response body should contain "is not a valid UUID"

  Scenario: Delete a rule not in draft space
    Given the rule exists only in test or custom space
    When I send a DELETE request to "/_plugins/_content_manager/rules/{rule_id}"
    Then the response status code should be 400
    And the response body should contain "is not in draft space"

  Scenario: Delete a rule without providing an ID
    When I send a DELETE request to "/_plugins/_content_manager/rules/"
    Then the response status code should be 400

  Scenario: Delete a rule without authentication
    Given I have no credentials
    When I send a DELETE request to "/_plugins/_content_manager/rules/{rule_id}"
    Then the response status code should be 401

  Scenario: Verify rule is removed from index after deletion
    Given a rule has been deleted with a known ID
    When I send a GET request to "/.cti-rules/_doc/{rule_id}"
    Then the response status code should be 404
