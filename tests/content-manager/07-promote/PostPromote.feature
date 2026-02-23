@content-manager @promote
Feature: Execute Promotion
  As a Wazuh user
  I want to promote content between spaces
  So that validated content progresses through the draft -> test -> custom pipeline

  Background:
    Given Wazuh Indexer is running
    And all draft custom resources have been cleaned up
    And draft resources exist (integrations, decoders, rules, kvdbs, policy)

  # --- Draft to Test promotion ---

  Scenario: Successfully promote from draft to test
    Given I have previewed the changes from draft to test
    When I send a POST request to "/_plugins/_content_manager/promote" with body:
      """
      {
        "space": "draft",
        "changes": {
          "kvdbs": [],
          "rules": [],
          "decoders": [],
          "filters": [],
          "integrations": [],
          "policy": []
        }
      }
      """
    Then the response status code should be 200
    And the response body should contain "Promotion completed successfully."

  Scenario: Verify resources exist in test space after draft to test promotion
    Given content has been promoted from draft to test
    When I query the ".cti-decoders" index filtering by "space.name" = "test"
    Then the promoted decoders should be present
    When I query the ".cti-rules" index filtering by "space.name" = "test"
    Then the promoted rules should be present
    When I query the ".cti-kvdbs" index filtering by "space.name" = "test"
    Then the promoted kvdbs should be present
    When I query the ".cti-integrations" index filtering by "space.name" = "test"
    Then the promoted integrations should be present

  Scenario: Verify promoted resources exist in both draft and test spaces
    Given content has been promoted from draft to test
    Then each promoted resource should exist in both "draft" and "test" spaces

  Scenario: Verify test space hash is regenerated after draft to test promotion
    Given I store the test policy "space.hash.sha256" before promotion
    And content has been promoted from draft to test
    When I query the ".cti-policies" index filtering by "space.name" = "test"
    Then the test policy "space.hash.sha256" should differ from the stored value

  Scenario: Verify promoted resource hashes match between draft and test spaces
    Given content has been promoted from draft to test
    Then the "hash.sha256" of each promoted resource in "draft" should equal the "hash.sha256" of the corresponding resource in "test"

  # --- Space isolation ---

  Scenario: Deleting a decoder in draft does not affect the promoted test space
    Given content has been promoted from draft to test
    When I delete a decoder from the draft space
    Then the decoder should no longer exist in draft space
    But the decoder should still exist in the test space
    And the integration in the test space should still reference the decoder

  # --- Test to Custom promotion ---

  Scenario: Successfully promote from test to custom
    Given content has been promoted from draft to test
    And I have previewed the changes from test to custom
    When I send a POST request to "/_plugins/_content_manager/promote" with body:
      """
      {
        "space": "test",
        "changes": {
          "kvdbs": [],
          "rules": [],
          "decoders": [],
          "filters": [],
          "integrations": [],
          "policy": []
        }
      }
      """
    Then the response status code should be 200
    And the response body should contain "Promotion completed successfully."

  Scenario: Verify resources exist in custom space after test to custom promotion
    Given content has been promoted from test to custom
    When I query the ".cti-decoders" index filtering by "space.name" = "custom"
    Then the promoted decoders should be present

  Scenario: Verify promoted resources exist in both test and custom spaces
    Given content has been promoted from test to custom
    Then each promoted resource should exist in both "test" and "custom" spaces

  Scenario: Verify custom space hash is regenerated after test to custom promotion
    Given I store the custom policy "space.hash.sha256" before promotion
    And content has been promoted from test to custom
    When I query the ".cti-policies" index filtering by "space.name" = "custom"
    Then the custom policy "space.hash.sha256" should differ from the stored value

  Scenario: Verify promoted resource hashes match between test and custom spaces
    Given content has been promoted from test to custom
    Then the "hash.sha256" of each promoted resource in "test" should equal the "hash.sha256" of the corresponding resource in "custom"

  # --- Error scenarios ---

  Scenario: Promote from custom (not allowed)
    When I send a POST request to "/_plugins/_content_manager/promote" with body:
      """
      {
        "space": "custom",
        "changes": {
          "kvdbs": [],
          "rules": [],
          "decoders": [],
          "filters": [],
          "integrations": [],
          "policy": []
        }
      }
      """
    Then the response status code should be 400
    And the response body should contain "cannot be promoted"

  Scenario: Promote with invalid space
    When I send a POST request to "/_plugins/_content_manager/promote" with body:
      """
      {
        "space": "prod",
        "changes": {
          "kvdbs": [],
          "rules": [],
          "decoders": [],
          "filters": [],
          "integrations": [],
          "policy": []
        }
      }
      """
    Then the response status code should be 400
    And the response body should contain "Unknown space"

  Scenario: Promote with missing changes object
    When I send a POST request to "/_plugins/_content_manager/promote" with body:
      """
      {
        "space": "draft"
      }
      """
    Then the response status code should be 400

  Scenario: Promote with incomplete changes (missing required resource arrays)
    When I send a POST request to "/_plugins/_content_manager/promote" with body:
      """
      {
        "space": "draft",
        "changes": {}
      }
      """
    Then the response status code should be 400

  Scenario: Promote with non-update operation on policy
    When I send a POST request to "/_plugins/_content_manager/promote" with body:
      """
      {
        "space": "draft",
        "changes": {
          "kvdbs": [],
          "rules": [],
          "decoders": [],
          "filters": [],
          "integrations": [],
          "policy": [{ "operation": "add", "id": "some-id" }]
        }
      }
      """
    Then the response status code should be 400
    And the response body should contain "Only 'update' operation is supported for policy."

  Scenario: Promote with empty body
    When I send a POST request to "/_plugins/_content_manager/promote" with an empty body
    Then the response status code should be 400

  Scenario: Promote without authentication
    Given I have no credentials
    When I send a POST request to "/_plugins/_content_manager/promote" with a valid payload
    Then the response status code should be 401
