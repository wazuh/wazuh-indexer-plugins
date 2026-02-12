@content-manager @policy
Feature: Update Draft Policy
  As a Wazuh user
  I want to update the draft policy
  So that my changes are applied to test and custom spaces via the promotion mechanism

  Background:
    Given Wazuh Indexer is running
    And the draft policy has been reset to its default state
    And the draft policy exists in the ".cti-policies" index

  Scenario: Successfully update the draft policy
    Given an integration exists in draft space and its ID is stored as "integration_id"
    And a decoder exists in draft space linked to "{integration_id}" and its ID is stored as "decoder_id"
    When I send a PUT request to "/_plugins/_content_manager/policy" with body:
      """
      {
        "type": "policy",
        "resource": {
          "title": "Updated policy",
          "date": "2026-02-03T18:57:33.931731040Z",
          "modified": "2026-02-03T18:57:33.931731040Z",
          "root_decoder": "{decoder_id}",
          "integrations": ["{integration_id}"],
          "filters": [],
          "enrichments": [],
          "author": "Test",
          "description": "Updated policy description",
          "documentation": "",
          "references": []
        }
      }
      """
    Then the response status code should be 200
    And the response body should contain the policy ID
    And the draft policy in ".cti-policies" should be updated

  Scenario: Update policy with missing type field
    When I send a PUT request to "/_plugins/_content_manager/policy" with body:
      """
      {
        "resource": {
          "title": "Custom policy",
          "author": "Test",
          "description": "Custom policy",
          "documentation": "",
          "references": []
        }
      }
      """
    Then the response status code should be 400
    And the response body should contain "Missing [type] field."

  Scenario: Update policy with wrong type value
    When I send a PUT request to "/_plugins/_content_manager/policy" with body:
      """
      {
        "type": "integration",
        "resource": {
          "title": "Custom policy",
          "author": "Test",
          "description": "Custom policy",
          "documentation": "",
          "references": []
        }
      }
      """
    Then the response status code should be 400
    And the response body should contain "Invalid 'type' format."

  Scenario: Update policy with missing resource object
    When I send a PUT request to "/_plugins/_content_manager/policy" with body:
      """
      {
        "type": "policy"
      }
      """
    Then the response status code should be 400

  Scenario: Update policy with missing required fields in resource
    When I send a PUT request to "/_plugins/_content_manager/policy" with body:
      """
      {
        "type": "policy",
        "resource": {
          "title": "Custom policy"
        }
      }
      """
    Then the response status code should be 400

  Scenario: Update policy attempting to add an integration to the list
    Given the current draft policy integrations list is known
    When I send a PUT request to "/_plugins/_content_manager/policy" with an additional integration ID appended to the current list
    Then the response status code should be 400
    And the response body should indicate integrations list cannot be modified

  Scenario: Update policy attempting to remove an integration from the list
    Given the current draft policy has at least one integration
    When I send a PUT request to "/_plugins/_content_manager/policy" with the current integrations list minus one entry
    Then the response status code should be 400
    And the response body should indicate integrations list cannot be modified

  Scenario: Update policy with reordered integrations list (allowed)
    Given the current draft policy has at least two integrations
    When I send a PUT request to "/_plugins/_content_manager/policy" with the same integrations in a different order
    Then the response status code should be 200

  Scenario: Update policy with empty body
    When I send a PUT request to "/_plugins/_content_manager/policy" with an empty body
    Then the response status code should be 400

  Scenario: Update policy without authentication
    Given I have no credentials
    When I send a PUT request to "/_plugins/_content_manager/policy" with a valid payload
    Then the response status code should be 401

  Scenario: Verify policy changes are NOT reflected in test space until promotion
    Given I have updated the draft policy
    When I query the test policy in ".cti-policies"
    Then the test policy should NOT reflect the draft changes

  Scenario: Verify policy changes are reflected in test space after promotion
    Given I have updated the draft policy
    And I promote content from draft to test
    When I query the test policy in ".cti-policies"
    Then the test policy should reflect the draft changes
