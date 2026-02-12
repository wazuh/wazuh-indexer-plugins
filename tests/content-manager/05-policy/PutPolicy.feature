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
    When I send a PUT request to "/_plugins/_content_manager/policy" with body:
      """
      {
        "type": "policy",
        "resource": {
          "title": "Custom policy",
          "date": "2026-02-03T18:57:33.931731040Z",
          "modified": "2026-02-03T18:57:33.931731040Z",
          "root_decoder": "e156ffc6-4567-4725-894a-cd86e1671d2e",
          "integrations": [
            "f55b7f69-5b10-493d-acbf-023f9ab79ba6"
          ],
          "author": "Test",
          "description": "Custom policy",
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

  Scenario: Update policy attempting to add or remove integrations
    Given the current draft policy has a known integrations list
    When I send a PUT request to "/_plugins/_content_manager/policy" adding or removing integrations from the list
    Then the response status code should be 400
    And the response body should indicate integrations list cannot be modified

  Scenario: Update policy with reordered integrations list (allowed)
    Given the current draft policy has integrations ["id-a", "id-b"]
    When I send a PUT request to "/_plugins/_content_manager/policy" with integrations ["id-b", "id-a"]
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
