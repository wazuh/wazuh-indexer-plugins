@content-manager @integrations
Feature: Delete Integration
  As a Wazuh user
  I want to delete an integration from draft space
  So that it is removed from the content catalog

  Background:
    Given Wazuh Indexer is running
    And all draft integrations have been cleaned up
    And an integration exists in draft space with a known ID

  Scenario: Successfully delete an integration with no attached resources
    Given the integration has no associated decoders, rules, or kvdbs
    When I send a DELETE request to "/_plugins/_content_manager/integrations/{integration_id}"
    Then the response status code should be 200
    And the response body should contain the integration ID
    And the integration should no longer exist in the ".cti-integrations" index
    And the integration should no longer exists in the secutity analytics logtypes with source "Draft"

  Scenario: Delete an integration that has attached resources
    Given the integration has associated decoders, rules, or kvdbs
    When I send a DELETE request to "/_plugins/_content_manager/integrations/{integration_id}"
    Then the response status code should be 400
    And the response body should contain "Cannot delete integration because it has [RESOURCE] attached."

  Scenario: Delete an integration that does not exist
    When I send a DELETE request to "/_plugins/_content_manager/integrations/00000000-0000-0000-0000-000000000000"
    Then the response status code should be 404

  Scenario: Delete an integration with an invalid UUID
    When I send a DELETE request to "/_plugins/_content_manager/integrations/not-a-uuid"
    Then the response status code should be 400
    And the response body should contain "is not a valid UUID"

  Scenario: Delete an integration without providing an ID
    When I send a DELETE request to "/_plugins/_content_manager/integrations/"
    Then the response status code should be 400

  Scenario: Delete an integration not in draft space
    Given the integration exists only in test or custom space
    When I send a DELETE request to "/_plugins/_content_manager/integrations/{integration_id}"
    Then the response status code should be 400
    And the response body should contain "is not in draft space"

  Scenario: Delete an integration without authentication
    Given I have no credentials
    When I send a DELETE request to "/_plugins/_content_manager/integrations/{integration_id}"
    Then the response status code should be 401
