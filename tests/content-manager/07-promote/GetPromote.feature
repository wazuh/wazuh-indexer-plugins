@content-manager @promote
Feature: Preview Promotion
  As a Wazuh user
  I want to preview the changes between spaces before promoting
  So that I can review what will be added, updated, or removed

  Background:
    Given Wazuh Indexer is running
    And all draft custom resources have been cleaned up
    And draft resources exist (integrations, decoders, rules, kvdbs, policy)

  Scenario: Preview promotion from draft to test
    When I send a GET request to "/_plugins/_content_manager/promote?space=draft"
    Then the response status code should be 200
    And the response body should contain a "changes" object
    And the changes should list operations with "add", "update", or "remove" per resource type
    And the resource types should include "integrations", "decoders", "rules", "kvdbs", "filters", "policy"

  Scenario: Preview promotion from test to custom
    Given content has been promoted from draft to test
    When I send a GET request to "/_plugins/_content_manager/promote?space=test"
    Then the response status code should be 200
    And the response body should contain a "changes" object

  Scenario: Preview promotion with missing space parameter
    When I send a GET request to "/_plugins/_content_manager/promote"
    Then the response status code should be 400
    And the response body should contain "Missing [space] field."

  Scenario: Preview promotion with empty space parameter
    When I send a GET request to "/_plugins/_content_manager/promote?space="
    Then the response status code should be 400

  Scenario: Preview promotion with invalid space value
    When I send a GET request to "/_plugins/_content_manager/promote?space=prod"
    Then the response status code should be 400
    And the response body should contain "Unknown space"

  Scenario: Preview promotion from custom (not allowed)
    When I send a GET request to "/_plugins/_content_manager/promote?space=custom"
    Then the response status code should be 400
    And the response body should contain "cannot be promoted"

  Scenario: Preview promotion without authentication
    Given I have no credentials
    When I send a GET request to "/_plugins/_content_manager/promote?space=draft"
    Then the response status code should be 401
