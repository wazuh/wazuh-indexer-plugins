@content-manager @policy @initialization
Feature: Policy Initialization
  As a Wazuh user
  I want to verify that all space policies are automatically generated
  So that the content promotion mechanism works correctly from a fresh environment

  Background:
    Given Wazuh Indexer is running
    And the CTI catalog sync has completed successfully

  Scenario: The ".cti-policies" index exists
    When I send a GET request to "/.cti-policies"
    Then the response status code should be 200

  Scenario: Exactly four policy documents exist (one per space)
    When I search the ".cti-policies" index for all documents
    Then the response status code should be 200
    And the total number of hits should be 4
    And there is one document for each space: "draft", "test", "custom", and "standard"

  Scenario: Standard policy has a different document ID than draft/test/custom
    When I search the ".cti-policies" index with filter "space.name" equal to "draft"
    And I store the "id" field as "shared_policy_id"
    And I search the ".cti-policies" index with filter "space.name" equal to "standard"
    Then the "id" field should NOT equal "{shared_policy_id}"

  Scenario: Draft, test, and custom policies start with empty integrations and root_decoder
    When I search the ".cti-policies" index with filter "space.name" equal to "draft"
    Then the document field "integrations" should be an empty list
    And the document field "root_decoder" should be empty
    When I search the ".cti-policies" index with filter "space.name" equal to "test"
    Then the document field "integrations" should be an empty list
    And the document field "root_decoder" should be empty
    When I search the ".cti-policies" index with filter "space.name" equal to "custom"
    Then the document field "integrations" should be an empty list
    And the document field "root_decoder" should be empty

  Scenario: Standard policy contains integrations and a root_decoder from CTI
    When I search the ".cti-policies" index with filter "space.name" equal to "standard"
    Then the document field "integrations" should be a non-empty list
    And the document field "root_decoder" should be non-empty

  Scenario: Each policy document contains the expected structure
    When I search the ".cti-policies" index with filter "space.name" equal to "draft"
    Then the response status code should be 200
    And the document should contain field "id"
    And the document should contain field "title"
    And the document should contain field "date"
    And the document should contain field "modified"
    And the document should contain field "root_decoder"
    And the document should contain field "integrations"
    And the document should contain field "filters"
    And the document should contain field "enrichments"
    And the document should contain field "author"
    And the document should contain field "description"
    And the document should contain field "documentation"
    And the document should contain field "references"
    And the document should contain field "space.name"
    And the document should contain field "space.hash.sha256"
    And the document should contain field "hash.sha256"

  Scenario: Each policy has a valid SHA-256 hash
    When I search the ".cti-policies" index for all documents
    Then the response status code should be 200
    And each document should have a non-empty "hash.sha256" field
    And each document should have a non-empty "space.hash.sha256" field
