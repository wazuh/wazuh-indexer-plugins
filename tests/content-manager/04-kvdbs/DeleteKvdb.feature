@content-manager @kvdbs @requires-integration
Feature: Delete KVDB
  As a Wazuh user
  I want to delete a key-value database from draft space
  So that it is removed from the content catalog

  Background:
    Given Wazuh Indexer is running
    And all draft kvdbs have been cleaned up
    And a KVDB exists in draft space with a known ID

  Scenario: Successfully delete a KVDB
    When I send a DELETE request to "/_plugins/_content_manager/kvdbs/{kvdb_id}"
    Then the response status code should be 200
    And the response body should contain the KVDB ID

  Scenario: Delete a KVDB that does not exist
    When I send a DELETE request to "/_plugins/_content_manager/kvdbs/00000000-0000-0000-0000-000000000000"
    Then the response status code should be 404

  Scenario: Delete a KVDB with an invalid UUID
    When I send a DELETE request to "/_plugins/_content_manager/kvdbs/not-a-uuid"
    Then the response status code should be 400
    And the response body should contain "is not a valid UUID"

  Scenario: Delete a KVDB not in draft space
    Given the KVDB exists only in test or custom space
    When I send a DELETE request to "/_plugins/_content_manager/kvdbs/{kvdb_id}"
    Then the response status code should be 400
    And the response body should contain "is not in draft space"

  Scenario: Delete a KVDB without providing an ID
    When I send a DELETE request to "/_plugins/_content_manager/kvdbs/"
    Then the response status code should be 400

  Scenario: Delete a KVDB without authentication
    Given I have no credentials
    When I send a DELETE request to "/_plugins/_content_manager/kvdbs/{kvdb_id}"
    Then the response status code should be 401

  Scenario: Verify KVDB is removed from index after deletion
    Given a KVDB has been deleted with a known ID
    When I send a GET request to "/.cti-kvdbs/_doc/{kvdb_id}"
    Then the response status code should be 404
