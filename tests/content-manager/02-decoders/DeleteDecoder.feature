@content-manager @decoders @requires-integration
Feature: Delete Decoder
  As a Wazuh user
  I want to delete a decoder from draft space
  So that it is removed from the content catalog

  Background:
    Given Wazuh Indexer is running
    And all draft decoders have been cleaned up
    And a decoder exists in draft space with a known ID

  Scenario: Successfully delete a decoder
    When I send a DELETE request to "/_plugins/_content_manager/decoders/{decoder_id}"
    Then the response status code should be 200
    And the response body should contain the decoder ID
    And the decoder should no longer exist in the ".cti-decoders" index
    And the decoder ID should no longer be listed in the integration's "decoders" list
    And the integration's "hash.sha256" field should have been updated
    And the draft policy "space.hash.sha256" should have been updated

  Scenario: Delete a decoder that does not exist
    When I send a DELETE request to "/_plugins/_content_manager/decoders/00000000-0000-0000-0000-000000000000"
    Then the response status code should be 404

  Scenario: Delete a decoder with an invalid UUID
    When I send a DELETE request to "/_plugins/_content_manager/decoders/not-a-uuid"
    Then the response status code should be 400
    And the response body should contain "is not a valid UUID"

  Scenario: Delete a decoder not in draft space
    Given the decoder exists only in test or custom space
    When I send a DELETE request to "/_plugins/_content_manager/decoders/{decoder_id}"
    Then the response status code should be 400
    And the response body should contain "is not in draft space"

  Scenario: Delete a decoder without providing an ID
    When I send a DELETE request to "/_plugins/_content_manager/decoders/"
    Then the response status code should be 400

  Scenario: Delete a decoder without authentication
    Given I have no credentials
    When I send a DELETE request to "/_plugins/_content_manager/decoders/{decoder_id}"
    Then the response status code should be 401

  Scenario: Verify decoder is removed from index after deletion
    Given a decoder has been deleted with a known ID
    When I send a GET request to "/.cti-decoders/_doc/{decoder_id}"
    Then the response status code should be 404
