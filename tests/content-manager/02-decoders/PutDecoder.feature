@content-manager @decoders @requires-integration
Feature: Update Decoder
  As a Wazuh user
  I want to update an existing decoder in draft space
  So that I can modify its configuration

  Background:
    Given Wazuh Indexer is running
    And all draft decoders have been cleaned up
    And a decoder exists in draft space with a known ID

  Scenario: Successfully update a decoder
    When I send a PUT request to "/_plugins/_content_manager/decoders/{decoder_id}" with body:
      """
      {
        "type": "decoder",
        "resource": {
          "name": "decoder/test-decoder/0",
          "enabled": false,
          "metadata": {
            "title": "Test Decoder UPDATED",
            "description": "Updated descriptions",
            "author": {
              "name": "Hello there"
            }
          },
          "decoder": "<decoder>\n  <prematch>updated pattern</prematch>\n</decoder>"
        }
      }
      """
    Then the response status code should be 200
    And the response body should contain the decoder ID

  Scenario: Update a decoder that does not exist
    When I send a PUT request to "/_plugins/_content_manager/decoders/00000000-0000-0000-0000-000000000000" with a valid payload
    Then the response status code should be 404

  Scenario: Update a decoder with an invalid UUID
    When I send a PUT request to "/_plugins/_content_manager/decoders/not-a-uuid" with a valid payload
    Then the response status code should be 400
    And the response body should contain "is not a valid UUID"

  Scenario: Update a decoder not in draft space
    Given the decoder exists only in test or custom space
    When I send a PUT request to "/_plugins/_content_manager/decoders/{decoder_id}" with a valid payload
    Then the response status code should be 400
    And the response body should contain "is not in draft space"

  Scenario: Update a decoder with missing resource object
    When I send a PUT request to "/_plugins/_content_manager/decoders/{decoder_id}" with body:
      """
      {}
      """
    Then the response status code should be 400

  Scenario: Update a decoder with empty body
    When I send a PUT request to "/_plugins/_content_manager/decoders/{decoder_id}" with an empty body
    Then the response status code should be 400

  Scenario: Update a decoder without authentication
    Given I have no credentials
    When I send a PUT request to "/_plugins/_content_manager/decoders/{decoder_id}" with a valid payload
    Then the response status code should be 401
