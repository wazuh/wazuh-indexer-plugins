@content-manager @decoders @requires-integration
Feature: Create Decoder
  As a Wazuh user
  I want to create a new decoder linked to an integration in draft space
  So that the engine can use it for log processing

  Background:
    Given Wazuh Indexer is running
    And all draft decoders have been cleaned up
    And an integration exists in draft space with a known ID

  Scenario: Successfully create a decoder
    When I send a POST request to "/_plugins/_content_manager/decoders" with body:
      """
      {
        "integration": "{integration_id}",
        "resource": {
          "enabled": true,
          "metadata": {
            "author": {
              "name": "Wazuh, Inc."
            },
            "compatibility": "All wazuh events.",
            "description": "Base decoder to process Wazuh message format.",
            "module": "wazuh",
            "references": [
              "https://documentation.wazuh.com/"
            ],
            "title": "Wazuh message decoder",
            "versions": [
              "Wazuh 5.*"
            ]
          },
          "name": "decoder/core-wazuh-message/0",
          "check": [
            {
              "tmp_json.event.action": "string_equal(\"netflow_flow\")"
            }
          ],
          "normalize": [
            {
              "map": [
                {
                  "@timestamp": "get_date()"
                }
              ]
            }
          ]
        }
      }
      """
    Then the response status code should be 201
    And the response body should contain the decoder ID
    And the decoder should exist in the ".cti-decoders"
    And the document "space.name" field should be "draft"
    And the document should have a non-empty "hash.sha256" field
    And the decoder ID should be listed in the integration's "decoders" list
    And the draft policy "space.hash.sha256" should have been updated

  Scenario: Create a decoder without an integration reference
    When I send a POST request to "/_plugins/_content_manager/decoders" with body:
      """
      {
        "resource": {
          "enabled": true,
          "name": "decoder/test/0"
        }
      }
      """
    Then the response status code should be 400
    And the response body should contain "Missing [integration] field."

  Scenario: Create a decoder with an explicit id in the resource
    When I send a POST request to "/_plugins/_content_manager/decoders" with body:
      """
      {
        "integration": "{integration_id}",
        "resource": {
          "id": "custom-id",
          "enabled": true,
          "name": "decoder/test/0"
        }
      }
      """
    Then the response status code should be 400

  Scenario: Create a decoder with an integration not in draft space
    When I send a POST request to "/_plugins/_content_manager/decoders" with body:
      """
      {
        "integration": "{non_draft_integration_id}",
        "resource": {
          "enabled": true,
          "name": "decoder/test/0"
        }
      }
      """
    Then the response status code should be 400
    And the response body should contain "is not in draft space"

  Scenario: Create a decoder with missing resource object
    When I send a POST request to "/_plugins/_content_manager/decoders" with body:
      """
      {
        "integration": "{integration_id}"
      }
      """
    Then the response status code should be 400

  Scenario: Create a decoder with empty body
    When I send a POST request to "/_plugins/_content_manager/decoders" with an empty body
    Then the response status code should be 400

  Scenario: Create a decoder without authentication
    Given I have no credentials
    When I send a POST request to "/_plugins/_content_manager/decoders" with a valid payload
    Then the response status code should be 401
