@content-manager @logtest
Feature: Log Test
  As a Wazuh user
  I want to send log events to the engine for testing
  So that I can validate decoder and rule behavior against sample data

  Background:
    Given Wazuh Indexer is running
    And the engine is available

  Scenario: Successfully test a log event
    When I send a POST request to "/_plugins/_content_manager/logtest" with body:
      """
      {
        "queue": 1,
        "location": "/var/log/auth.log",
        "agent_metadata": {},
        "event": "Dec 19 12:00:00 host sshd[123]: Failed password for root from 10.0.0.1 port 12345 ssh2",
        "trace_level": "NONE"
      }
      """
    Then the response status code should be 200
    And the response body should contain the engine processing result

  Scenario: Send log test with empty body
    When I send a POST request to "/_plugins/_content_manager/logtest" with an empty body
    Then the response status code should be 400
    And the response body should contain "Invalid request body."

  Scenario: Send log test with invalid JSON
    When I send a POST request to "/_plugins/_content_manager/logtest" with invalid JSON
    Then the response status code should be 400

  Scenario: Send log test without authentication
    Given I have no credentials
    When I send a POST request to "/_plugins/_content_manager/logtest" with a valid payload
    Then the response status code should be 401
