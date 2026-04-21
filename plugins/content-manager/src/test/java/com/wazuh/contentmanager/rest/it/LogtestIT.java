/*
 * Copyright (C) 2026, Wazuh Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.wazuh.contentmanager.rest.it;

import com.fasterxml.jackson.databind.JsonNode;

import org.apache.hc.core5.http.ParseException;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.core.rest.RestStatus;

import java.io.IOException;
import java.util.Locale;

import com.wazuh.contentmanager.ContentManagerRestTestCase;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Integration tests for the end-to-end logtest workflow.
 *
 * <p>Covers scenarios from:
 *
 * <ul>
 *   <li>06-logtest/PostLogtest.feature
 * </ul>
 *
 * <p>These tests exercise the full REST layer (request validation, integration lookup, and response
 * structure) against a live OpenSearch test cluster. Since the Wazuh Engine is not available in the
 * test environment, engine-dependent scenarios validate graceful error handling and correct
 * response structure rather than successful engine processing.
 */
public class LogtestIT extends ContentManagerRestTestCase {

    // ========================
    // Payload Helpers
    // ========================

    /**
     * Builds a valid logtest request payload.
     *
     * @param integrationId the integration ID to include in the request
     * @return JSON string with all required fields
     */
    private String validPayload(String integrationId) {
        // spotless:off
        return String.format(Locale.ROOT, """
                {
                    "integration": "%s",
                    "space": "test",
                    "queue": 1,
                    "location": "/var/log/auth.log",
                    "event": "Dec 19 12:00:00 host sshd[123]: Failed password for root from 10.0.0.1 port 12345 ssh2",
                    "trace_level": "NONE"
                }
                """, integrationId);
        // spotless:on
    }

    // ========================
    // Request Validation Tests
    // ========================

    /**
     * Sending a POST with an empty body returns 400.
     *
     * @throws IOException on communication error
     */
    public void testEmptyBody400() throws IOException {
        ResponseException ex =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("POST", PluginSettings.LOGTEST_URI, ""));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), ex.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Sending a POST with invalid JSON returns 400.
     *
     * @throws IOException on communication error
     */
    public void testInvalidJson400() throws IOException {
        ResponseException ex =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("POST", PluginSettings.LOGTEST_URI, "{not valid json"));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), ex.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Sending a POST without the required "integration" field returns 200, and the detection phase is
     * skipped.
     *
     * @throws IOException on communication error
     */
    public void testMissingIntegrationField200() throws IOException, ParseException {
        // spotless:off
        String payload = """
                {
                    "space": "test",
                    "queue": 1,
                    "location": "/var/log/auth.log",
                    "event": "test event"
                }
                """;
        // spotless:on

        Response response = this.makeRequest("POST", PluginSettings.LOGTEST_URI, payload);
        assertEquals(RestStatus.OK.getStatus(), this.getStatusCode(response));

        JsonNode body = this.responseAsJson(response);
        JsonNode detectionNode = body.path("message").path("detection");

        assertEquals("skipped", detectionNode.path("status").asText());
        assertEquals("integration field not provided", detectionNode.path("reason").asText());
    }

    /**
     * Sending a POST without the required "space" field returns 400.
     *
     * @throws IOException on communication error
     */
    public void testMissingSpaceField400() throws IOException {
        // spotless:off
        String payload = """
                {
                    "integration": "some-id",
                    "queue": 1,
                    "location": "/var/log/auth.log",
                    "event": "test event"
                }
                """;
        // spotless:on
        ResponseException ex =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("POST", PluginSettings.LOGTEST_URI, payload));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), ex.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Sending a POST with a non-test space returns 400.
     *
     * @throws IOException on communication error
     */
    public void testNonTestSpace400() throws IOException {
        // spotless:off
        String payload = """
                {
                    "integration": "some-id",
                    "space": "draft",
                    "queue": 1,
                    "location": "/var/log/auth.log",
                    "event": "test event"
                }
                """;
        // spotless:on
        ResponseException ex =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("POST", PluginSettings.LOGTEST_URI, payload));
        int status = ex.getResponse().getStatusLine().getStatusCode();
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), status);
    }

    // ========================
    // Integration Lookup Tests
    // ========================

    /**
     * Sending a logtest request with a non-existent integration ID returns 400 with an appropriate
     * error message.
     *
     * @throws IOException on communication error
     */
    public void testIntegrationNotFound400() throws IOException {
        String payload = validPayload("non-existent-integration-id");
        ResponseException ex =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("POST", PluginSettings.LOGTEST_URI, payload));
        int status = ex.getResponse().getStatusLine().getStatusCode();
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), status);
    }

    // ========================
    // End-to-End Workflow Tests
    // ========================

    /**
     * Full logtest workflow: create integration and rule in draft, promote to test, then run logtest.
     *
     * <p>Since the Wazuh Engine is not running in the test cluster, the engine processing will fail.
     * This test validates that:
     *
     * <ul>
     *   <li>The endpoint accepts the request (HTTP 200)
     *   <li>The response contains both normalization and detection
     *   <li>The normalization status indicates an error (engine unavailable)
     *   <li>The detection is skipped when the engine fails
     * </ul>
     *
     * @throws IOException on communication error
     */
    public void testLogtestWithPromotedIntegration() throws IOException {
        // 1. Create integration and rule in draft
        String integrationTitle = "logtest-e2e-test";
        String integrationId = this.createIntegration(integrationTitle);
        this.createRule(integrationId, integrationTitle);

        // 2. Promote draft → test
        this.promoteDraftToTest();

        // 3. Verify integration exists in test space
        this.assertResourceExistsInSpace(Constants.INDEX_INTEGRATIONS, integrationId, "test");

        // 4. Send logtest request
        String payload = validPayload(integrationId);
        Response response = this.makeRequest("POST", PluginSettings.LOGTEST_URI, payload);
        assertEquals(RestStatus.OK.getStatus(), this.getStatusCode(response));

        // 5. Validate response structure
        JsonNode body = this.responseAsJson(response);
        JsonNode messageNode = body.path("message");

        assertTrue("Response should contain normalization", messageNode.has("normalization"));
        assertTrue("Response should contain detection", messageNode.has("detection"));

        // Engine is not available in test cluster, so it should report error
        JsonNode engineResult = messageNode.path("normalization");
        assertEquals("error", engineResult.path("status").asText());

        // SAP should be skipped when engine fails
        JsonNode saResult = messageNode.path("detection");
        assertEquals("skipped", saResult.path("status").asText());
    }

    /**
     * Logtest with an integration that has no rules still returns a valid response structure.
     *
     * @throws IOException on communication error
     */
    public void testLogtestIntegrationWithNoRules() throws IOException {
        // 1. Create integration without rules
        String integrationTitle = "logtest-no-rules-test";
        String integrationId = this.createIntegration(integrationTitle);

        // 2. Promote to test
        this.promoteDraftToTest();

        // 3. Send logtest request
        String payload = validPayload(integrationId);
        Response response = this.makeRequest("POST", PluginSettings.LOGTEST_URI, payload);
        assertEquals(RestStatus.OK.getStatus(), this.getStatusCode(response));

        // 4. Validate response structure
        JsonNode body = this.responseAsJson(response);
        JsonNode messageNode = body.path("message");

        assertTrue("Response should contain normalization", messageNode.has("normalization"));
        assertTrue("Response should contain detection", messageNode.has("detection"));
    }

    /**
     * Logtest for an integration that exists only in draft (not promoted to test) returns 400.
     *
     * @throws IOException on communication error
     */
    public void testLogtestDraftOnlyIntegration400() throws IOException {
        String integrationTitle = "logtest-draft-only-test";
        String integrationId = this.createIntegration(integrationTitle);

        String payload = validPayload(integrationId);
        ResponseException ex =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("POST", PluginSettings.LOGTEST_URI, payload));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), ex.getResponse().getStatusLine().getStatusCode());
    }

    // ========================
    // Promote Helper
    // ========================

    /**
     * Promotes all resources from draft to test space.
     *
     * @throws IOException on communication error
     */
    private void promoteDraftToTest() throws IOException {
        // Get promotion preview
        Response previewResponse =
                this.makeRequest(
                        "GET", PluginSettings.PROMOTE_URI, null, java.util.Map.of("space", "draft"));
        assertEquals(RestStatus.OK.getStatus(), this.getStatusCode(previewResponse));

        JsonNode preview = this.responseAsJson(previewResponse);
        JsonNode changes = preview.path("changes");
        String changesJson = MAPPER.writeValueAsString(changes);

        // Execute promotion
        // spotless:off
        String promotePayload = String.format(Locale.ROOT, """
                {
                    "space": "draft",
                    "changes": %s
                }
                """, changesJson);
        // spotless:on
        Response promoteResponse = this.makeRequest("POST", PluginSettings.PROMOTE_URI, promotePayload);
        assertEquals(RestStatus.OK.getStatus(), this.getStatusCode(promoteResponse));

        // Refresh indices so promoted documents are searchable
        this.refreshIndex(Constants.INDEX_INTEGRATIONS);
        this.refreshIndex(Constants.INDEX_RULES);
    }
}
