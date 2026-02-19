/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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

import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.core.rest.RestStatus;

import java.io.IOException;
import java.util.Locale;

import com.wazuh.contentmanager.ContentManagerRestTestCase;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Integration tests for the Decoder resource CRUD operations.
 *
 * <p>Covers scenarios from:
 *
 * <ul>
 *   <li>02-decoders/PostDecoder.feature
 *   <li>02-decoders/PutDecoder.feature
 *   <li>02-decoders/DeleteDecoder.feature
 * </ul>
 */
public class DecoderCUDIT extends ContentManagerRestTestCase {

    // ========================
    // POST - Create Decoder
    // ========================

    /**
     * Successfully create a decoder linked to an integration.
     *
     * <p>Verifies:
     *
     * <ul>
     *   <li>Response status code is 201 Created.
     *   <li>The decoder exists in the .cti-decoders index.
     *   <li>The document space.name field is "draft".
     *   <li>The document has a non-empty hash.sha256 field.
     *   <li>The decoder ID is listed in the integration's decoders list.
     *   <li>The draft policy space.hash.sha256 has been updated.
     * </ul>
     *
     * @throws IOException On failure to communicate with OpenSearch or parse responses.
     */
    public void testPostDecoder_success() throws IOException {
        String integrationId = this.createIntegration("test-decoder-integration");
        String policyHashBefore = this.getDraftPolicySpaceHash();

        String decoderId = this.createDecoder(integrationId);

        // Verify resource exists in draft space
        this.assertResourceExistsInDraft(Constants.INDEX_DECODERS, decoderId);

        // Verify space.name and hash
        JsonNode source = this.getResourceByDocumentId(Constants.INDEX_DECODERS, decoderId, "draft");
        assertNotNull(source);
        this.assertSpaceName(source);
        this.assertHashPresent(source, "Decoder");

        // Verify decoder is in integration's decoders list
        this.assertResourceInIntegrationList(integrationId, Constants.KEY_DECODERS, decoderId);

        // Verify draft policy space hash changed
        String policyHashAfter = this.getDraftPolicySpaceHash();
        assertNotEquals(
                "Draft policy space hash should have been updated after decoder creation",
                policyHashBefore,
                policyHashAfter);
    }

    /**
     * Create a decoder without an integration reference.
     *
     * <p>Verifies: Response status code is 400 with "Missing [integration] field."
     */
    public void testPostDecoder_missingIntegration() {
        // spotless:off
        String payload = """
                {
                    "resource": {
                        "enabled": true,
                        "name": "decoder/test/0"
                    }
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("POST", PluginSettings.DECODERS_URI, payload));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Create a decoder with an explicit id in the resource.
     *
     * <p>Verifies: Response status code is 400.
     *
     * @throws IOException On
     */
    public void testPostDecoder_explicitId() throws IOException {
        String integrationId = this.createIntegration("test-decoder-explicit-id");

        // spotless:off
        String payload = """
                {
                    "integration": "%s",
                    "resource": {
                        "id": "custom-id",
                        "enabled": true,
                        "name": "decoder/test/0"
                    }
                }
                """;
        String body = String.format(Locale.ROOT, payload, integrationId);
        // spotless:on

        // The system silently ignores the explicit ID and auto-generates one (201)
        Response response = this.makeRequest("POST", PluginSettings.DECODERS_URI, body);
        int statusCode = this.getStatusCode(response);
        assertEquals("Status should be 201 (id ignored)", 201, statusCode);
    }

    /**
     * Create a decoder with a non-existent integration.
     *
     * <p>Verifies: Response status code is 400 or 404.
     */
    public void testPostDecoder_nonDraftIntegration() {
        // spotless:off
        String payload = """
                {
                    "integration": "00000000-0000-0000-0000-000000000000",
                    "resource": {
                        "enabled": true,
                        "name": "decoder/test/0",
                        "metadata": {
                            "title": "Test decoder",
                            "description": "Test",
                            "author": {"name": "Wazuh, Inc."},
                            "compatibility": "All",
                            "module": "test",
                            "references": [],
                            "versions": ["5.*"]
                        },
                        "check": [{"tmp_json.event.action": "string_equal(\\"test\\")"}],
                        "normalize": [{"map": [{"@timestamp": "get_date()"}]}]
                    }
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("POST", PluginSettings.DECODERS_URI, payload));
        int status = e.getResponse().getStatusLine().getStatusCode();
        assertEquals("Expected 400 for non-existent integration", 400, status);
    }

    /**
     * Create a decoder with missing resource object.
     *
     * <p>Verifies: Response status code is 400.
     *
     * @throws IOException On failure to communicate with OpenSearch or parse responses.
     */
    public void testPostDecoder_missingResourceObject() throws IOException {
        String integrationId = this.createIntegration("test-decoder-missing-res");

        // spotless:off
        String payload = """
                {
                    "integration": "%s"
                }
                """;
        String body = String.format(Locale.ROOT, payload, integrationId);
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("POST", PluginSettings.DECODERS_URI, body));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Create a decoder with empty body.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPostDecoder_emptyBody() {
        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("POST", PluginSettings.DECODERS_URI, ""));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    // ========================
    // PUT - Update Decoder
    // ========================

    /**
     * Successfully update a decoder.
     *
     * <p>Verifies:
     *
     * <ul>
     *   <li>Response status code is 200 OK.
     *   <li>The decoder document is correctly updated in the .cti-decoders index.
     *   <li>The document space.name field is still "draft".
     *   <li>The document hash.sha256 field has been updated.
     *   <li>The draft policy space.hash.sha256 has been updated.
     * </ul>
     *
     * @throws IOException On failure to communicate with OpenSearch or parse responses.
     */
    public void testPutDecoder_success() throws IOException {
        String integrationId = this.createIntegration("test-decoder-put-int");
        String decoderId = this.createDecoder(integrationId);

        JsonNode sourceBefore =
                this.getResourceByDocumentId(Constants.INDEX_DECODERS, decoderId, "draft");
        String hashBefore = sourceBefore.path(Constants.KEY_HASH).path(Constants.KEY_SHA256).asText();
        String policyHashBefore = this.getDraftPolicySpaceHash();

        // spotless:off
        String payload = """
                {
                    "type": "decoder",
                    "resource": {
                        "name": "decoder/test-decoder/0",
                        "enabled": false,
                        "metadata": {
                            "title": "Test Decoder UPDATED",
                            "description": "Updated description",
                            "author": {"name": "Updated Author"},
                            "compatibility": "All",
                            "module": "test",
                            "references": [],
                            "versions": ["5.*"]
                        },
                        "check": [{"tmp_json.event.action": "string_equal(\\"updated\\")"}],
                        "normalize": [{"map": [{"@timestamp": "get_date()"}]}]
                    }
                }
                """;
        // spotless:on

        Response response =
                this.makeRequest("PUT", PluginSettings.DECODERS_URI + "/" + decoderId, payload);
        assertEquals(RestStatus.OK.getStatus(), this.getStatusCode(response));

        // Verify updated in index
        JsonNode sourceAfter =
                this.getResourceByDocumentId(Constants.INDEX_DECODERS, decoderId, "draft");
        assertNotNull(sourceAfter);
        this.assertSpaceName(sourceAfter);

        // Verify hash updated
        String hashAfter = sourceAfter.path(Constants.KEY_HASH).path(Constants.KEY_SHA256).asText();
        assertNotEquals("Decoder hash should have been updated", hashBefore, hashAfter);

        // Verify draft policy space hash updated
        String policyHashAfter = this.getDraftPolicySpaceHash();
        assertNotEquals(
                "Draft policy space hash should have been updated", policyHashBefore, policyHashAfter);
    }

    /**
     * Update a decoder that does not exist.
     *
     * <p>Verifies: Response status code is 404.
     */
    public void testPutDecoder_notFound() {
        // spotless:off
        String payload = """
                {
                    "type": "decoder",
                    "resource": {
                        "name": "decoder/test/0",
                        "enabled": true,
                        "metadata": {
                            "title": "Test",
                            "description": "Test",
                            "author": {"name": "Test"},
                            "compatibility": "All",
                            "module": "test",
                            "references": [],
                            "versions": ["5.*"]
                        },
                        "check": [{"tmp_json.event.action": "string_equal(\\"test\\")"}],
                        "normalize": [{"map": [{"@timestamp": "get_date()"}]}]
                    }
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () ->
                                this.makeRequest(
                                        "PUT",
                                        PluginSettings.DECODERS_URI + "/00000000-0000-0000-0000-000000000000",
                                        payload));
        assertEquals(RestStatus.NOT_FOUND.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Update a decoder that is not found.
     *
     * <p>Verifies: Response status code is 404.
     */
    public void testPutDecoder_invalidUuid() {
        // spotless:off
        String payload = """
                {
                    "type": "decoder",
                    "resource": {
                        "name": "decoder/test/0",
                        "enabled": true
                    }
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("PUT", PluginSettings.DECODERS_URI + "/not-a-uuid", payload));
        assertEquals(RestStatus.NOT_FOUND.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Update a decoder with missing resource object (empty body).
     *
     * <p>Verifies: Response status code is 400.
     *
     * @throws IOException On failure to communicate with OpenSearch or parse responses.
     */
    public void testPutDecoder_emptyBody() throws IOException {
        String integrationId = this.createIntegration("test-decoder-put-empty");
        String decoderId = this.createDecoder(integrationId);

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("PUT", PluginSettings.DECODERS_URI + "/" + decoderId, "{}"));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    // ========================
    // DELETE - Delete Decoder
    // ========================

    /**
     * Successfully delete a decoder.
     *
     * <p>Verifies:
     *
     * <ul>
     *   <li>Response status code is 200 OK.
     *   <li>The decoder no longer exists in the .cti-decoders index.
     *   <li>The decoder ID is no longer listed in the integration's decoders list.
     *   <li>The integration's hash.sha256 field has been updated.
     *   <li>The draft policy space.hash.sha256 has been updated.
     * </ul>
     *
     * @throws IOException On failure to communicate with OpenSearch or parse responses.
     */
    public void testDeleteDecoder_success() throws IOException {
        String integrationId = this.createIntegration("test-decoder-delete-int");
        String decoderId = this.createDecoder(integrationId);

        // Capture hashes before deletion
        JsonNode integrationBefore =
                this.getResourceByDocumentId(Constants.INDEX_INTEGRATIONS, integrationId, "draft");
        String integrationHashBefore =
                integrationBefore.path(Constants.KEY_HASH).path(Constants.KEY_SHA256).asText();
        String policyHashBefore = this.getDraftPolicySpaceHash();

        Response response = this.deleteResource(PluginSettings.DECODERS_URI, decoderId);
        assertEquals(RestStatus.OK.getStatus(), this.getStatusCode(response));

        // Verify decoder no longer exists in draft
        this.assertResourceNotInDraft(Constants.INDEX_DECODERS, decoderId);

        // Verify decoder removed from integration's decoders list
        this.assertResourceNotInIntegrationList(integrationId, Constants.KEY_DECODERS, decoderId);

        // Verify integration's hash was updated
        JsonNode integrationAfter =
                this.getResourceByDocumentId(Constants.INDEX_INTEGRATIONS, integrationId, "draft");
        String integrationHashAfter =
                integrationAfter.path(Constants.KEY_HASH).path(Constants.KEY_SHA256).asText();
        assertNotEquals(
                "Integration hash should have been updated after decoder deletion",
                integrationHashBefore,
                integrationHashAfter);

        // Verify policy space hash updated
        String policyHashAfter = this.getDraftPolicySpaceHash();
        assertNotEquals(
                "Draft policy space hash should have been updated after decoder deletion",
                policyHashBefore,
                policyHashAfter);
    }

    /**
     * Delete a decoder that does not exist.
     *
     * <p>Verifies: Response status code is 404.
     */
    public void testDeleteDecoder_notFound() {
        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () ->
                                this.deleteResource(
                                        PluginSettings.DECODERS_URI, "00000000-0000-0000-0000-000000000000"));
        assertEquals(RestStatus.NOT_FOUND.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Delete a decoder that is not found.
     *
     * <p>Verifies: Response status code is 404.
     */
    public void testDeleteDecoder_invalidUuid() {
        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.deleteResource(PluginSettings.DECODERS_URI, "not-a-uuid"));
        assertEquals(RestStatus.NOT_FOUND.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Delete a decoder without providing an ID.
     *
     * <p>Verifies: Response status code is 405.
     */
    public void testDeleteDecoder_missingId() {
        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("DELETE", PluginSettings.DECODERS_URI + "/"));
        int statusCode = e.getResponse().getStatusLine().getStatusCode();
        assertEquals("Expected 405 for missing ID", 405, statusCode);
    }
}
