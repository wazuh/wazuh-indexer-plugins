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
 * Integration tests for the KVDB resource CRUD operations.
 *
 * <p>Covers scenarios from:
 *
 * <ul>
 *   <li>04-kvdbs/PostKvdb.feature
 *   <li>04-kvdbs/PutKvdb.feature
 *   <li>04-kvdbs/DeleteKvdb.feature
 * </ul>
 */
public class KvdbCUDIT extends ContentManagerRestTestCase {

    // ========================
    // POST - Create KVDB
    // ========================

    /**
     * Successfully create a KVDB linked to an integration.
     *
     * <p>Verifies:
     *
     * <ul>
     *   <li>Response status code is 201 Created.
     *   <li>The KVDB exists in the .cti-kvdbs index.
     *   <li>The document space.name field is "draft".
     *   <li>The document has a non-empty hash.sha256 field.
     *   <li>The KVDB ID is listed in the integration's kvdbs list.
     *   <li>The draft policy space.hash.sha256 has been updated.
     * </ul>
     *
     * @throws IOException On request failure.
     */
    public void testPostKvdb_success() throws IOException {
        String integrationId = this.createIntegration("test-kvdb-integration");
        String policyHashBefore = this.getDraftPolicySpaceHash();

        String kvdbId = this.createKvdb(integrationId);

        // Verify resource exists in draft space
        this.assertResourceExistsInDraft(Constants.INDEX_KVDBS, kvdbId);

        // Verify space.name and hash
        JsonNode source = this.getResourceByDocumentId(Constants.INDEX_KVDBS, kvdbId, "draft");
        assertNotNull(source);
        this.assertSpaceName(source);
        this.assertHashPresent(source, "KVDB");

        // Verify KVDB is in integration's kvdbs list
        this.assertResourceInIntegrationList(integrationId, Constants.KEY_KVDBS, kvdbId);

        // Verify draft policy space hash changed
        String policyHashAfter = this.getDraftPolicySpaceHash();
        assertNotEquals(
                "Draft policy space hash should have been updated after KVDB creation",
                policyHashBefore,
                policyHashAfter);
    }

    /**
     * Create a KVDB with missing title.
     *
     * <p>Verifies: Response status code is 400.
     *
     * @throws IOException On request failure.
     */
    public void testPostKvdb_missingTitle() throws IOException {
        String integrationId = this.createIntegration("test-kvdb-no-title");

        // spotless:off
        String payload = """
                {
                    "integration": "%s",
                    "resource": {
                        "name": "test",
                        "author": "Wazuh Inc.",
                        "content": {"key": "value"}
                    }
                }
                """;
        String body = String.format(Locale.ROOT, payload, integrationId);
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("POST", PluginSettings.KVDBS_URI, body));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Create a KVDB with missing author.
     *
     * <p>Verifies: Response status code is 400.
     *
     * @throws IOException On request failure.
     */
    public void testPostKvdb_missingAuthor() throws IOException {
        String integrationId = this.createIntegration("test-kvdb-no-author");

        // spotless:off
        String payload = """
                {
                    "integration": "%s",
                    "resource": {
                        "name": "test",
                        "title": "Test KVDB",
                        "content": {"key": "value"}
                    }
                }
                """;
        String body = String.format(Locale.ROOT, payload, integrationId);
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("POST", PluginSettings.KVDBS_URI, body));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Create a KVDB with missing content.
     *
     * <p>Verifies: Response status code is 400.
     *
     * @throws IOException On request failure.
     */
    public void testPostKvdb_missingContent() throws IOException {
        String integrationId = this.createIntegration("test-kvdb-no-content");

        // spotless:off
        String payload = """
                {
                    "integration": "%s",
                    "resource": {
                        "name": "test",
                        "title": "Test KVDB",
                        "author": "Wazuh Inc."
                    }
                }
                """;
        String body = String.format(Locale.ROOT, payload, integrationId);
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("POST", PluginSettings.KVDBS_URI, body));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Create a KVDB without an integration reference.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPostKvdb_missingIntegration() {
        // spotless:off
        String payload = """
                {
                    "resource": {
                        "name": "test",
                        "title": "Test KVDB",
                        "author": "Wazuh Inc.",
                        "content": {"key": "value"}
                    }
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("POST", PluginSettings.KVDBS_URI, payload));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Create a KVDB with an explicit id in the resource.
     *
     * <p>Verifies: Response status code is 201 (ID is ignored).
     *
     * @throws IOException On request failure.
     */
    public void testPostKvdb_explicitId() throws IOException {
        String integrationId = this.createIntegration("test-kvdb-explicit-id");

        // spotless:off
        String payload = """
                {
                    "integration": "%s",
                    "resource": {
                        "id": "custom-id",
                        "name": "test",
                        "title": "Test KVDB",
                        "author": "Wazuh Inc.",
                        "content": {"key": "value"}
                    }
                }
                """;
        String body = String.format(Locale.ROOT, payload, integrationId);
        // spotless:on

        // The system silently ignores the explicit ID and auto-generates one (201)
        Response response = this.makeRequest("POST", PluginSettings.KVDBS_URI, body);
        int statusCode = this.getStatusCode(response);
        assertEquals("Status should be 201 (id ignored)", 201, statusCode);
    }

    /**
     * Create a KVDB with a non-existent integration.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPostKvdb_nonDraftIntegration() {
        // spotless:off
        String payload = """
                {
                    "integration": "00000000-0000-0000-0000-000000000000",
                    "resource": {
                        "name": "test",
                        "title": "Test KVDB",
                        "author": "Wazuh Inc.",
                        "content": {"key": "value"},
                        "enabled": true,
                        "description": "Test",
                        "documentation": "test",
                        "references": []
                    }
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("POST", PluginSettings.KVDBS_URI, payload));
        int status = e.getResponse().getStatusLine().getStatusCode();
        assertEquals("Expected 400 for non-existent integration", 400, status);
    }

    /**
     * Create a KVDB with empty body.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPostKvdb_emptyBody() {
        ResponseException e =
                expectThrows(
                        ResponseException.class, () -> this.makeRequest("POST", PluginSettings.KVDBS_URI, ""));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    // ========================
    // PUT - Update KVDB
    // ========================

    /**
     * Successfully update a KVDB.
     *
     * <p>Verifies:
     *
     * <ul>
     *   <li>Response status code is 200 OK.
     *   <li>The KVDB document is correctly updated in the .cti-kvdbs index.
     *   <li>The document space.name field is still "draft".
     *   <li>The document hash.sha256 field has been updated.
     *   <li>The draft policy space.hash.sha256 has been updated.
     * </ul>
     *
     * @throws IOException On request failure.
     */
    public void testPutKvdb_success() throws IOException {
        String integrationId = this.createIntegration("test-kvdb-put-int");
        String kvdbId = this.createKvdb(integrationId);

        JsonNode sourceBefore = this.getResourceByDocumentId(Constants.INDEX_KVDBS, kvdbId, "draft");
        String hashBefore = sourceBefore.path(Constants.KEY_HASH).path(Constants.KEY_SHA256).asText();
        String policyHashBefore = this.getDraftPolicySpaceHash();

        // spotless:off
        String payload = """
                {
                    "resource": {
                        "name": "test-UPDATED",
                        "enabled": true,
                        "author": "Wazuh.",
                        "content": {
                            "non_standard_timezones": {
                                "AEST": "Australia/Sydney",
                                "CEST": "Europe/Berlin"
                            }
                        },
                        "description": "UPDATE",
                        "documentation": "UPDATE.doc",
                        "references": ["https://wazuh.com"],
                        "title": "non_standard_timezones-2"
                    }
                }
                """;
        // spotless:on

        Response response = this.makeRequest("PUT", PluginSettings.KVDBS_URI + "/" + kvdbId, payload);
        assertEquals(RestStatus.OK.getStatus(), this.getStatusCode(response));

        // Verify updated in index
        JsonNode sourceAfter = this.getResourceByDocumentId(Constants.INDEX_KVDBS, kvdbId, "draft");
        assertNotNull(sourceAfter);
        this.assertSpaceName(sourceAfter);

        // Verify hash updated
        String hashAfter = sourceAfter.path(Constants.KEY_HASH).path(Constants.KEY_SHA256).asText();
        assertNotEquals("KVDB hash should have been updated", hashBefore, hashAfter);

        // Verify draft policy space hash updated
        String policyHashAfter = this.getDraftPolicySpaceHash();
        assertNotEquals(
                "Draft policy space hash should have been updated", policyHashBefore, policyHashAfter);
    }

    /**
     * Update a KVDB with missing required fields.
     *
     * <p>Verifies: Response status code is 400.
     *
     * @throws IOException On request failure.
     */
    public void testPutKvdb_missingRequiredFields() throws IOException {
        String integrationId = this.createIntegration("test-kvdb-put-missing");
        String kvdbId = this.createKvdb(integrationId);

        // spotless:off
        String payload = """
                {
                    "resource": {
                        "name": "updated"
                    }
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("PUT", PluginSettings.KVDBS_URI + "/" + kvdbId, payload));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Update a KVDB that does not exist.
     *
     * <p>Verifies: Response status code is 404.
     */
    public void testPutKvdb_notFound() {
        // spotless:off
        String payload = """
                {
                    "resource": {
                        "name": "test",
                        "enabled": true,
                        "author": "Test",
                        "content": {"key": "value"},
                        "description": "",
                        "documentation": "",
                        "references": [],
                        "title": "Test"
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
                                        PluginSettings.KVDBS_URI + "/00000000-0000-0000-0000-000000000000",
                                        payload));
        assertEquals(RestStatus.NOT_FOUND.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Update a KVDB that is not found.
     *
     * <p>Verifies: Response status code is 404.
     */
    public void testPutKvdb_invalidUuid() {
        // spotless:off
        String payload = """
                {
                    "resource": {
                        "name": "test",
                        "title": "Test",
                        "author": "Test",
                        "content": {"key": "value"}
                    }
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("PUT", PluginSettings.KVDBS_URI + "/not-a-uuid", payload));
        assertEquals(RestStatus.NOT_FOUND.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Update a KVDB with empty body.
     *
     * <p>Verifies: Response status code is 400.
     *
     * @throws IOException On request failure.
     */
    public void testPutKvdb_emptyBody() throws IOException {
        String integrationId = this.createIntegration("test-kvdb-put-empty");
        String kvdbId = this.createKvdb(integrationId);

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("PUT", PluginSettings.KVDBS_URI + "/" + kvdbId, "{}"));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    // ========================
    // DELETE - Delete KVDB
    // ========================

    /**
     * Successfully delete a KVDB.
     *
     * <p>Verifies:
     *
     * <ul>
     *   <li>Response status code is 200 OK.
     *   <li>The KVDB no longer exists in the .cti-kvdbs index.
     *   <li>The KVDB ID is no longer listed in the integration's kvdbs list.
     *   <li>The integration's hash.sha256 field has been updated.
     *   <li>The draft policy space.hash.sha256 has been updated.
     * </ul>
     *
     * @throws IOException On request failure.
     */
    public void testDeleteKvdb_success() throws IOException {
        String integrationId = this.createIntegration("test-kvdb-delete-int");
        String kvdbId = this.createKvdb(integrationId);

        // Capture hashes before deletion
        JsonNode integrationBefore =
                this.getResourceByDocumentId(Constants.INDEX_INTEGRATIONS, integrationId, "draft");
        String integrationHashBefore =
                integrationBefore.path(Constants.KEY_HASH).path(Constants.KEY_SHA256).asText();
        String policyHashBefore = this.getDraftPolicySpaceHash();

        Response response = this.deleteResource(PluginSettings.KVDBS_URI, kvdbId);
        assertEquals(RestStatus.OK.getStatus(), this.getStatusCode(response));

        // Verify KVDB no longer exists in draft
        this.assertResourceNotInDraft(Constants.INDEX_KVDBS, kvdbId);

        // Verify KVDB removed from integration's kvdbs list
        this.assertResourceNotInIntegrationList(integrationId, Constants.KEY_KVDBS, kvdbId);

        // Verify integration's hash was updated
        JsonNode integrationAfter =
                this.getResourceByDocumentId(Constants.INDEX_INTEGRATIONS, integrationId, "draft");
        String integrationHashAfter =
                integrationAfter.path(Constants.KEY_HASH).path(Constants.KEY_SHA256).asText();
        assertNotEquals(
                "Integration hash should have been updated after KVDB deletion",
                integrationHashBefore,
                integrationHashAfter);

        // Verify policy space hash updated
        String policyHashAfter = this.getDraftPolicySpaceHash();
        assertNotEquals(
                "Draft policy space hash should have been updated after KVDB deletion",
                policyHashBefore,
                policyHashAfter);
    }

    /**
     * Delete a KVDB that does not exist.
     *
     * <p>Verifies: Response status code is 404.
     */
    public void testDeleteKvdb_notFound() {
        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () ->
                                this.deleteResource(
                                        PluginSettings.KVDBS_URI, "00000000-0000-0000-0000-000000000000"));
        assertEquals(RestStatus.NOT_FOUND.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Delete a KVDB that is not found.
     *
     * <p>Verifies: Response status code is 404.
     */
    public void testDeleteKvdb_invalidUuid() {
        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.deleteResource(PluginSettings.KVDBS_URI, "not-a-uuid"));
        assertEquals(RestStatus.NOT_FOUND.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Delete a KVDB without providing an ID.
     *
     * <p>Verifies: Response status code is 405.
     */
    public void testDeleteKvdb_missingId() {
        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("DELETE", PluginSettings.KVDBS_URI + "/"));
        int statusCode = e.getResponse().getStatusLine().getStatusCode();
        assertEquals("Expected 405 for missing ID", 405, statusCode);
    }
}
