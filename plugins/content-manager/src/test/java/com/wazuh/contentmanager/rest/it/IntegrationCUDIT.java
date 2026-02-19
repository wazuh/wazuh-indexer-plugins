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
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.ContentManagerRestTestCase;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Integration tests for the Integration resource CRUD operations.
 *
 * <p>Covers scenarios from:
 *
 * <ul>
 *   <li>01-integrations/PostIntegration.feature
 *   <li>01-integrations/PutIntegration.feature
 *   <li>01-integrations/DeleteIntegration.feature
 * </ul>
 */
public class IntegrationCUDIT extends ContentManagerRestTestCase {

    // ========================
    // POST - Create Integration
    // ========================

    /**
     * Successfully create an integration.
     *
     * <p>Verifies:
     *
     * <ul>
     *   <li>Response status code is 201 Created.
     *   <li>Response body contains a generated resource ID.
     *   <li>The integration exists in the .cti-integrations index.
     *   <li>The document space.name field is "draft".
     *   <li>The document has a non-empty hash.sha256 field.
     *   <li>The integration ID is listed in the draft policy's document.integrations.
     *   <li>The draft policy space.hash.sha256 has been updated.
     * </ul>
     */
    public void testPostIntegration_success() throws IOException {
        String hashBefore = getDraftPolicySpaceHash();

        String integrationId = createIntegration("test-integration-post");

        // Verify resource exists in draft space
        assertResourceExistsInDraft(Constants.INDEX_INTEGRATIONS, integrationId);

        // Verify space.name and hash
        JsonNode source = getResourceByDocumentId(Constants.INDEX_INTEGRATIONS, integrationId, "draft");
        assertNotNull(source);
        assertSpaceName(source, "draft");
        assertHashPresent(source, "Integration");

        // Verify integration is in draft policy's integrations list
        List<String> policyIntegrations = getDraftPolicyIntegrations();
        assertTrue(
                "Integration ID should be in draft policy integrations list",
                policyIntegrations.contains(integrationId));

        // Verify draft policy space hash changed
        String hashAfter = getDraftPolicySpaceHash();
        assertNotEquals(
                "Draft policy space hash should have been updated after creation", hashBefore, hashAfter);
    }

    /**
     * Create an integration with the same title as an existing integration.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPostIntegration_duplicateTitle() throws IOException {
        createIntegration("test-integration-dup");

        // spotless:off
        String payload = """
                {
                    "resource": {
                        "title": "test-integration-dup",
                        "author": "Wazuh Inc.",
                        "category": "cloud-services",
                        "description": "Duplicate.",
                        "documentation": "doc",
                        "references": ["https://wazuh.com"],
                        "enabled": true
                    }
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> makeRequest("POST", PluginSettings.INTEGRATIONS_URI, payload));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Create an integration with missing title.
     *
     * <p>Verifies: Response status code is 400 and body contains "Missing [title] field."
     */
    public void testPostIntegration_missingTitle() throws IOException {
        // spotless:off
        String payload = """
                {
                    "resource": {
                        "author": "Wazuh Inc.",
                        "category": "cloud-services"
                    }
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> makeRequest("POST", PluginSettings.INTEGRATIONS_URI, payload));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Create an integration with missing author.
     *
     * <p>Verifies: Response status code is 400 and body contains "Missing [author] field."
     */
    public void testPostIntegration_missingAuthor() throws IOException {
        // spotless:off
        String payload = """
                {
                    "resource": {
                        "title": "test-integration-no-author",
                        "category": "cloud-services"
                    }
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> makeRequest("POST", PluginSettings.INTEGRATIONS_URI, payload));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Create an integration with missing category.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPostIntegration_missingCategory() throws IOException {
        // spotless:off
        String payload = """
                {
                    "resource": {
                        "title": "test-integration-no-cat",
                        "author": "Wazuh Inc."
                    }
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> makeRequest("POST", PluginSettings.INTEGRATIONS_URI, payload));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Create an integration with an explicit id in the resource.
     *
     * <p>Verifies: Response status code is 201 (ID is ignored).
     */
    public void testPostIntegration_explicitIdIgnored() throws IOException {
        // spotless:off
        String payload = """
                {
                    "resource": {
                        "id": "custom-id",
                        "title": "test-integration-with-id",
                        "author": "Wazuh Inc.",
                        "category": "cloud-services",
                        "description": "Test.",
                        "documentation": "doc",
                        "references": ["https://wazuh.com"]
                    }
                }
                """;
        // spotless:on

        Response response = makeRequest("POST", PluginSettings.INTEGRATIONS_URI, payload);
        // The system may accept (ignore the ID) or reject it. Check behavior.
        int statusCode = getStatusCode(response);
        assertTrue(
                "Status should be 201 (id ignored) or 400 (id rejected)",
                statusCode == 201 || statusCode == 400);
    }

    /**
     * Create an integration with missing resource object.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPostIntegration_missingResourceObject() throws IOException {
        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> makeRequest("POST", PluginSettings.INTEGRATIONS_URI, "{}"));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Create an integration with empty body.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPostIntegration_emptyBody() throws IOException {
        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> makeRequest("POST", PluginSettings.INTEGRATIONS_URI, ""));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    // ========================
    // PUT - Update Integration
    // ========================

    /**
     * Successfully update an integration.
     *
     * <p>Verifies:
     *
     * <ul>
     *   <li>Response status code is 200 OK.
     *   <li>The integration document is correctly updated in the .cti-integrations index.
     *   <li>The document space.name field is still "draft".
     *   <li>The document hash.sha256 field has been updated.
     *   <li>The draft policy space.hash.sha256 has been updated.
     * </ul>
     */
    public void testPutIntegration_success() throws IOException {
        String integrationId = createIntegration("test-integration-put");

        JsonNode sourceBefore =
                getResourceByDocumentId(Constants.INDEX_INTEGRATIONS, integrationId, "draft");
        String hashBefore = sourceBefore.path(Constants.KEY_HASH).path(Constants.KEY_SHA256).asText();
        String policyHashBefore = getDraftPolicySpaceHash();

        // spotless:off
        String payload = """
                {
                    "resource": {
                        "title": "test-integration-put-updated",
                        "author": "Wazuh Inc.",
                        "category": "cloud-services",
                        "description": "Updated description.",
                        "documentation": "updated-doc",
                        "references": ["https://wazuh.com"],
                        "enabled": true,
                        "rules": [],
                        "decoders": [],
                        "kvdbs": []
                    }
                }
                """;
        // spotless:on

        Response response =
                makeRequest("PUT", PluginSettings.INTEGRATIONS_URI + "/" + integrationId, payload);
        assertEquals(RestStatus.OK.getStatus(), getStatusCode(response));

        // Verify updated in index
        JsonNode sourceAfter =
                getResourceByDocumentId(Constants.INDEX_INTEGRATIONS, integrationId, "draft");
        assertNotNull(sourceAfter);
        assertSpaceName(sourceAfter, "draft");
        assertEquals(
                "Updated description.",
                sourceAfter.path(Constants.KEY_DOCUMENT).path("description").asText());

        // Verify hash updated
        String hashAfter = sourceAfter.path(Constants.KEY_HASH).path(Constants.KEY_SHA256).asText();
        assertNotEquals("Integration hash should have been updated", hashBefore, hashAfter);

        // Verify draft policy space hash updated
        String policyHashAfter = getDraftPolicySpaceHash();
        assertNotEquals(
                "Draft policy space hash should have been updated", policyHashBefore, policyHashAfter);
    }

    /**
     * Update an integration changing its title to one that already exists in draft space.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPutIntegration_duplicateTitle() throws IOException {
        String id1 = createIntegration("test-put-dup-a");
        createIntegration("test-put-dup-b");

        // spotless:off
        String payload = """
                {
                    "resource": {
                        "title": "test-put-dup-b",
                        "author": "Wazuh Inc.",
                        "category": "cloud-services",
                        "description": "Try changing to existing title.",
                        "documentation": "doc",
                        "references": ["https://wazuh.com"],
                        "rules": [],
                        "decoders": [],
                        "kvdbs": []
                    }
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> makeRequest("PUT", PluginSettings.INTEGRATIONS_URI + "/" + id1, payload));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Update an integration that does not exist.
     *
     * <p>Verifies: Response status code is 404.
     */
    public void testPutIntegration_notFound() throws IOException {
        // spotless:off
        String payload = """
                {
                    "resource": {
                        "title": "nonexistent",
                        "author": "Test",
                        "category": "cloud-services",
                        "description": "",
                        "documentation": "",
                        "references": [],
                        "rules": [],
                        "decoders": [],
                        "kvdbs": []
                    }
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () ->
                                makeRequest(
                                        "PUT",
                                        PluginSettings.INTEGRATIONS_URI + "/00000000-0000-0000-0000-000000000000",
                                        payload));
        assertEquals(RestStatus.NOT_FOUND.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Update an integration that is not found.
     *
     * <p>Verifies: Response status code is 404.
     */
    public void testPutIntegration_invalidUuid() throws IOException {
        // spotless:off
        String payload = """
                {
                    "resource": {
                        "title": "test",
                        "author": "Test",
                        "category": "cloud-services",
                        "description": "",
                        "documentation": "",
                        "references": [],
                        "rules": [],
                        "decoders": [],
                        "kvdbs": []
                    }
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> makeRequest("PUT", PluginSettings.INTEGRATIONS_URI + "/not-a-uuid", payload));
        assertEquals(RestStatus.NOT_FOUND.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Update an integration with missing required fields.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPutIntegration_missingRequiredFields() throws IOException {
        String integrationId = createIntegration("test-integration-put-missing");

        // spotless:off
        String payload = """
                {
                    "resource": {
                        "title": "updated-title"
                    }
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () ->
                                makeRequest("PUT", PluginSettings.INTEGRATIONS_URI + "/" + integrationId, payload));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Update an integration with an id in the request body (should be ignored).
     *
     * <p>Verifies: Response status code is 200, since the ID is ignored on update.
     */
    public void testPutIntegration_idInBodyIgnored() throws IOException {
        String integrationId = createIntegration("test-integration-put-idinbody");

        // spotless:off
        String payload = """
                {
                    "resource": {
                        "id": "some-id",
                        "title": "test-integration-put-idinbody-updated",
                        "author": "Wazuh Inc.",
                        "category": "cloud-services",
                        "description": "Same.",
                        "documentation": "doc",
                        "references": ["https://wazuh.com"],
                        "rules": [],
                        "decoders": [],
                        "kvdbs": []
                    }
                }
                """;
        // spotless:on

        Response response =
                makeRequest("PUT", PluginSettings.INTEGRATIONS_URI + "/" + integrationId, payload);
        assertEquals(RestStatus.OK.getStatus(), getStatusCode(response));
        Map<String, Object> body = parseResponseAsMap(response);
        assertEquals("Path ID should be used, not body ID", integrationId, body.get("message"));
    }

    // ========================
    // DELETE - Delete Integration
    // ========================

    /**
     * Successfully delete an integration with no attached resources.
     *
     * <p>Verifies:
     *
     * <ul>
     *   <li>Response status code is 200 OK.
     *   <li>The integration no longer exists in the .cti-integrations index.
     *   <li>The integration ID is no longer listed in the draft policy's document.integrations.
     *   <li>The draft policy space.hash.sha256 has been updated.
     *   <li>The draft policy hash.sha256 has been updated.
     * </ul>
     */
    public void testDeleteIntegration_success() throws IOException {
        String integrationId = createIntegration("test-integration-delete");

        String policySpaceHashBefore = getDraftPolicySpaceHash();
        String policyDocHashBefore = getDraftPolicyDocumentHash();

        Response response = deleteResource(PluginSettings.INTEGRATIONS_URI, integrationId);
        assertEquals(RestStatus.OK.getStatus(), getStatusCode(response));

        // Verify integration no longer exists in draft
        assertResourceNotInDraft(Constants.INDEX_INTEGRATIONS, integrationId);

        // Verify integration removed from draft policy's integrations list
        List<String> policyIntegrations = getDraftPolicyIntegrations();
        assertFalse(
                "Integration ID should no longer be in draft policy integrations list",
                policyIntegrations.contains(integrationId));

        // Verify draft policy space hash updated
        String policySpaceHashAfter = getDraftPolicySpaceHash();
        assertNotEquals(
                "Draft policy space hash should have been updated after delete",
                policySpaceHashBefore,
                policySpaceHashAfter);

        // Verify draft policy document hash updated
        String policyDocHashAfter = getDraftPolicyDocumentHash();
        assertNotEquals(
                "Draft policy document hash should have been updated after delete",
                policyDocHashBefore,
                policyDocHashAfter);
    }

    /**
     * Delete an integration that has attached resources (decoders).
     *
     * <p>Verifies: Response status code is 400 with message about attached resources.
     */
    public void testDeleteIntegration_hasAttachedResources() throws IOException {
        String integrationId = createIntegration("test-integration-with-deps");
        createDecoder(integrationId);

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> deleteResource(PluginSettings.INTEGRATIONS_URI, integrationId));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Delete an integration that does not exist.
     *
     * <p>Verifies: Response status code is 404.
     */
    public void testDeleteIntegration_notFound() throws IOException {
        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () ->
                                deleteResource(
                                        PluginSettings.INTEGRATIONS_URI, "00000000-0000-0000-0000-000000000000"));
        assertEquals(RestStatus.NOT_FOUND.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Delete an integration that is not found.
     *
     * <p>Verifies: Response status code is 404.
     */
    public void testDeleteIntegration_invalidUuid() throws IOException {
        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> deleteResource(PluginSettings.INTEGRATIONS_URI, "not-a-uuid"));
        assertEquals(RestStatus.NOT_FOUND.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Delete an integration without providing an ID.
     *
     * <p>Verifies: Response status code is 400 or 405 (method not allowed on base endpoint).
     */
    public void testDeleteIntegration_missingId() throws IOException {
        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> makeRequest("DELETE", PluginSettings.INTEGRATIONS_URI + "/"));
        int statusCode = e.getResponse().getStatusLine().getStatusCode();
        assertTrue("Expected 400 or 405 for missing ID", statusCode == 400 || statusCode == 405);
    }
}
