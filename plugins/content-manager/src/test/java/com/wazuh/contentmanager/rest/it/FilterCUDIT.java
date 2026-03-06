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
import java.util.Map;

import com.wazuh.contentmanager.ContentManagerRestTestCase;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Integration tests for the Filter resource CRUD operations.
 *
 * <p>Covers scenarios for:
 *
 * <ul>
 *   <li>RestPostFilterAction
 *   <li>RestPutFilterAction
 *   <li>RestDeleteFilterAction
 * </ul>
 */
public class FilterCUDIT extends ContentManagerRestTestCase {

    // ========================
    // POST - Create Filter
    // ========================

    /**
     * Successfully create a filter in draft space.
     *
     * <p>Verifies:
     *
     * <ul>
     *   <li>Response status code is 201 Created.
     *   <li>The filter exists in the .cti-filters index.
     *   <li>The document space.name field is "draft".
     *   <li>The document has a non-empty hash.sha256 field.
     *   <li>The filter ID is listed in the draft policy's filters list.
     *   <li>The draft policy space.hash.sha256 has been updated.
     * </ul>
     *
     * @throws IOException On failure to communicate with OpenSearch or parse responses.
     */
    public void testPostFilter_draftSuccess() throws IOException {
        String policyHashBefore = this.getDraftPolicySpaceHash();

        String filterId = this.createFilter("draft");

        // Verify resource exists in draft space
        this.assertResourceExistsInDraft(Constants.INDEX_FILTERS, filterId);

        // Verify space.name and hash
        JsonNode source = this.getResourceByDocumentId(Constants.INDEX_FILTERS, filterId, "draft");
        assertNotNull(source);
        this.assertSpaceName(source);
        this.assertHashPresent(source, "Filter");

        // Verify filter is in draft policy's filters list
        this.assertFilterInPolicyList(filterId, "draft");

        // Verify draft policy space hash changed
        String policyHashAfter = this.getDraftPolicySpaceHash();
        assertNotEquals(
                "Draft policy space hash should have been updated after filter creation",
                policyHashBefore,
                policyHashAfter);
    }

    /**
     * Successfully create a filter in standard space.
     *
     * <p>Verifies:
     *
     * <ul>
     *   <li>Response status code is 201 Created.
     *   <li>The filter exists in the .cti-filters index in standard space.
     *   <li>The document space.name field is "standard".
     *   <li>The document has a non-empty hash.sha256 field.
     *   <li>The filter ID is listed in the standard policy's filters list.
     *   <li>The standard policy space.hash.sha256 has been updated.
     * </ul>
     *
     * @throws IOException On failure to communicate with OpenSearch or parse responses.
     */
    public void testPostFilter_standardSuccess() throws IOException {
        String policyHashBefore = this.getPolicySpaceHash("standard");

        String filterId = this.createFilter("standard");

        // Verify resource exists in standard space
        this.assertResourceExistsInSpace(Constants.INDEX_FILTERS, filterId, "standard");

        // Verify space.name and hash
        JsonNode source = this.getResourceByDocumentId(Constants.INDEX_FILTERS, filterId, "standard");
        assertNotNull(source);
        assertEquals("standard", source.path(Constants.KEY_SPACE).path(Constants.KEY_NAME).asText());
        this.assertHashPresent(source, "Filter");

        // Verify filter is in standard policy's filters list
        this.assertFilterInPolicyList(filterId, "standard");

        // Verify standard policy space hash changed
        String policyHashAfter = this.getPolicySpaceHash("standard");
        assertNotEquals(
                "Standard policy space hash should have been updated after filter creation",
                policyHashBefore,
                policyHashAfter);
    }

    /**
     * Create a filter with an explicit id in the resource.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPostFilter_explicitId() {
        // spotless:off
        String payload = """
                {
                    "space": "draft",
                    "resource": {
                        "id": "custom-id",
                        "name": "filter/test/0",
                        "enabled": true,
                        "metadata": {
                            "description": "Test filter",
                            "author": {
                                "name": "Wazuh, Inc.",
                                "email": "info@wazuh.com",
                                "url": "https://wazuh.com"
                            }
                        },
                        "check": "$host.os.platform == 'ubuntu'",
                        "type": "pre-filter"
                    }
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("POST", PluginSettings.FILTERS_URI, payload));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Create a filter with invalid space value.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPostFilter_invalidSpace() {
        // spotless:off
        String payload = """
                {
                    "space": "invalid",
                    "resource": {
                        "name": "filter/test/0",
                        "enabled": true,
                        "metadata": {
                            "description": "Test filter",
                            "author": {
                                "name": "Wazuh, Inc.",
                                "email": "info@wazuh.com",
                                "url": "https://wazuh.com"
                            }
                        },
                        "check": "$host.os.platform == 'ubuntu'",
                        "type": "pre-filter"
                    }
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("POST", PluginSettings.FILTERS_URI, payload));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Create a filter with missing space field.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPostFilter_missingSpace() {
        // spotless:off
        String payload = """
                {
                    "resource": {
                        "name": "filter/test/0",
                        "enabled": true,
                        "metadata": {
                            "description": "Test filter",
                            "author": {
                                "name": "Wazuh, Inc.",
                                "email": "info@wazuh.com",
                                "url": "https://wazuh.com"
                            }
                        },
                        "check": "$host.os.platform == 'ubuntu'",
                        "type": "pre-filter"
                    }
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("POST", PluginSettings.FILTERS_URI, payload));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Create a filter with missing resource object.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPostFilter_missingResourceObject() {
        // spotless:off
        String payload = """
                {
                    "space": "draft"
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("POST", PluginSettings.FILTERS_URI, payload));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Create a filter with empty body.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPostFilter_emptyBody() {
        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("POST", PluginSettings.FILTERS_URI, ""));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    // ========================
    // PUT - Update Filter
    // ========================

    /**
     * Successfully update a filter in draft space.
     *
     * <p>Verifies:
     *
     * <ul>
     *   <li>Response status code is 200 OK.
     *   <li>The filter document is correctly updated in the .cti-filters index.
     *   <li>The document space.name field is still "draft".
     *   <li>The document hash.sha256 field has been updated.
     *   <li>The draft policy space.hash.sha256 has been updated.
     * </ul>
     *
     * @throws IOException On failure to communicate with OpenSearch or parse responses.
     */
    public void testPutFilter_draftSuccess() throws IOException {
        String filterId = this.createFilter("draft");

        JsonNode sourceBefore =
                this.getResourceByDocumentId(Constants.INDEX_FILTERS, filterId, "draft");
        String hashBefore = sourceBefore.path(Constants.KEY_HASH).path(Constants.KEY_SHA256).asText();
        String policyHashBefore = this.getDraftPolicySpaceHash();

        // spotless:off
        String payload = """
                {
                    "type": "filter",
                    "space" : "draft",
                    "resource": {
                        "name": "filter/test-filter-updated/0",
                        "enabled": false,
                        "metadata": {
                            "description": "Updated filter description",
                            "author": {
                                "name": "Updated Author",
                                "email": "updated@wazuh.com",
                                "url": "https://wazuh.com"
                            }
                        },
                        "check": "$host.os.platform == 'windows'",
                        "type": "post-filter"
                    }
                }
                """;
        // spotless:on

        Response response =
                this.makeRequest("PUT", PluginSettings.FILTERS_URI + "/" + filterId, payload);
        assertEquals(RestStatus.OK.getStatus(), this.getStatusCode(response));

        // Verify updated in index
        JsonNode sourceAfter = this.getResourceByDocumentId(Constants.INDEX_FILTERS, filterId, "draft");
        assertNotNull(sourceAfter);
        this.assertSpaceName(sourceAfter);

        // Verify hash updated
        String hashAfter = sourceAfter.path(Constants.KEY_HASH).path(Constants.KEY_SHA256).asText();
        assertNotEquals("Filter hash should have been updated", hashBefore, hashAfter);

        // Verify draft policy space hash updated
        String policyHashAfter = this.getDraftPolicySpaceHash();
        assertNotEquals(
                "Draft policy space hash should have been updated", policyHashBefore, policyHashAfter);
    }

    /**
     * Successfully update a filter in standard space.
     *
     * <p>Verifies:
     *
     * <ul>
     *   <li>Response status code is 200 OK.
     *   <li>The filter document is correctly updated in the .cti-filters index.
     *   <li>The document space.name field is still "standard".
     *   <li>The document hash.sha256 field has been updated.
     *   <li>The standard policy space.hash.sha256 has been updated.
     * </ul>
     *
     * @throws IOException On failure to communicate with OpenSearch or parse responses.
     */
    public void testPutFilter_standardSuccess() throws IOException {
        String filterId = this.createFilter("standard");

        JsonNode sourceBefore =
                this.getResourceByDocumentId(Constants.INDEX_FILTERS, filterId, "standard");
        String hashBefore = sourceBefore.path(Constants.KEY_HASH).path(Constants.KEY_SHA256).asText();
        String policyHashBefore = this.getPolicySpaceHash("standard");

        // spotless:off
        String payload = """
                {
                    "type": "filter",
                    "space" : "standard",
                    "resource": {
                        "name": "filter/test-filter-updated/0",
                        "enabled": false,
                        "metadata": {
                            "description": "Updated filter description",
                            "author": {
                                "name": "Updated Author",
                                "email": "updated@wazuh.com",
                                "url": "https://wazuh.com"
                            }
                        },
                        "check": "$host.os.platform == 'windows'",
                        "type": "post-filter"
                    }
                }
                """;
        // spotless:on

        Response response =
                this.makeRequest("PUT", PluginSettings.FILTERS_URI + "/" + filterId, payload);
        assertEquals(RestStatus.OK.getStatus(), this.getStatusCode(response));

        // Verify updated in index
        JsonNode sourceAfter =
                this.getResourceByDocumentId(Constants.INDEX_FILTERS, filterId, "standard");
        assertNotNull(sourceAfter);
        assertEquals(
                "standard", sourceAfter.path(Constants.KEY_SPACE).path(Constants.KEY_NAME).asText());

        // Verify hash updated
        String hashAfter = sourceAfter.path(Constants.KEY_HASH).path(Constants.KEY_SHA256).asText();
        assertNotEquals("Filter hash should have been updated", hashBefore, hashAfter);

        // Verify standard policy space hash updated
        String policyHashAfter = this.getPolicySpaceHash("standard");
        assertNotEquals(
                "Standard policy space hash should have been updated", policyHashBefore, policyHashAfter);
    }

    /**
     * Update a filter that does not exist.
     *
     * <p>Verifies: Response status code is 404.
     */
    public void testPutFilter_notFound() {
        // spotless:off
        String payload = """
                {
                    "type": "filter",
                    "resource": {
                        "name": "filter/test/0",
                        "enabled": true,
                        "metadata": {
                            "description": "Test filter",
                            "author": {
                                "name": "Wazuh, Inc.",
                                "email": "info@wazuh.com",
                                "url": "https://wazuh.com"
                            }
                        },
                        "check": "$host.os.platform == 'ubuntu'",
                        "type": "pre-filter"
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
                                        PluginSettings.FILTERS_URI + "/00000000-0000-0000-0000-000000000000",
                                        payload));
        assertEquals(RestStatus.NOT_FOUND.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Update a filter with invalid UUID.
     *
     * <p>Verifies: Response status code is 404.
     */
    public void testPutFilter_invalidUuid() {
        // spotless:off
        String payload = """
                {
                    "type": "filter",
                    "resource": {
                        "name": "filter/test/0",
                        "enabled": true
                    }
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("PUT", PluginSettings.FILTERS_URI + "/not-a-uuid", payload));
        assertEquals(RestStatus.NOT_FOUND.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Update a filter with missing resource object (empty body).
     *
     * <p>Verifies: Response status code is 400.
     *
     * @throws IOException On failure to communicate with OpenSearch or parse responses.
     */
    public void testPutFilter_emptyBody() throws IOException {
        String filterId = this.createFilter("draft");

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("PUT", PluginSettings.FILTERS_URI + "/" + filterId, "{}"));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    // ========================
    // DELETE - Delete Filter
    // ========================

    /**
     * Successfully delete a filter from draft space.
     *
     * <p>Verifies:
     *
     * <ul>
     *   <li>Response status code is 200 OK.
     *   <li>The filter no longer exists in the .cti-filters index.
     *   <li>The filter ID is no longer listed in the draft policy's filters list.
     *   <li>The draft policy space.hash.sha256 has been updated.
     * </ul>
     *
     * @throws IOException On failure to communicate with OpenSearch or parse responses.
     */
    public void testDeleteFilter_draftSuccess() throws IOException {
        String filterId = this.createFilter("draft");

        String policyHashBefore = this.getDraftPolicySpaceHash();

        Response response = this.deleteResource(PluginSettings.FILTERS_URI, filterId);
        assertEquals(RestStatus.OK.getStatus(), this.getStatusCode(response));

        // Verify filter no longer exists in draft
        this.assertResourceNotInDraft(Constants.INDEX_FILTERS, filterId);

        // Verify filter removed from draft policy's filters list
        this.assertFilterNotInPolicyList(filterId, "draft");

        // Verify policy space hash updated
        String policyHashAfter = this.getDraftPolicySpaceHash();
        assertNotEquals(
                "Draft policy space hash should have been updated after filter deletion",
                policyHashBefore,
                policyHashAfter);
    }

    /**
     * Successfully delete a filter from standard space.
     *
     * <p>Verifies:
     *
     * <ul>
     *   <li>Response status code is 200 OK.
     *   <li>The filter no longer exists in the .cti-filters index.
     *   <li>The filter ID is no longer listed in the standard policy's filters list.
     *   <li>The standard policy space.hash.sha256 has been updated.
     * </ul>
     *
     * @throws IOException On failure to communicate with OpenSearch or parse responses.
     */
    public void testDeleteFilter_standardSuccess() throws IOException {
        String filterId = this.createFilter("standard");

        String policyHashBefore = this.getPolicySpaceHash("standard");

        Response response = this.deleteResource(PluginSettings.FILTERS_URI, filterId);
        assertEquals(RestStatus.OK.getStatus(), this.getStatusCode(response));

        // Verify filter no longer exists in standard space
        JsonNode filterAfter =
                this.getResourceByDocumentId(Constants.INDEX_FILTERS, filterId, "standard");
        assertNull("Filter should no longer exist in standard space", filterAfter);

        // Verify filter removed from standard policy's filters list
        this.assertFilterNotInPolicyList(filterId, "standard");

        // Verify policy space hash updated
        String policyHashAfter = this.getPolicySpaceHash("standard");
        assertNotEquals(
                "Standard policy space hash should have been updated after filter deletion",
                policyHashBefore,
                policyHashAfter);
    }

    /**
     * Delete a filter that does not exist.
     *
     * <p>Verifies: Response status code is 404.
     */
    public void testDeleteFilter_notFound() {
        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () ->
                                this.deleteResource(
                                        PluginSettings.FILTERS_URI, "00000000-0000-0000-0000-000000000000"));
        assertEquals(RestStatus.NOT_FOUND.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Delete a filter with invalid UUID.
     *
     * <p>Verifies: Response status code is 404.
     */
    public void testDeleteFilter_invalidUuid() {
        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.deleteResource(PluginSettings.FILTERS_URI, "not-a-uuid"));
        assertEquals(RestStatus.NOT_FOUND.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Delete a filter without providing an ID.
     *
     * <p>Verifies: Response status code is 405.
     */
    public void testDeleteFilter_missingId() {
        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("DELETE", PluginSettings.FILTERS_URI + "/"));
        int statusCode = e.getResponse().getStatusLine().getStatusCode();
        assertEquals("Expected 405 for missing ID", 405, statusCode);
    }

    // ========================
    // Helper Methods
    // ========================

    /**
     * Creates a filter in the specified space and returns its generated ID.
     *
     * @param spaceName the space name ("draft" or "standard")
     * @return the generated filter ID
     * @throws IOException on communication error
     */
    protected String createFilter(String spaceName) throws IOException {
        // spotless:off
        String payload = """
                {
                    "space": "%s",
                    "resource": {
                        "name": "filter/test-filter/0",
                        "enabled": true,
                        "metadata": {
                            "description": "Test filter for integration tests",
                            "author": {
                                "name": "Wazuh, Inc.",
                                "email": "info@wazuh.com",
                                "url": "https://wazuh.com"
                            }
                        },
                        "check": "$host.os.platform == 'ubuntu'",
                        "type": "pre-filter"
                    }
                }
                """;
        payload = String.format(Locale.ROOT, payload, spaceName);
        // spotless:on

        Response response = this.makeRequest("POST", PluginSettings.FILTERS_URI, payload);
        assertEquals(RestStatus.CREATED.getStatus(), this.getStatusCode(response));

        Map<String, Object> body = this.parseResponseAsMap(response);
        String id = (String) body.get("message");
        assertNotNull("Filter ID should not be null", id);
        return id;
    }

    /**
     * Gets the policy space hash for a given space.
     *
     * @param spaceName space name (draft, test, custom, standard)
     * @return the SHA-256 space hash string
     * @throws IOException on communication error
     */
    protected String getPolicySpaceHash(String spaceName) throws IOException {
        JsonNode policy = this.getPolicy(spaceName);
        return policy
                .path(Constants.KEY_SPACE)
                .path(Constants.KEY_HASH)
                .path(Constants.KEY_SHA256)
                .asText();
    }

    /**
     * Asserts that a filter ID exists in a policy's filters list.
     *
     * @param filterId the filter document.id
     * @param spaceName the space to check (draft, test, custom, standard)
     * @throws IOException on communication error
     */
    protected void assertFilterInPolicyList(String filterId, String spaceName) throws IOException {
        JsonNode policy = this.getPolicy(spaceName);
        assertNotNull("Policy for space '" + spaceName + "' should exist", policy);
        JsonNode filters = policy.path(Constants.KEY_DOCUMENT).path(Constants.KEY_FILTERS);
        assertTrue("Filters list should be an array", filters.isArray());
        boolean found = false;
        for (JsonNode element : filters) {
            if (element.asText().equals(filterId)) {
                found = true;
                break;
            }
        }
        assertTrue("Filter " + filterId + " should be in policy's filters list in " + spaceName, found);
    }

    /**
     * Asserts that a filter ID does NOT exist in a policy's filters list.
     *
     * @param filterId the filter document.id that should be absent
     * @param spaceName the space to check (draft, test, custom, standard)
     * @throws IOException on communication error
     */
    protected void assertFilterNotInPolicyList(String filterId, String spaceName) throws IOException {
        JsonNode policy = this.getPolicy(spaceName);
        if (policy == null) return; // Policy was deleted, filter is implicitly unlinked
        JsonNode filters = policy.path(Constants.KEY_DOCUMENT).path(Constants.KEY_FILTERS);
        if (!filters.isArray()) return;
        for (JsonNode element : filters) {
            assertNotEquals(
                    "Filter " + filterId + " should NOT be in policy's filters list in " + spaceName,
                    filterId,
                    element.asText());
        }
    }
}
