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
import java.util.Locale;
import java.util.Map;

import com.wazuh.contentmanager.ContentManagerRestTestCase;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Integration tests for the Promote operations (GET preview and POST execute).
 *
 * <p>Covers scenarios from:
 *
 * <ul>
 *   <li>07-promote/GetPromote.feature
 *   <li>07-promote/PostPromote.feature
 * </ul>
 */
public class PromoteIT extends ContentManagerRestTestCase {

    // ========================
    // Helper: Build promotion payload from GET preview
    // ========================

    /**
     * Gets the promotion preview and builds a valid POST payload from it.
     *
     * @param space the source space to promote from
     * @return JSON payload string for POST promote
     * @throws IOException on communication error
     */
    private String buildPromotionPayload(String space) throws IOException {
        Response previewResponse =
                this.makeRequest("GET", PluginSettings.PROMOTE_URI, null, Map.of("space", space));
        assertEquals(RestStatus.OK.getStatus(), this.getStatusCode(previewResponse));
        JsonNode preview = this.responseAsJson(previewResponse);
        JsonNode changes = preview.path("changes");

        // Rebuild the changes as JSON to send back in POST
        String changesJson = MAPPER.writeValueAsString(changes);

        // spotless:off
        String promotePayload = """
                {
                    "space": "%s",
                    "changes": %s
                }
                """;
        return String.format(Locale.ROOT, promotePayload, space, changesJson);
        // spotless:on
    }

    /**
     * Creates a full set of draft resources (integration, decoder, rule, kvdb) for promotion testing.
     *
     * @param suffix a unique suffix for resource names
     * @return list of created resource IDs in order: [integrationId, decoderId, ruleId, kvdbId]
     * @throws IOException on communication error
     */
    private List<String> createDraftResourceSet(String suffix) throws IOException {
        String integrationTitle = "promote-int-" + suffix;
        String integrationId = this.createIntegration(integrationTitle);
        String decoderId = this.createDecoder(integrationId);
        String ruleId = this.createRule(integrationId, integrationTitle);
        String kvdbId = this.createKvdb(integrationId);
        return List.of(integrationId, decoderId, ruleId, kvdbId);
    }

    // ========================
    // GET Promote - Preview
    // ========================

    /**
     * Preview promotion from draft to test.
     *
     * <p>Verifies:
     *
     * <ul>
     *   <li>Response status code is 200.
     *   <li>Response body contains a "changes" object.
     *   <li>The changes list operations per resource type.
     * </ul>
     *
     * @throws IOException On communication error
     */
    public void testGetPromote_draftToTest() throws IOException {
        this.createDraftResourceSet("preview");

        Response response =
                this.makeRequest("GET", PluginSettings.PROMOTE_URI, null, Map.of("space", "draft"));
        assertEquals(RestStatus.OK.getStatus(), this.getStatusCode(response));

        JsonNode body = this.responseAsJson(response);
        JsonNode changes = body.path("changes");
        assertFalse("Response should contain 'changes' object", changes.isMissingNode());

        // Verify resource types present
        assertFalse(
                "changes.integrations should be present", changes.path("integrations").isMissingNode());
        assertFalse("changes.decoders should be present", changes.path("decoders").isMissingNode());
        assertFalse("changes.rules should be present", changes.path("rules").isMissingNode());
        assertFalse("changes.kvdbs should be present", changes.path("kvdbs").isMissingNode());
        assertFalse("changes.filters should be present", changes.path("filters").isMissingNode());
        assertFalse("changes.policy should be present", changes.path("policy").isMissingNode());
    }

    /**
     * Preview promotion with missing space parameter.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testGetPromote_missingSpace() {
        ResponseException e =
                expectThrows(
                        ResponseException.class, () -> this.makeRequest("GET", PluginSettings.PROMOTE_URI));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Preview promotion with empty space parameter.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testGetPromote_emptySpace() {
        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("GET", PluginSettings.PROMOTE_URI, null, Map.of("space", "")));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Preview promotion with invalid space value.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testGetPromote_invalidSpace() {
        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () ->
                                this.makeRequest("GET", PluginSettings.PROMOTE_URI, null, Map.of("space", "prod")));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Preview promotion from custom (not allowed).
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testGetPromote_customNotAllowed() {
        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () ->
                                this.makeRequest(
                                        "GET", PluginSettings.PROMOTE_URI, null, Map.of("space", "custom")));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    // ========================
    // POST Promote - Execute
    // ========================

    /**
     * Successfully promote from draft to test.
     *
     * <p>Verifies:
     *
     * <ul>
     *   <li>Response status code is 200.
     *   <li>Resources exist in test space after promotion.
     *   <li>Resources still exist in draft space.
     *   <li>Test policy space hash is regenerated.
     *   <li>Promoted resource hashes match between draft and test spaces.
     * </ul>
     *
     * @throws IOException On communication error
     */
    public void testPostPromote_draftToTest() throws IOException {
        List<String> resourceIds = this.createDraftResourceSet("d2t");
        String integrationId = resourceIds.get(0);
        String decoderId = resourceIds.get(1);
        String ruleId = resourceIds.get(2);
        String kvdbId = resourceIds.get(3);

        // Capture test policy hash before promotion
        String testPolicyHashBefore =
                this.getPolicy("test")
                        .path(Constants.KEY_SPACE)
                        .path(Constants.KEY_HASH)
                        .path(Constants.KEY_SHA256)
                        .asText();

        // Build payload from actual preview
        String payload = this.buildPromotionPayload("draft");

        // Execute promotion
        Response response = this.makeRequest("POST", PluginSettings.PROMOTE_URI, payload);
        assertEquals(RestStatus.OK.getStatus(), this.getStatusCode(response));

        // Verify resources exist in test space
        this.assertResourceExistsInSpace(Constants.INDEX_INTEGRATIONS, integrationId, "test");
        this.assertResourceExistsInSpace(Constants.INDEX_DECODERS, decoderId, "test");
        this.assertResourceExistsInSpace(Constants.INDEX_RULES, ruleId, "test");
        this.assertResourceExistsInSpace(Constants.INDEX_KVDBS, kvdbId, "test");

        // Verify resources still exist in draft space
        this.assertResourceExistsInDraft(Constants.INDEX_INTEGRATIONS, integrationId);
        this.assertResourceExistsInDraft(Constants.INDEX_DECODERS, decoderId);
        this.assertResourceExistsInDraft(Constants.INDEX_RULES, ruleId);
        this.assertResourceExistsInDraft(Constants.INDEX_KVDBS, kvdbId);

        // Verify test policy space hash was regenerated
        String testPolicyHashAfter =
                this.getPolicy("test")
                        .path(Constants.KEY_SPACE)
                        .path(Constants.KEY_HASH)
                        .path(Constants.KEY_SHA256)
                        .asText();
        assertNotEquals(
                "Test policy space hash should be regenerated after promotion",
                testPolicyHashBefore,
                testPolicyHashAfter);

        // Verify promoted resource hashes match between draft and test
        this.assertHashesMatch(Constants.INDEX_INTEGRATIONS, integrationId, "draft", "test");
        this.assertHashesMatch(Constants.INDEX_DECODERS, decoderId, "draft", "test");
        this.assertHashesMatch(Constants.INDEX_RULES, ruleId, "draft", "test");
        this.assertHashesMatch(Constants.INDEX_KVDBS, kvdbId, "draft", "test");
    }

    /**
     * Successfully promote from test to custom.
     *
     * <p>Verifies:
     *
     * <ul>
     *   <li>Response status code is 200 after promoting from test to custom.
     *   <li>Resources exist in custom space after promotion.
     *   <li>Resources still exist in test space.
     *   <li>Custom policy space hash is regenerated.
     *   <li>Promoted resource hashes match between test and custom spaces.
     * </ul>
     *
     * @throws IOException On communication error
     */
    public void testPostPromote_testToCustom() throws IOException {
        List<String> resourceIds = this.createDraftResourceSet("t2c");
        String integrationId = resourceIds.get(0);
        String decoderId = resourceIds.get(1);
        String ruleId = resourceIds.get(2);
        String kvdbId = resourceIds.get(3);

        // First promote draft -> test
        String draftPayload = this.buildPromotionPayload("draft");
        Response draftPromoteResponse =
                this.makeRequest("POST", PluginSettings.PROMOTE_URI, draftPayload);
        assertEquals(RestStatus.OK.getStatus(), this.getStatusCode(draftPromoteResponse));

        // Capture custom policy hash before promotion
        String customPolicyHashBefore =
                this.getPolicy("custom")
                        .path(Constants.KEY_SPACE)
                        .path(Constants.KEY_HASH)
                        .path(Constants.KEY_SHA256)
                        .asText();

        // Now promote test -> custom
        String testPayload = this.buildPromotionPayload("test");
        Response response = this.makeRequest("POST", PluginSettings.PROMOTE_URI, testPayload);
        assertEquals(RestStatus.OK.getStatus(), this.getStatusCode(response));

        // Verify resources exist in custom space
        this.assertResourceExistsInSpace(Constants.INDEX_INTEGRATIONS, integrationId, "custom");
        this.assertResourceExistsInSpace(Constants.INDEX_DECODERS, decoderId, "custom");
        this.assertResourceExistsInSpace(Constants.INDEX_RULES, ruleId, "custom");
        this.assertResourceExistsInSpace(Constants.INDEX_KVDBS, kvdbId, "custom");

        // Verify resources still exist in test space
        this.assertResourceExistsInSpace(Constants.INDEX_INTEGRATIONS, integrationId, "test");
        this.assertResourceExistsInSpace(Constants.INDEX_DECODERS, decoderId, "test");
        this.assertResourceExistsInSpace(Constants.INDEX_RULES, ruleId, "test");
        this.assertResourceExistsInSpace(Constants.INDEX_KVDBS, kvdbId, "test");

        // Verify custom policy space hash was regenerated
        String customPolicyHashAfter =
                this.getPolicy("custom")
                        .path(Constants.KEY_SPACE)
                        .path(Constants.KEY_HASH)
                        .path(Constants.KEY_SHA256)
                        .asText();
        assertNotEquals(
                "Custom policy space hash should be regenerated after promotion",
                customPolicyHashBefore,
                customPolicyHashAfter);

        // Verify promoted resource hashes match between test and custom
        this.assertHashesMatch(Constants.INDEX_INTEGRATIONS, integrationId, "test", "custom");
        this.assertHashesMatch(Constants.INDEX_DECODERS, decoderId, "test", "custom");
        this.assertHashesMatch(Constants.INDEX_RULES, ruleId, "test", "custom");
        this.assertHashesMatch(Constants.INDEX_KVDBS, kvdbId, "test", "custom");
    }

    // ========================
    // POST Promote - Space Isolation
    // ========================

    /**
     * Verify that deleting a decoder in draft does not affect the promoted test space.
     *
     * <p>Steps:
     *
     * <ol>
     *   <li>Create an integration and a decoder in draft.
     *   <li>Promote draft to test.
     *   <li>Delete the decoder from draft.
     *   <li>Verify the decoder no longer exists in draft.
     *   <li>Verify the decoder still exists in the test space.
     *   <li>Verify the test-space integration still references the decoder.
     * </ol>
     *
     * <p>Expected: Only the draft space is modified; the test space remains unchanged.
     *
     * @throws IOException On communication error
     */
    public void testPostPromote_draftDeletionDoesNotAffectTestSpace() throws IOException {
        // 1. Create integration + decoder in draft
        String integrationTitle = "promote-isolation";
        String integrationId = this.createIntegration(integrationTitle);
        String decoderId = this.createDecoder(integrationId);

        // Verify decoder is linked to integration in draft
        this.assertResourceInIntegrationList(integrationId, Constants.KEY_DECODERS, decoderId);

        // 2. Promote draft -> test
        String payload = this.buildPromotionPayload("draft");
        Response promoteResponse = this.makeRequest("POST", PluginSettings.PROMOTE_URI, payload);
        assertEquals(RestStatus.OK.getStatus(), this.getStatusCode(promoteResponse));

        // Verify decoder exists in test space
        this.assertResourceExistsInSpace(Constants.INDEX_DECODERS, decoderId, "test");
        this.assertResourceInIntegrationList(integrationId, Constants.KEY_DECODERS, decoderId, "test");

        // 3. Delete the decoder from draft
        Response deleteResponse = this.deleteResource(PluginSettings.DECODERS_URI, decoderId);
        assertEquals(RestStatus.OK.getStatus(), this.getStatusCode(deleteResponse));

        // 4. Verify decoder no longer exists in draft
        this.assertResourceNotInDraft(Constants.INDEX_DECODERS, decoderId);

        // 5. Verify decoder still exists in test space
        this.assertResourceExistsInSpace(Constants.INDEX_DECODERS, decoderId, "test");

        // 6. Verify test-space integration still references the decoder
        this.assertResourceInIntegrationList(integrationId, Constants.KEY_DECODERS, decoderId, "test");
    }

    // ========================
    // POST Promote - Error Scenarios
    // ========================

    /**
     * Promote from custom (not allowed).
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPostPromote_customNotAllowed() {
        // spotless:off
        String payload = """
                {
                    "space": "custom",
                    "changes": {
                        "kvdbs": [],
                        "rules": [],
                        "decoders": [],
                        "filters": [],
                        "integrations": [],
                        "policy": []
                    }
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("POST", PluginSettings.PROMOTE_URI, payload));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Promote with invalid space.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPostPromote_invalidSpace() {
        // spotless:off
        String payload = """
                {
                    "space": "prod",
                    "changes": {
                        "kvdbs": [],
                        "rules": [],
                        "decoders": [],
                        "filters": [],
                        "integrations": [],
                        "policy": []
                    }
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("POST", PluginSettings.PROMOTE_URI, payload));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Promote with missing changes object.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPostPromote_missingChanges() {
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
                        () -> this.makeRequest("POST", PluginSettings.PROMOTE_URI, payload));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Promote with incomplete changes (missing required resource arrays).
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPostPromote_incompleteChanges() {
        // spotless:off
        String payload = """
                {
                    "space": "draft",
                    "changes": {}
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("POST", PluginSettings.PROMOTE_URI, payload));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Promote with non-update operation on policy.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPostPromote_invalidPolicyOperation() {
        // spotless:off
        String payload = """
                {
                    "space": "draft",
                    "changes": {
                        "kvdbs": [],
                        "rules": [],
                        "decoders": [],
                        "filters": [],
                        "integrations": [],
                        "policy": [{"operation": "add", "id": "some-id"}]
                    }
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("POST", PluginSettings.PROMOTE_URI, payload));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Promote with empty body.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPostPromote_emptyBody() {
        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> this.makeRequest("POST", PluginSettings.PROMOTE_URI, ""));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    // ========================
    // Assertion Helper
    // ========================

    /**
     * Asserts that the hash.sha256 of a resource in two spaces match.
     *
     * @param indexName target index
     * @param resourceId the document.id
     * @param sourceSpace source space name
     * @param targetSpace target space name
     * @throws IOException on communication error
     */
    private void assertHashesMatch(
            String indexName, String resourceId, String sourceSpace, String targetSpace)
            throws IOException {
        JsonNode sourceDoc = this.getResourceByDocumentId(indexName, resourceId, sourceSpace);
        JsonNode targetDoc = this.getResourceByDocumentId(indexName, resourceId, targetSpace);
        assertNotNull("Resource " + resourceId + " should exist in " + sourceSpace, sourceDoc);
        assertNotNull("Resource " + resourceId + " should exist in " + targetSpace, targetDoc);

        String sourceHash = sourceDoc.path(Constants.KEY_HASH).path(Constants.KEY_SHA256).asText();
        String targetHash = targetDoc.path(Constants.KEY_HASH).path(Constants.KEY_SHA256).asText();
        assertEquals(
                "Hash of " + resourceId + " in " + sourceSpace + " should match " + targetSpace,
                sourceHash,
                targetHash);
    }
}
