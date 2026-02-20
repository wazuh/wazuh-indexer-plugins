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

import com.wazuh.contentmanager.ContentManagerRestTestCase;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Integration tests for the Policy resource operations and initialization.
 *
 * <p>Covers scenarios from:
 *
 * <ul>
 *   <li>05-policy/PolicyInitialization.feature
 *   <li>05-policy/PutPolicy.feature
 * </ul>
 */
public class PolicyIT extends ContentManagerRestTestCase {

    // ========================
    // Policy Initialization
    // ========================

    /**
     * The .cti-policies index exists.
     *
     * <p>Verifies: Response status code is 200 when querying the index.
     * @throws IOException On parsing or request error.
     */
    public void testPoliciesIndexExists() throws IOException {
        Response response = this.makeRequest("GET", Constants.INDEX_POLICIES);
        assertEquals(RestStatus.OK.getStatus(), this.getStatusCode(response));
    }

    /**
     * Exactly four policy documents exist, one per space.
     *
     * <p>Verifies:
     *
     * <ul>
     *   <li>Total number of hits is 4.
     *   <li>There is one document for each space: draft, test, custom, standard.
     * </ul>
     * @throws IOException On parsing or request error.
     */
    public void testPoliciesExactlyFour() throws IOException {
        JsonNode result = this.getAllDocuments();
        long totalHits = result.path("hits").path("total").path("value").asLong(0);
        assertEquals("There should be exactly 4 policy documents", 4, totalHits);

        // Verify one policy per space
        JsonNode hits = result.path("hits").path("hits");
        boolean hasDraft = false;
        boolean hasTest = false;
        boolean hasCustom = false;
        boolean hasStandard = false;

        for (JsonNode hit : hits) {
            String spaceName =
                    hit.path("_source").path(Constants.KEY_SPACE).path(Constants.KEY_NAME).asText();
            switch (spaceName) {
                case "draft" -> hasDraft = true;
                case "test" -> hasTest = true;
                case "custom" -> hasCustom = true;
                case "standard" -> hasStandard = true;
            }
        }
        assertTrue("Draft policy should exist", hasDraft);
        assertTrue("Test policy should exist", hasTest);
        assertTrue("Custom policy should exist", hasCustom);
        assertTrue("Standard policy should exist", hasStandard);
    }

    /**
     * Draft, test, and custom policies start with empty integrations and root_decoder.
     *
     * <p>Verifies: The document.integrations list is empty and document.root_decoder is empty for
     * draft, test, and custom spaces.
     * @throws IOException On parsing or request error.
     */
    public void testNonStandardPoliciesStartEmpty() throws IOException {
        for (String space : new String[] {"draft", "test", "custom"}) {
            JsonNode policy = this.getPolicy(space);
            JsonNode integrations = policy.path(Constants.KEY_DOCUMENT).path(Constants.KEY_INTEGRATIONS);
            assertTrue(
                    space + " policy integrations should be empty",
                    integrations.isArray() && integrations.isEmpty());
            String rootDecoder = policy.path(Constants.KEY_DOCUMENT).path("root_decoder").asText("");
            assertTrue(space + " policy root_decoder should be empty", rootDecoder.isEmpty());
        }
    }

    /**
     * Each policy document contains the expected structure.
     *
     * <p>Verifies: The draft policy contains all required fields: id, title, date, modified,
     * root_decoder, integrations, filters, enrichments, author, description, documentation,
     * references, space.name, space.hash.sha256, hash.sha256.
     * @throws IOException On parsing or request error.
     */
    public void testPolicyDocumentStructure() throws IOException {
        JsonNode policy = this.getDraftPolicy();

        JsonNode doc = policy.path(Constants.KEY_DOCUMENT);
        assertFalse("document.id should exist", doc.path("id").isMissingNode());
        assertFalse("document.title should exist", doc.path("title").isMissingNode());
        assertFalse("document.date should exist", doc.path("date").isMissingNode());
        assertFalse("document.modified should exist", doc.path("modified").isMissingNode());
        assertFalse("document.root_decoder should exist", doc.path("root_decoder").isMissingNode());
        assertFalse("document.integrations should exist", doc.path("integrations").isMissingNode());
        assertFalse("document.filters should exist", doc.path("filters").isMissingNode());
        assertFalse("document.enrichments should exist", doc.path("enrichments").isMissingNode());
        assertFalse("document.author should exist", doc.path("author").isMissingNode());
        assertFalse("document.description should exist", doc.path("description").isMissingNode());
        assertFalse("document.documentation should exist", doc.path("documentation").isMissingNode());
        assertFalse("document.references should exist", doc.path("references").isMissingNode());

        // Verify space fields
        assertFalse(
                "space.name should exist",
                policy.path(Constants.KEY_SPACE).path(Constants.KEY_NAME).isMissingNode());
        assertFalse(
                "space.hash.sha256 should exist",
                policy
                        .path(Constants.KEY_SPACE)
                        .path(Constants.KEY_HASH)
                        .path(Constants.KEY_SHA256)
                        .isMissingNode());
        assertFalse(
                "hash.sha256 should exist",
                policy.path(Constants.KEY_HASH).path(Constants.KEY_SHA256).isMissingNode());
    }

    /**
     * Each policy has a valid SHA-256 hash.
     *
     * <p>Verifies: Every policy document has non-empty hash.sha256 and space.hash.sha256 fields.
     * @throws IOException On parsing or request error.
     */
    public void testPoliciesHaveValidHashes() throws IOException {
        JsonNode result = this.getAllDocuments();
        JsonNode hits = result.path("hits").path("hits");

        for (JsonNode hit : hits) {
            JsonNode source = hit.path("_source");
            String spaceName = source.path(Constants.KEY_SPACE).path(Constants.KEY_NAME).asText();

            String docHash = source.path(Constants.KEY_HASH).path(Constants.KEY_SHA256).asText("");
            assertFalse(spaceName + " policy should have a non-empty hash.sha256", docHash.isEmpty());

            String spaceHash =
                    source
                            .path(Constants.KEY_SPACE)
                            .path(Constants.KEY_HASH)
                            .path(Constants.KEY_SHA256)
                            .asText("");
            assertFalse(
                    spaceName + " policy should have a non-empty space.hash.sha256", spaceHash.isEmpty());
        }
    }

    // ========================
    // PUT - Update Draft Policy
    // ========================

    /**
     * Successfully update the draft policy.
     *
     * <p>Verifies:
     *
     * <ul>
     *   <li>Response status code is 200 OK.
     *   <li>The draft policy in .cti-policies is updated.
     *   <li>Its space.hash.sha256 field is updated.
     * </ul>
     * @throws IOException On parsing or request error.
     */
    public void testPutPolicy_success() throws IOException {
        // Create an integration and decoder for the policy payload
        String integrationId = this.createIntegration("test-policy-update-int");
        String decoderId = this.createDecoder(integrationId);

        String policyHashBefore = this.getDraftPolicySpaceHash();

        // Get current integrations list (it should have the new integration)
        List<String> currentIntegrations = this.getDraftPolicyIntegrations();

        // Build integrations JSON array
        StringBuilder intListJson = new StringBuilder("[");
        for (int i = 0; i < currentIntegrations.size(); i++) {
            if (i > 0) intListJson.append(",");
            intListJson.append("\"").append(currentIntegrations.get(i)).append("\"");
        }
        intListJson.append("]");

        // spotless:off
        String payload = getString(decoderId, intListJson);
        // spotless:on

        Response response = this.makeRequest("PUT", PluginSettings.POLICY_URI, payload);
        assertEquals(RestStatus.OK.getStatus(), this.getStatusCode(response));

        // Verify draft policy space hash updated
        String policyHashAfter = this.getDraftPolicySpaceHash();
        assertNotEquals(
                "Draft policy space hash should have been updated", policyHashBefore, policyHashAfter);
    }

    private static String getString(String decoderId, StringBuilder intListJson) {
        String payload = """
                {
                    "type": "policy",
                    "resource": {
                        "title": "Updated policy",
                        "date": "2026-02-03T18:57:33.931731040Z",
                        "modified": "2026-02-03T18:57:33.931731040Z",
                        "root_decoder": "%s",
                        "integrations": %s,
                        "filters": [],
                        "enrichments": [],
                        "author": "Test",
                        "description": "Updated policy description",
                        "documentation": "",
                        "references": []
                    }
                }
                """;
        payload = String.format(Locale.ROOT, payload, decoderId, intListJson);
        return payload;
    }

    /**
     * Update policy with missing type field.
     *
     * <p>Verifies: Response status code is 200 OK. The plugin does not validate the type field, so
     * the request is accepted.
     * @throws IOException On parsing or request error.
     */
    public void testPutPolicy_missingType() throws IOException {
        // spotless:off
        String payload = """
                {
                    "resource": {
                        "title": "Custom policy",
                        "author": "Test",
                        "description": "Custom policy",
                        "documentation": "",
                        "references": []
                    }
                }
                """;
        // spotless:on

        Response response = this.makeRequest("PUT", PluginSettings.POLICY_URI, payload);
        assertEquals(RestStatus.OK.getStatus(), this.getStatusCode(response));
    }

    /**
     * Update policy with wrong type value.
     *
     * <p>Verifies: Response status code is 200 OK. The plugin does not validate the type field value,
     * so the request is accepted even with a non-policy type.
     * @throws IOException On parsing or request error.
     */
    public void testPutPolicy_wrongType() throws IOException {
        // spotless:off
        String payload = """
                {
                    "type": "integration",
                    "resource": {
                        "title": "Custom policy",
                        "author": "Test",
                        "description": "Custom policy",
                        "documentation": "",
                        "references": []
                    }
                }
                """;
        // spotless:on

        Response response = this.makeRequest("PUT", PluginSettings.POLICY_URI, payload);
        assertEquals(RestStatus.OK.getStatus(), this.getStatusCode(response));
    }

    /**
     * Update policy with missing resource object.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPutPolicy_missingResource() {
        // spotless:off
        String payload = """
                {
                    "type": "policy"
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class, () -> this.makeRequest("PUT", PluginSettings.POLICY_URI, payload));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Update policy with missing required fields in resource.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPutPolicy_missingRequiredFields() {
        // spotless:off
        String payload = """
                {
                    "type": "policy",
                    "resource": {
                        "title": "Custom policy"
                    }
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class, () -> this.makeRequest("PUT", PluginSettings.POLICY_URI, payload));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Update policy with empty body.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPutPolicy_emptyBody() {
        ResponseException e =
                expectThrows(
                        ResponseException.class, () -> this.makeRequest("PUT", PluginSettings.POLICY_URI, ""));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Verify policy changes are NOT reflected in test space until promotion.
     *
     * <p>Verifies: After updating the draft policy, the test policy remains unchanged.
     * @throws IOException On parsing or request error.
     */
    public void testPolicyChangesNotReflectedInTestBeforePromotion() throws IOException {
        // Get current test policy state
        JsonNode testPolicyBefore = this.getPolicy("test");
        String testHashBefore =
                testPolicyBefore
                        .path(Constants.KEY_SPACE)
                        .path(Constants.KEY_HASH)
                        .path(Constants.KEY_SHA256)
                        .asText();

        // Create integration to modify draft policy
        this.createIntegration("test-policy-no-reflect");

        // Verify test policy is unchanged
        JsonNode testPolicyAfter = this.getPolicy("test");
        String testHashAfter =
                testPolicyAfter
                        .path(Constants.KEY_SPACE)
                        .path(Constants.KEY_HASH)
                        .path(Constants.KEY_SHA256)
                        .asText();
        assertEquals(
                "Test policy space hash should NOT change when only draft is modified",
                testHashBefore,
                testHashAfter);
    }
}
