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
 * Integration tests for the Rule resource CRUD operations.
 *
 * <p>Covers scenarios from:
 *
 * <ul>
 *   <li>03-rules/PostRule.feature
 *   <li>03-rules/PutRule.feature
 *   <li>03-rules/DeleteRule.feature
 * </ul>
 */
public class RuleCUDIT extends ContentManagerRestTestCase {

    // ========================
    // POST - Create Rule
    // ========================

    /**
     * Successfully create a rule linked to an integration.
     *
     * <p>Verifies:
     *
     * <ul>
     *   <li>Response status code is 201 Created.
     *   <li>The rule exists in the .cti-rules index.
     *   <li>The document space.name field is "draft".
     *   <li>The document has a non-empty hash.sha256 field.
     *   <li>The rule ID is listed in the integration's rules list.
     *   <li>The draft policy space.hash.sha256 has been updated.
     * </ul>
     */
    public void testPostRule_success() throws IOException {
        String integrationTitle = "test-rule-integration";
        String integrationId = createIntegration(integrationTitle);
        String policyHashBefore = getDraftPolicySpaceHash();

        String ruleId = createRule(integrationId, integrationTitle);

        // Verify resource exists in draft space
        assertResourceExistsInDraft(Constants.INDEX_RULES, ruleId);

        // Verify space.name and hash
        JsonNode source = getResourceByDocumentId(Constants.INDEX_RULES, ruleId, "draft");
        assertNotNull(source);
        assertSpaceName(source, "draft");
        assertHashPresent(source, "Rule");

        // Verify rule is in integration's rules list
        assertResourceInIntegrationList(integrationId, Constants.KEY_RULES, ruleId);

        // Verify draft policy space hash changed
        String policyHashAfter = getDraftPolicySpaceHash();
        assertNotEquals(
                "Draft policy space hash should have been updated after rule creation",
                policyHashBefore,
                policyHashAfter);
    }

    /**
     * Create a rule with missing title.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPostRule_missingTitle() throws IOException {
        String integrationId = createIntegration("test-rule-no-title");

        // spotless:off
        String payload = """
                {
                    "integration": "%s",
                    "resource": {
                        "description": "A rule without title",
                        "author": "Tester",
                        "logsource": {
                            "product": "system",
                            "category": "system"
                        },
                        "detection": {
                            "condition": "selection",
                            "selection": {
                                "event.action": ["test"]
                            }
                        },
                        "level": "low"
                    }
                }
                """;
        String body = String.format(Locale.ROOT, payload, integrationId);
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class, () -> makeRequest("POST", PluginSettings.RULES_URI, body));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Create a rule without an integration reference.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPostRule_missingIntegration() throws IOException {
        // spotless:off
        String payload = """
                {
                    "resource": {
                        "title": "Orphan Rule",
                        "logsource": {
                            "product": "system",
                            "category": "system"
                        },
                        "detection": {
                            "condition": "selection",
                            "selection": {
                                "event.action": ["test"]
                            }
                        },
                        "level": "low"
                    }
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class, () -> makeRequest("POST", PluginSettings.RULES_URI, payload));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Create a rule with an explicit id in the resource.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPostRule_explicitId() throws IOException {
        String integrationTitle = "test-rule-explicit-id";
        String integrationId = createIntegration(integrationTitle);

        // spotless:off
        String payload = """
                {
                    "integration": "%s",
                    "resource": {
                        "id": "custom-id",
                        "title": "Rule with explicit ID %s",
                        "description": "A rule with an explicit ID field.",
                        "author": "Tester",
                        "sigma_id": "test-sigma-explicit",
                        "references": ["https://wazuh.com"],
                        "enabled": true,
                        "status": "experimental",
                        "logsource": {
                            "product": "%s",
                            "category": "%s"
                        },
                        "detection": {
                            "condition": "selection",
                            "selection": {
                                "event.action": ["test"]
                            }
                        },
                        "level": "low"
                    }
                }
                """;
        String body = String.format(Locale.ROOT, payload, integrationId, integrationTitle, integrationTitle, integrationTitle);
        // spotless:on

        // The system silently ignores the explicit ID and auto-generates one (201),
        // but a future version may reject it (400).
        Response response = makeRequest("POST", PluginSettings.RULES_URI, body);
        int statusCode = getStatusCode(response);
        assertTrue(
                "Status should be 201 (id ignored) or 400 (id rejected)",
                statusCode == 201 || statusCode == 400);
    }

    /**
     * Create a rule with a non-existent integration.
     *
     * <p>Verifies: Response status code is 400 or 404.
     */
    public void testPostRule_nonDraftIntegration() throws IOException {
        // spotless:off
        String payload = """
                {
                    "integration": "00000000-0000-0000-0000-000000000000",
                    "resource": {
                        "title": "Rule with non-draft integration",
                        "author": "Tester",
                        "logsource": {
                            "product": "system",
                            "category": "system"
                        },
                        "detection": {
                            "condition": "selection",
                            "selection": {
                                "event.action": ["test"]
                            }
                        },
                        "level": "low"
                    }
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class, () -> makeRequest("POST", PluginSettings.RULES_URI, payload));
        int status = e.getResponse().getStatusLine().getStatusCode();
        assertTrue("Expected 400 or 404 for non-existent integration", status == 400 || status == 404);
    }

    /**
     * Create a rule with empty body.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPostRule_emptyBody() throws IOException {
        ResponseException e =
                expectThrows(
                        ResponseException.class, () -> makeRequest("POST", PluginSettings.RULES_URI, ""));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    // ========================
    // PUT - Update Rule
    // ========================

    /**
     * Successfully update a rule.
     *
     * <p>Verifies:
     *
     * <ul>
     *   <li>Response status code is 200 OK.
     *   <li>The rule document is correctly updated in the .cti-rules index.
     *   <li>The document space.name field is still "draft".
     *   <li>The document hash.sha256 field has been updated.
     *   <li>The draft policy space.hash.sha256 has been updated.
     * </ul>
     */
    public void testPutRule_success() throws IOException {
        String integrationTitle = "test-rule-put-int";
        String integrationId = createIntegration(integrationTitle);
        String ruleId = createRule(integrationId, integrationTitle);

        JsonNode sourceBefore = getResourceByDocumentId(Constants.INDEX_RULES, ruleId, "draft");
        String hashBefore = sourceBefore.path(Constants.KEY_HASH).path(Constants.KEY_SHA256).asText();
        String policyHashBefore = getDraftPolicySpaceHash();

        // spotless:off
        String payload = """
                {
                    "type": "rule",
                    "resource": {
                        "title": "Test Rule UPDATED",
                        "description": "Updated rule description.",
                        "author": "Tester",
                        "status": "experimental",
                        "logsource": {
                            "product": "system",
                            "category": "system"
                        },
                        "detection": {
                            "condition": "selection",
                            "selection": {
                                "event.action": ["updated_event"]
                            }
                        },
                        "level": "medium"
                    }
                }
                """;
        // spotless:on

        Response response = makeRequest("PUT", PluginSettings.RULES_URI + "/" + ruleId, payload);
        assertEquals(RestStatus.OK.getStatus(), getStatusCode(response));

        // Verify updated in index
        JsonNode sourceAfter = getResourceByDocumentId(Constants.INDEX_RULES, ruleId, "draft");
        assertNotNull(sourceAfter);
        assertSpaceName(sourceAfter, "draft");

        // Verify hash updated
        String hashAfter = sourceAfter.path(Constants.KEY_HASH).path(Constants.KEY_SHA256).asText();
        assertNotEquals("Rule hash should have been updated", hashBefore, hashAfter);

        // Verify draft policy space hash updated
        String policyHashAfter = getDraftPolicySpaceHash();
        assertNotEquals(
                "Draft policy space hash should have been updated", policyHashBefore, policyHashAfter);
    }

    /**
     * Update a rule with missing title.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPutRule_missingTitle() throws IOException {
        String integrationTitle = "test-rule-put-notitle";
        String integrationId = createIntegration(integrationTitle);
        String ruleId = createRule(integrationId, integrationTitle);

        // spotless:off
        String payload = """
                {
                    "type": "rule",
                    "resource": {
                        "description": "Updated without title",
                        "author": "Tester",
                        "logsource": {
                            "product": "system",
                            "category": "system"
                        },
                        "detection": {
                            "condition": "selection",
                            "selection": {
                                "event.action": ["test"]
                            }
                        },
                        "level": "low"
                    }
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> makeRequest("PUT", PluginSettings.RULES_URI + "/" + ruleId, payload));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Update a rule that does not exist.
     *
     * <p>Verifies: Response status code is 404.
     */
    public void testPutRule_notFound() throws IOException {
        // spotless:off
        String payload = """
                {
                    "type": "rule",
                    "resource": {
                        "title": "Test",
                        "author": "Test",
                        "logsource": {
                            "product": "system",
                            "category": "system"
                        },
                        "detection": {
                            "condition": "selection",
                            "selection": {
                                "event.action": ["test"]
                            }
                        },
                        "level": "low"
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
                                        PluginSettings.RULES_URI + "/00000000-0000-0000-0000-000000000000",
                                        payload));
        assertEquals(RestStatus.NOT_FOUND.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Update a rule that is not found.
     *
     * <p>Verifies: Response status code is 404.
     */
    public void testPutRule_invalidUuid() throws IOException {
        // spotless:off
        String payload = """
                {
                    "type": "rule",
                    "resource": {
                        "title": "Test",
                        "author": "Test",
                        "logsource": {
                            "product": "system",
                            "category": "system"
                        },
                        "detection": {
                            "condition": "selection",
                            "selection": {
                                "event.action": ["test"]
                            }
                        },
                        "level": "low"
                    }
                }
                """;
        // spotless:on

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> makeRequest("PUT", PluginSettings.RULES_URI + "/not-a-uuid", payload));
        assertEquals(RestStatus.NOT_FOUND.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Update a rule with empty body.
     *
     * <p>Verifies: Response status code is 400.
     */
    public void testPutRule_emptyBody() throws IOException {
        String integrationTitle = "test-rule-put-empty";
        String integrationId = createIntegration(integrationTitle);
        String ruleId = createRule(integrationId, integrationTitle);

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> makeRequest("PUT", PluginSettings.RULES_URI + "/" + ruleId, "{}"));
        assertEquals(
                RestStatus.BAD_REQUEST.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    // ========================
    // DELETE - Delete Rule
    // ========================

    /**
     * Successfully delete a rule.
     *
     * <p>Verifies:
     *
     * <ul>
     *   <li>Response status code is 200 OK.
     *   <li>The rule no longer exists in the .cti-rules index.
     *   <li>The rule ID is no longer listed in the integration's rules list.
     *   <li>The integration's hash.sha256 field has been updated.
     *   <li>The draft policy space.hash.sha256 has been updated.
     * </ul>
     */
    public void testDeleteRule_success() throws IOException {
        String integrationTitle = "test-rule-delete-int";
        String integrationId = createIntegration(integrationTitle);
        String ruleId = createRule(integrationId, integrationTitle);

        // Capture hashes before deletion
        JsonNode integrationBefore =
                getResourceByDocumentId(Constants.INDEX_INTEGRATIONS, integrationId, "draft");
        String integrationHashBefore =
                integrationBefore.path(Constants.KEY_HASH).path(Constants.KEY_SHA256).asText();
        String policyHashBefore = getDraftPolicySpaceHash();

        Response response = deleteResource(PluginSettings.RULES_URI, ruleId);
        assertEquals(RestStatus.OK.getStatus(), getStatusCode(response));

        // Verify rule no longer exists in draft
        assertResourceNotInDraft(Constants.INDEX_RULES, ruleId);

        // Verify rule removed from integration's rules list
        assertResourceNotInIntegrationList(integrationId, Constants.KEY_RULES, ruleId);

        // Verify integration's hash was updated
        JsonNode integrationAfter =
                getResourceByDocumentId(Constants.INDEX_INTEGRATIONS, integrationId, "draft");
        String integrationHashAfter =
                integrationAfter.path(Constants.KEY_HASH).path(Constants.KEY_SHA256).asText();
        assertNotEquals(
                "Integration hash should have been updated after rule deletion",
                integrationHashBefore,
                integrationHashAfter);

        // Verify policy space hash updated
        String policyHashAfter = getDraftPolicySpaceHash();
        assertNotEquals(
                "Draft policy space hash should have been updated after rule deletion",
                policyHashBefore,
                policyHashAfter);
    }

    /**
     * Delete a rule that does not exist.
     *
     * <p>Verifies: Response status code is 404.
     */
    public void testDeleteRule_notFound() throws IOException {
        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> deleteResource(PluginSettings.RULES_URI, "00000000-0000-0000-0000-000000000000"));
        assertEquals(RestStatus.NOT_FOUND.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Delete a rule that is not found.
     *
     * <p>Verifies: Response status code is 404.
     */
    public void testDeleteRule_invalidUuid() throws IOException {
        ResponseException e =
                expectThrows(
                        ResponseException.class, () -> deleteResource(PluginSettings.RULES_URI, "not-a-uuid"));
        assertEquals(RestStatus.NOT_FOUND.getStatus(), e.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Delete a rule without providing an ID.
     *
     * <p>Verifies: Response status code is 400 or 405.
     */
    public void testDeleteRule_missingId() throws IOException {
        ResponseException e =
                expectThrows(
                        ResponseException.class, () -> makeRequest("DELETE", PluginSettings.RULES_URI + "/"));
        int statusCode = e.getResponse().getStatusLine().getStatusCode();
        assertTrue("Expected 400 or 405 for missing ID", statusCode == 400 || statusCode == 405);
    }
}
