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
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.hc.core5.http.ParseException;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.core.rest.RestStatus;

import java.io.IOException;
import java.util.Locale;
import java.util.UUID;

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

    /** Rules this test created, so the promotion can be scoped to them. */
    private final java.util.List<String> ownRuleIds = new java.util.ArrayList<>();

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
        assertEquals("'integration' field not provided", detectionNode.path("reason").asText());
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
    // Detection (percolate) Tests
    // ========================

    /**
     * The reported bug, plus the cases that keep the fix honest, in one test.
     *
     * <p>One test rather than four because the setup ends in a draft-to-test promotion, and promotion
     * is global: every promotion sweeps up whatever other test classes happen to have in draft, so
     * each one is a chance for this class to break an unrelated one. The four assertions below are
     * independent, and each carries the response in its failure message.
     *
     * <p>What this exercises is the real thing: the rules are compiled by Security Analytics and
     * percolated against the event by alerting's percolator, in a cluster where both plugins are
     * installed and rule evaluation is not mocked.
     *
     * @throws IOException on communication error
     */
    public void testDetectionPercolatesRulesLikeADetector() throws IOException {
        String integrationTitle = "logtest-percolate";
        this.createEventsSourceIndex();
        String integrationId = this.createIntegration(integrationTitle);
        // The reported SQL-injection rule, trimmed to the branch under test.
        this.createRuleWithDetection(
                integrationId,
                integrationTitle,
                "sqli",
                """
                {"condition": "selection and selection_1",
                 "selection": {"http.request.method": "GET"},
                 "selection_1": {"url.original|contains": ["UNION SELECT", "UNION ALL SELECT"]}}
                """);
        // process.name is a real WCS field, so the rule is valid, but the source index this
        // integration's detector reads does not map it — so no detector could ever match it.
        this.createRuleWithDetection(
                integrationId,
                integrationTitle,
                "unmapped",
                """
                {"condition": "selection",
                 "selection": {"process.name|contains": "anything"}}
                """);
        this.copyOwnResourcesToTestSpace(integrationId);

        // 1. The rule against the case it was written in: this is the branch that does produce a
        // finding in production, so it must match here too.
        JsonNode exactCase =
                this.detect(
                        integrationId,
                        """
                        {"http": {"request": {"method": "GET"}},
                         "url": {"original": "/item.php?id=-1 UNION SELECT username,password FROM users--"}}
                        """);
        assertEquals(exactCase.toString(), "success", exactCase.path("status").asText());
        assertEquals(
                "the rule must match its own case: " + exactCase, 1, exactCase.path("rules_matched").asInt());
        assertFalse(
                "matched_conditions must carry the query that matched: " + exactCase,
                exactCase.path("matches").path(0).path("matched_conditions").isEmpty());

        // 2. The reported case: the rule says UNION SELECT, the event says UNION sElect. String
        // comparison is case-sensitive, so a deployed detector produces no finding for this event —
        // and this is the assertion that pins logtest to that answer. Before this change logtest
        // reported a match here, which is what made it untrustworthy. Making `contains`
        // case-insensitive is tracked separately; if that lands, this expectation flips to 1 in the
        // same commit that changes the analyzer, and the detector flips with it.
        JsonNode differentCase =
                this.detect(
                        integrationId,
                        """
                        {"http": {"request": {"method": "GET"}},
                         "url": {"original": "/item.php?id=-1 UNION sElect username,password FROM users--"}}
                        """);
        assertEquals(
                "logtest must not claim a match a detector would not produce: " + differentCase,
                0,
                differentCase.path("rules_matched").asInt());

        // 3. An event without the pattern at all, so the comparison has not become match-nothing
        // for the wrong reason.
        JsonNode noMatch =
                this.detect(
                        integrationId,
                        """
                        {"http": {"request": {"method": "GET"}}, "url": {"original": "/index.php?id=1"}}
                        """);
        assertEquals(
                "an unrelated event must not match: " + noMatch, 0, noMatch.path("rules_matched").asInt());

        // 4. The rule over the unmapped field is reported, not quietly dropped: the percolator refuses
        // to store a query over a field the source index does not map, which is exactly why a detector
        // would never match it either.
        assertEquals(
                "the rule that cannot be evaluated must be reported: " + noMatch,
                1,
                noMatch.path("rules_skipped").asInt());
        assertFalse(
                "the skip must say why: " + noMatch,
                noMatch.path("skipped").path(0).path("reason").asText().isEmpty());
        assertEquals(
                "both rules are in scope: " + noMatch, 2, noMatch.path("rules_evaluated").asInt());
    }

    // ========================
    // Detection Helpers
    // ========================

    /**
     * Creates the WCS event index a threat detector for this integration would read, so the compiled
     * rule queries have real field mappings to resolve against.
     *
     * <p>{@code cloud-services} is the category {@link #createIntegration(String)} uses, and a
     * detector with no explicit source falls back to {@code wazuh-events-v5-<category>}.
     *
     * @throws IOException on communication error
     */
    private void createEventsSourceIndex() throws IOException {
        String dataStream = "wazuh-events-v5-cloud-services";

        // The setup plugin declares wazuh-events-v5* as a data stream, so this name cannot be a
        // plain index. Create the stream, tolerating the case where a previous test already did.
        try {
            Response created = this.makeRequest("PUT", "/_data_stream/" + dataStream);
            assertEquals(RestStatus.OK.getStatus(), this.getStatusCode(created));
        } catch (ResponseException e) {
            assertEquals(
                    "creating the events data stream must not fail for any other reason",
                    RestStatus.BAD_REQUEST.getStatus(),
                    e.getResponse().getStatusLine().getStatusCode());
        }

        // Ingest one event so the fields the rules reference get mapped. The events template is
        // `dynamic: strict_allow_templates`, so a field is mapped only once a document carries it —
        // which is exactly the production precondition: until events have been ingested, a compiled
        // rule query has nothing to resolve against and no detector can match it either.
        //
        // `process.name` is deliberately absent. The second rule of the detection test references
        // it, and its whole point is to be a rule the percolator must refuse.
        // spotless:off
        String event = """
                {"@timestamp": "2026-09-04T10:16:00.000Z",
                 "http": {"request": {"method": "GET"}},
                 "url": {"original": "/seed"}}
                """;
        // spotless:on
        Response indexed = this.makeRequest("POST", "/" + dataStream + "/_doc?refresh=true", event);
        assertEquals(RestStatus.CREATED.getStatus(), this.getStatusCode(indexed));
    }

    /**
     * Creates a rule with a caller-supplied detection block, which the shared helper does not allow.
     *
     * @param integrationId the parent integration ID
     * @param integrationTitle the integration title, used as log source
     * @param name distinguishes this rule from the others of the same integration
     * @param detectionJson the Sigma detection block
     * @return the generated rule ID
     * @throws IOException on communication error
     */
    private String createRuleWithDetection(
            String integrationId, String integrationTitle, String name, String detectionJson)
            throws IOException {
        // spotless:off
        String payload = String.format(Locale.ROOT, """
                {
                    "integration": "%s",
                    "resource": {
                        "metadata": {
                            "title": "Rule %s for %s",
                            "description": "A rule for integration tests.",
                            "author": "Tester",
                            "references": ["https://wazuh.com"]
                        },
                        "sigma_id": "%s-%s",
                        "enabled": true,
                        "status": "experimental",
                        "logsource": {"product": "%s", "category": "%s"},
                        "detection": %s,
                        "level": "high"
                    }
                }
                """, integrationId, name, integrationTitle, integrationTitle, name, integrationTitle,
                integrationTitle, detectionJson);
        // spotless:on

        Response response = this.makeRequest("POST", PluginSettings.RULES_URI, payload);
        assertEquals(RestStatus.CREATED.getStatus(), this.getStatusCode(response));
        String id = (String) this.parseResponseAsMap(response).get("message");
        assertNotNull("Rule ID should not be null", id);
        this.ownRuleIds.add(id);
        return id;
    }

    /**
     * Runs the detection-only endpoint against a pre-normalized event, which needs no Engine.
     *
     * @param integrationId the integration whose rules to evaluate
     * @param inputJson the normalized event
     * @return the detection result
     * @throws IOException on communication error
     */
    private JsonNode detect(String integrationId, String inputJson) throws IOException {
        // spotless:off
        String payload = String.format(Locale.ROOT, """
                {"integration": "%s", "space": "test", "input": %s}
                """, integrationId, inputJson);
        // spotless:on

        Response response = this.makeRequest("POST", PluginSettings.LOGTEST_DETECTION_URI, payload);
        assertEquals(RestStatus.OK.getStatus(), this.getStatusCode(response));
        return this.responseAsJson(response).path("message");
    }

    // ========================
    // Promote Helper
    // ========================

    /**
     * Moves this test's integration and its rules into the {@code test} space, and leaves draft as it
     * found it.
     *
     * <p>Not via {@link #promoteDraftToTest()}: promotion applies to the whole space, so in a suite
     * that shares one cluster it promotes whatever another test class happens to have in draft, which
     * is enough to make that class fail — and it does, intermittently, depending on the order the
     * classes run in. Detection reads these two indices and nothing else, so copying the documents
     * the plugin just wrote, then deleting the draft originals, exercises the same path while leaving
     * no trace for anyone else. Promotion itself is covered by
     * {@link #testLogtestWithPromotedIntegration()}.
     *
     * @param integrationId the integration to move, with its rules
     * @throws IOException on communication error
     */
    private void copyOwnResourcesToTestSpace(String integrationId) throws IOException {
        for (String ruleId : this.ownRuleIds) {
            this.copyDocumentToTestSpace(Constants.INDEX_RULES, ruleId);
        }
        this.copyDocumentToTestSpace(Constants.INDEX_INTEGRATIONS, integrationId);

        // Remove the draft originals so no other class sees them, in particular so a promotion
        // elsewhere does not pick them up.
        for (String ruleId : this.ownRuleIds) {
            this.deleteResource(PluginSettings.RULES_URI, ruleId);
        }
        this.deleteResource(PluginSettings.INTEGRATIONS_URI, integrationId);

        this.refreshIndex(Constants.INDEX_INTEGRATIONS);
        this.refreshIndex(Constants.INDEX_RULES);
        // Deleting the draft originals rewrites the draft policy; refresh it too so the next test's
        // draft policy check reads a searchable index.
        this.refreshIndex(Constants.INDEX_POLICIES);
    }

    /**
     * Copies one content document from the draft space into the test space.
     *
     * <p>The copy is the document the plugin itself wrote, with only {@code space.name} changed, so
     * the test does not depend on a hand-written document shape.
     *
     * @param index the content index
     * @param documentId the resource id
     * @throws IOException on communication error
     */
    private void copyDocumentToTestSpace(String index, String documentId) throws IOException {
        JsonNode draft = this.getResourceByDocumentId(index, documentId, "draft");
        assertNotNull("draft document must exist before copying: " + documentId, draft);

        ObjectNode copy = draft.deepCopy();
        ObjectNode space = copy.with(Constants.KEY_SPACE);
        space.put(Constants.KEY_NAME, "test");

        Response response =
                this.makeRequest(
                        "PUT",
                        "/" + index + "/_doc/" + UUID.randomUUID() + "?refresh=true",
                        MAPPER.writeValueAsString(copy));
        assertEquals(RestStatus.CREATED.getStatus(), this.getStatusCode(response));
    }

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
