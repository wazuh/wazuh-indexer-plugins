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

import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.junit.After;
import org.junit.Ignore;

import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

import com.wazuh.contentmanager.ContentManagerRestTestCase;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * End-to-end checks for the reconciliation that deletes from Security Analytics the standard
 * content CTI no longer publishes (wazuh-indexer-plugins#1818).
 *
 * <p>The unit tests cover the diff, the deletion order and the guards. What they cannot cover is
 * the five searches the diff is built on -- the field names, the nested query on the detectors and
 * the {@code search_after} pagination -- or the Security Analytics deletions themselves. This test
 * runs both against a real cluster with Security Analytics installed.
 *
 * <p>Security Analytics is seeded through the plugin's own replication rather than by hand: the
 * content is written, the consumer's pending phases are set, and a sync pass pushes it across. Only
 * the detector is written by hand, because detector creation is off in this cluster.
 *
 * <p><b>Not run by the suite.</b> It drives real sync passes, and the first one loads the whole CTI
 * catalog, so it takes around ten minutes and needs the catalog to be reachable. That is past the
 * twenty-minute cap the test framework puts on one suite, and it is more than a shared CI run
 * should spend. Run it on its own:
 *
 * <pre>
 * ./gradlew :wazuh-indexer-content-manager:integTest -PnumNodes=1 \
 *     --tests "*StandardSpaceReconciliationIT*"
 * </pre>
 *
 * <p>It is kept because it is the only thing that exercises the five searches against real indices
 * and the real Security Analytics deletions, and it has already earned it: it caught the reads
 * sorting on fields that a dynamically mapped index makes {@code text}.
 */
@Ignore(
        "Takes about ten minutes and needs the CTI catalog; run it on its own, see the class javadoc")
public class StandardSpaceReconciliationIT extends ContentManagerRestTestCase {

    private static final String LOG_TYPES_INDEX = ".opensearch-sap-log-types-config";
    private static final String SAP_RULES_INDEX = ".opensearch-sap-pre-packaged-rules-config";
    private static final String DETECTORS_INDEX = ".opensearch-sap-detectors-config";
    private static final String CONSUMERS_INDEX = ".wazuh-cti-consumers";

    /** Kept: its integration is still published. */
    private static final String KEPT_INTEGRATION = "it1818-kept-integration";

    /** Removed from the content half way through, so Security Analytics is left holding it. */
    private static final String STALE_INTEGRATION = "it1818-stale-integration";

    /**
     * Rule ids are UUIDs, as CTI's own are. Security Analytics compiles the whole document as Sigma
     * and reads its {@code id} field as the rule identifier, so anything else is rejected with {@code
     * SigmaIdentifierError} on the push.
     */
    private static final String KEPT_RULE = "1818a001-0000-4000-8000-000000000001";

    private static final String STALE_RULE = "1818a002-0000-4000-8000-000000000002";

    /**
     * The Security Analytics log type name of each integration, which is its {@code metadata.title}
     * and the {@code logsource.product} its rules have to declare. Held to {@code [a-z0-9_-]{2,50}}
     * by {@code WIndexIntegrationRequest.validate}, which is also the shape of CTI's own titles.
     */
    private static final String KEPT_LOG_TYPE = "it1818-kept";

    private static final String STALE_LOG_TYPE = "it1818-stale";

    /** A log type and a rule of another space, which the reconciliation must never touch. */
    private static final String CUSTOM_INTEGRATION = "it1818-custom-integration";

    private static final String CUSTOM_RULE = "it1818-custom-rule";

    @After
    public void cleanUpTestResources() throws IOException {
        for (String id : List.of(KEPT_INTEGRATION, STALE_INTEGRATION)) {
            deleteIfPresent(Constants.INDEX_INTEGRATIONS, id);
            deleteIfPresent(LOG_TYPES_INDEX, id);
            deleteIfPresent(DETECTORS_INDEX, id);
        }
        for (String id : List.of(KEPT_RULE, STALE_RULE)) {
            deleteIfPresent(Constants.INDEX_RULES, id);
        }
        deleteIfPresent(LOG_TYPES_INDEX, CUSTOM_INTEGRATION);
        deleteIfPresent(SAP_RULES_INDEX, CUSTOM_RULE);
        for (String index : List.of(Constants.INDEX_INTEGRATIONS, Constants.INDEX_RULES)) {
            this.refreshIndex(index);
        }
    }

    /**
     * The whole of the issue, in one pass over a real cluster.
     *
     * <ol>
     *   <li>Two integrations with one rule each are published and replicated to Security Analytics.
     *   <li>One integration and the other one's rule are removed from the content, as CTI removing
     *       them would.
     *   <li>A sync pass reconciles: the integration and the rule go from Security Analytics, and the
     *       detector of the integration that is left without rules goes with them.
     *   <li>What is still published stays, and so does the content of another space.
     * </ol>
     *
     * @throws Exception on communication error, or if the guarantee is not observed in time.
     */
    public void testReconciliation_deletesWhatCtiNoLongerPublishes() throws Exception {
        // The sync reports a resource Security Analytics rejected as "N of M could not be sent" and
        // logs the reason per resource at debug, so without this a failure here says what did not
        // happen and never why.
        this.enableSyncDebugLogging();

        // Let the cluster load its content first. The fixtures cannot be seeded before this pass:
        // initialising from the catalog snapshot wipes the standard space before loading it, through
        // StandardSpaceWiper, so anything written beforehand goes with it.
        this.runSyncPass();

        this.seedCustomSpaceResources();

        // The titles are the Security Analytics log type names, and WIndexIntegrationRequest.validate
        // holds them to [a-z0-9_-]{2,50}: anything with a space or a capital is rejected on the push.
        // CTI's own titles look like this too -- windows, apache-http.
        this.indexIntegration(KEPT_INTEGRATION, KEPT_LOG_TYPE, KEPT_RULE);
        this.indexIntegration(STALE_INTEGRATION, STALE_LOG_TYPE, STALE_RULE);
        this.indexRule(KEPT_RULE, KEPT_LOG_TYPE, "it1818-kept-rule-title");
        this.indexRule(STALE_RULE, STALE_LOG_TYPE, "it1818-stale-rule-title");

        // Replicate what was just published, through the plugin's own phases. The content is already
        // up to date, so the pass owes nothing and the phases have to be asked for.
        this.setPendingPhases("integrations", "rules");
        this.runSyncPass();
        assertBusy(
                () -> {
                    assertTrue(
                            "the kept integration must reach Security Analytics",
                            this.logTypeExists(KEPT_INTEGRATION));
                    assertTrue(
                            "the stale integration must reach Security Analytics",
                            this.logTypeExists(STALE_INTEGRATION));
                    assertTrue("the kept rule must reach Security Analytics", this.sapRuleExists(KEPT_RULE));
                    assertTrue(
                            "the stale rule must reach Security Analytics", this.sapRuleExists(STALE_RULE));
                },
                60,
                TimeUnit.SECONDS);

        // Detector creation is off in this cluster, so the detector of the integration that is about
        // to lose its rules is written by hand. source=standard is what tells the diff the content
        // manager owns it; a user's own detector carries source=custom and is never read.
        this.indexDetector(KEPT_INTEGRATION);

        // CTI stops publishing the integration, and the other integration's only rule.
        this.deleteContent(Constants.INDEX_INTEGRATIONS, STALE_INTEGRATION);
        this.deleteContent(Constants.INDEX_RULES, KEPT_RULE);

        // A pass with nothing to sync and nothing pending: the reconciliation has to run on it all
        // the same, which is what makes a failed deletion retry at all.
        this.runSyncPass();

        assertBusy(
                () -> {
                    assertFalse(
                            "an integration CTI no longer publishes must go from Security Analytics",
                            this.logTypeExists(STALE_INTEGRATION));
                    assertFalse(
                            "a rule CTI no longer publishes must go from Security Analytics",
                            this.sapRuleExists(KEPT_RULE));
                    assertFalse(
                            "a detector whose rules CTI deleted keeps its monitor and goes on matching, so"
                                    + " it must go too",
                            this.detectorExists(KEPT_INTEGRATION));
                },
                90,
                TimeUnit.SECONDS);

        assertTrue(
                "the integration CTI still publishes must stay", this.logTypeExists(KEPT_INTEGRATION));
        assertTrue("the rule CTI still publishes must stay", this.sapRuleExists(STALE_RULE));
        assertTrue(
                "a log type of the custom space must never be touched",
                this.logTypeExists(CUSTOM_INTEGRATION));
        assertTrue("a rule of the custom space must never be touched", this.sapRuleExists(CUSTOM_RULE));
    }

    // --- Seeding -----------------------------------------------------------------------------

    /** Indexes a standard integration listing one rule. */
    private void indexIntegration(String id, String title, String ruleId) throws IOException {
        // spotless:off
        String document = """
                {
                  "document": {
                    "id": "%s",
                    "enabled": true,
                    "category": "security",
                    "metadata": {"title": "%s", "description": "Fixture for #1818"},
                    "rules": ["%s"],
                    "decoders": [],
                    "kvdbs": [],
                    "detector": {"enabled": true, "interval": 5, "source": ["wazuh-events-v5-security"]}
                  },
                  "space": {"name": "standard"}
                }""";
        // spotless:on
        this.makeRequest(
                "PUT",
                "/" + Constants.INDEX_INTEGRATIONS + "/_doc/" + id + "?refresh=true",
                String.format(Locale.ROOT, document, id, title, ruleId));
    }

    /**
     * Indexes a standard rule. Its {@code logsource.product} has to name the integration that lists
     * it, or the rules phase holds it back instead of sending it. Security Analytics compiles the
     * document as Sigma on the way in, so it also needs a {@code metadata.date}: without one the push
     * fails with a {@code NullPointerException} out of {@code Rule}, not a validation error. It is
     * written ISO because the content index maps that field as a {@code date}, and Sigma takes both
     * that and {@code yyyy/MM/dd}.
     */
    private void indexRule(String id, String integrationTitle, String ruleTitle) throws IOException {
        // spotless:off
        String document = """
                {
                  "document": {
                    "id": "%s",
                    "enabled": true,
                    "sigma_id": "%s",
                    "status": "experimental",
                    "metadata": {
                      "title": "%s",
                      "description": "Fixture for #1818",
                      "author": "Tester",
                      "date": "2026-11-19",
                      "references": ["https://wazuh.com"]
                    },
                    "logsource": {"product": "%s", "category": "%s"},
                    "detection": {"condition": "selection", "selection": {"event.action": ["it1818"]}},
                    "level": "low"
                  },
                  "space": {"name": "standard"}
                }""";
        // spotless:on
        this.makeRequest(
                "PUT",
                "/" + Constants.INDEX_RULES + "/_doc/" + id + "?refresh=true",
                String.format(
                        Locale.ROOT, document, id, id, ruleTitle, integrationTitle, integrationTitle));
    }

    /**
     * Writes a log type and a pre-packaged rule in the custom space, to prove the diff reads the
     * standard space alone. Neither is parsed by anything on the way out, because neither is meant to
     * be deleted.
     */
    private void seedCustomSpaceResources() throws IOException {
        this.makeRequest(
                "PUT",
                "/" + LOG_TYPES_INDEX + "/_doc/" + CUSTOM_INTEGRATION + "?refresh=true",
                String.format(
                        Locale.ROOT,
                        "{\"name\":\"it1818-custom\",\"description\":\"\",\"category\":\"Security\","
                                + "\"space\":\"custom\",\"tags\":{},\"document.id\":\"%s\"}",
                        CUSTOM_INTEGRATION));
        this.makeRequest(
                "PUT",
                "/" + SAP_RULES_INDEX + "/_doc/" + CUSTOM_RULE + "?refresh=true",
                String.format(
                        Locale.ROOT,
                        "{\"rule\":{\"category\":\"it1818\",\"title\":\"IT 1818 Custom rule\","
                                + "\"space\":\"custom\",\"document\":{\"id\":\"%s\"}}}",
                        CUSTOM_RULE));
    }

    /**
     * Indexes a detector the content manager would have created, whose id is its integration's.
     *
     * <p>Three things it has to carry, each learned the hard way. A {@code schedule}, or Security
     * Analytics fails the deletion while parsing it. Its rules under {@code pre_packaged_rules},
     * which is where a standard detector really keeps them. And {@code detector_type} mapped {@code
     * keyword}, as the real mapping has it: dynamically mapped it becomes {@code text}, and the
     * {@code match} query that refuses to delete a log type with active detectors then cross-matches
     * any other detector sharing a token with its name.
     *
     * <p>{@code detector.source} is added to the mapping for the same reason: without it the nested
     * query the diff runs would match nothing and the test would pass without proving anything.
     */
    private void indexDetector(String integrationId) throws IOException {
        try {
            this.makeRequest("PUT", "/" + DETECTORS_INDEX, DETECTORS_MAPPING);
        } catch (ResponseException e) {
            if (e.getResponse().getStatusLine().getStatusCode() != 400) {
                throw e;
            }
            this.makeRequest("PUT", "/" + DETECTORS_INDEX + "/_mapping", DETECTOR_SOURCE_MAPPING);
        }
        // spotless:off
        String detector = """
                {
                  "detector": {
                    "name": "%s",
                    "enabled": true,
                    "source": "standard",
                    "type": "detector",
                    "detector_type": "%s",
                    "monitor_id": [],
                    "schedule": {"period": {"interval": 5, "unit": "MINUTES"}},
                    "inputs": [{"detector_input": {
                        "description": "Fixture for #1818",
                        "indices": ["wazuh-events-v5-security"],
                        "custom_rules": [],
                        "pre_packaged_rules": [{"id": "%s"}]
                    }}],
                    "triggers": []
                  }
                }""";
        // spotless:on
        this.makeRequest(
                "PUT",
                "/" + DETECTORS_INDEX + "/_doc/" + integrationId + "?refresh=true",
                String.format(Locale.ROOT, detector, integrationId, KEPT_LOG_TYPE, KEPT_RULE));
    }

    // spotless:off
    private static final String DETECTORS_MAPPING = """
            {
              "mappings": {
                "properties": {
                  "detector": {
                    "type": "nested",
                    "properties": {
                      "name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                      "enabled": {"type": "boolean"},
                      "source": {"type": "keyword"},
                      "detector_type": {"type": "keyword"},
                      "inputs": {
                        "type": "nested",
                        "properties": {
                          "detector_input": {
                            "type": "nested",
                            "properties": {
                              "custom_rules": {"type": "nested", "properties": {"id": {"type": "text"}}},
                              "pre_packaged_rules": {"type": "nested", "properties": {"id": {"type": "text"}}}
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }""";

    private static final String DETECTOR_SOURCE_MAPPING = """
            {"properties": {"detector": {"type": "nested", "properties": {
                "source": {"type": "keyword"},
                "detector_type": {"type": "keyword"}}}}}""";
    // spotless:on

    // --- Driving a sync pass ------------------------------------------------------------------

    /**
     * Waits for the pass this test started to finish.
     *
     * <p>The endpoint answers before the pass has written anything, so the status still reads {@code
     * ready} from the previous one for a moment. Waiting for {@code ready} alone would therefore
     * return immediately and let the next step fire a request the running pass rejects with 409. So
     * this waits for the pass to be seen running first, and only tolerates never seeing it when the
     * whole pass was shorter than the poll.
     *
     * @throws Exception on communication error, or if the pass never finishes.
     */
    private void awaitPassFinished() throws Exception {
        try {
            assertBusy(() -> assertEquals("running", this.consumerField("status")), 2, TimeUnit.MINUTES);
        } catch (AssertionError neverSeenRunning) {
            // A pass with nothing to do can finish between two polls. Fall through to the wait
            // below, which is the one that matters.
            logger.info("the pass was never observed running; it was probably a no-op");
        }
        assertBusy(
                () -> {
                    String status = this.consumerField("status");
                    assertTrue(
                            "waiting for the sync pass to finish, status is [" + status + "]",
                            "ready".equals(status) || "failed".equals(status));
                },
                15,
                TimeUnit.MINUTES);
    }

    /**
     * Runs one sync pass of our own and waits for it to finish.
     *
     * <p>Winning the guard is the wait: {@code POST /update} answers 409 while any pass is running,
     * the node's own first one included, so retrying until it answers 202 is what makes sure the pass
     * that follows is ours and nothing else is in flight. The window covers a first pass initialising
     * the content from the catalog, which takes minutes.
     *
     * @throws Exception on communication error.
     */
    private void runSyncPass() throws Exception {
        assertBusy(
                () -> {
                    try {
                        Response response = this.makeRequest("POST", PluginSettings.UPDATE_URI, "");
                        assertEquals(202, this.getStatusCode(response));
                    } catch (ResponseException e) {
                        throw new AssertionError("a sync pass is already running; retrying", e);
                    }
                },
                15,
                TimeUnit.MINUTES);
        this.awaitPassFinished();
    }

    /**
     * Marks phases as pending on the ruleset consumer, so the next pass pushes them to Security
     * Analytics although it applies no offset of its own. Without this, a pass that finds the content
     * already up to date would push nothing and the fixtures would never be replicated.
     *
     * @param phases the phases to mark pending.
     * @throws IOException on communication error.
     */
    private void setPendingPhases(String... phases) throws IOException {
        StringBuilder list = new StringBuilder("[");
        for (int i = 0; i < phases.length; i++) {
            if (i > 0) {
                list.append(",");
            }
            list.append("\"").append(phases[i]).append("\"");
        }
        list.append("]");
        this.makeRequest(
                "POST",
                "/" + CONSUMERS_INDEX + "/_update/" + Constants.CONSUMER_TYPE_RULESET + "?refresh=true",
                "{\"doc\":{\"pending_sync_phases\":" + list + "}}");
    }

    /**
     * Raises the sync loggers to debug for the rest of the run, so a resource Security Analytics
     * rejects says why in the cluster log instead of only being counted.
     *
     * @throws IOException on communication error.
     */
    private void enableSyncDebugLogging() throws IOException {
        this.makeRequest(
                "PUT",
                "/_cluster/settings",
                "{\"transient\":{"
                        + "\"logger.com.wazuh.contentmanager.cti.catalog.service\":\"DEBUG\","
                        + "\"logger.org.opensearch.securityanalytics.transport\":\"DEBUG\"}}");
    }

    /** Reads a field of the ruleset consumer document, or {@code ""} while it does not exist yet. */
    private String consumerField(String field) throws IOException {
        try {
            JsonNode doc =
                    this.responseAsJson(
                            this.makeRequest(
                                    "GET", "/" + CONSUMERS_INDEX + "/_doc/" + Constants.CONSUMER_TYPE_RULESET));
            return doc.path("_source").path(field).asText("");
        } catch (ResponseException e) {
            if (e.getResponse().getStatusLine().getStatusCode() == 404) {
                return "";
            }
            throw e;
        }
    }

    // --- Assertions ---------------------------------------------------------------------------

    /**
     * {@code match_phrase} and not {@code term}, because these indices are auto-created from the
     * first write with no template and their string fields may be mapped either {@code keyword} or
     * {@code text}. A {@code term} on a {@code text} field would never match an id with hyphens in
     * it, and the assertion would fail on its own query rather than on what the product did.
     */
    private boolean logTypeExists(String documentId) throws IOException {
        return this.countBy(
                        LOG_TYPES_INDEX, "{\"match_phrase\":{\"document.id\":\"" + documentId + "\"}}")
                > 0;
    }

    private boolean sapRuleExists(String documentId) throws IOException {
        return this.countBy(
                        SAP_RULES_INDEX, "{\"match_phrase\":{\"rule.document.id\":\"" + documentId + "\"}}")
                > 0;
    }

    private boolean detectorExists(String detectorId) throws IOException {
        return this.countBy(DETECTORS_INDEX, "{\"ids\":{\"values\":[\"" + detectorId + "\"]}}") > 0;
    }

    /** Counts the documents a query matches, treating a missing index as zero. */
    private long countBy(String index, String query) throws IOException {
        try {
            this.makeRequest("POST", "/" + index + "/_refresh", "");
            JsonNode response =
                    this.responseAsJson(
                            this.makeRequest("POST", "/" + index + "/_count", "{\"query\":" + query + "}"));
            return response.path("count").asLong(0);
        } catch (ResponseException e) {
            if (e.getResponse().getStatusLine().getStatusCode() == 404) {
                return 0;
            }
            throw e;
        }
    }

    private void deleteContent(String index, String id) throws IOException {
        this.makeRequest("DELETE", "/" + index + "/_doc/" + id + "?refresh=true");
    }

    private void deleteIfPresent(String index, String id) throws IOException {
        try {
            this.makeRequest("DELETE", "/" + index + "/_doc/" + id + "?refresh=true");
        } catch (ResponseException e) {
            int status = e.getResponse().getStatusLine().getStatusCode();
            if (status != 404) {
                throw e;
            }
        }
    }
}
