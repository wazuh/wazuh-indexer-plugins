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
package com.wazuh.setup;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;

import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.test.rest.OpenSearchRestTestCase;
import org.junit.After;
import org.junit.Before;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;

/**
 * Integration tests verifying that the setup plugin provisions the threat-intel content indices:
 * for every alias name, a concrete {@code <name>-a} index, an index template covering {@code
 * <name>*} and the public alias pointing at the concrete index.
 *
 * <p>The mapping assertions reproduce the diagnostic from issue #1476: when {@code
 * wazuh-threatintel-enrichments-a} is missing, the CTI writer's first write auto-creates a
 * dynamically mapped index under the alias name, {@code document.type} becomes a {@code text} field
 * and the home overview's Threat catalog widget group fails with a 400.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.SUITE)
public class ThreatIntelIndicesIT extends OpenSearchRestTestCase {

    private static final String ENRICHMENTS = "wazuh-threatintel-enrichments";

    /** Suffix of the concrete index each public alias points at. */
    private static final String SUFFIX_A = "-a";

    // spotless:off
    private static final String[] ALIASES = {
        ENRICHMENTS,
        "wazuh-threatintel-filters",
        "wazuh-threatintel-decoders",
        "wazuh-threatintel-rules",
        "wazuh-threatintel-kvdbs",
        "wazuh-threatintel-integrations",
        "wazuh-threatintel-policies",
        ".wazuh-threatintel-vulnerabilities"
    };
    // spotless:on

    /** Registered after the content indices, so its presence marks them all done. */
    private static final String SETTINGS_INDEX = ".wazuh-settings";

    private static final int MAX_WAIT_SECONDS = 120;
    private static final int POLL_INTERVAL_MS = 500;

    /**
     * Preserves indices upon test completion. The SetupPlugin creates indices during cluster
     * initialization, and these need to persist across all tests since the plugin only creates them
     * once.
     *
     * @return true to preserve indices
     */
    @Override
    protected boolean preserveIndicesUponCompletion() {
        return true;
    }

    /**
     * Preserves data streams upon test completion. The SetupPlugin creates data streams during
     * initialization, and these need to persist across all tests.
     *
     * @return true to preserve data streams
     */
    @Override
    protected boolean preserveDataStreamsUponCompletion() {
        return true;
    }

    /**
     * Preserves index templates upon test completion. The SetupPlugin creates index templates for
     * the content indices, and these need to persist across all tests.
     *
     * @return true to preserve templates
     */
    @Override
    protected boolean preserveTemplatesUponCompletion() {
        return true;
    }

    /**
     * Waits for the plugin initialization to complete by polling for the settings index, which is
     * registered after the content indices in the setup plugin's initialization order. CI runners may
     * be slow due to resource constraints; timeout is {@value #MAX_WAIT_SECONDS} seconds.
     *
     * @throws Exception if the index is not created within the timeout
     */
    @Before
    public void waitForPluginInitialization() throws Exception {
        long startTime = System.currentTimeMillis();
        long timeout = TimeUnit.SECONDS.toMillis(MAX_WAIT_SECONDS);

        while (System.currentTimeMillis() - startTime < timeout) {
            try {
                client().performRequest(new Request("GET", "/" + SETTINGS_INDEX));
                logger.info("Setup plugin initialization is ready");
                return;
            } catch (ResponseException e) {
                if (e.getResponse().getStatusLine().getStatusCode() == 404) {
                    logger.debug("Waiting for [{}] index to be created...", SETTINGS_INDEX);
                    Thread.sleep(POLL_INTERVAL_MS);
                } else {
                    throw e;
                }
            }
        }
        fail(
                "Timed out waiting for ["
                        + SETTINGS_INDEX
                        + "] index to be created after "
                        + MAX_WAIT_SECONDS
                        + " seconds");
    }

    /**
     * Verifies that every content index exists as a concrete {@code <name>-a} index, which is the
     * name the issue reports as missing for the enrichments index.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testConcreteIndicesCreated() throws IOException, ParseException {
        for (String alias : ALIASES) {
            String physical = alias + SUFFIX_A;
            Response response = client().performRequest(new Request("GET", "/" + physical));
            String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

            logger.info("Index response for [{}]: {}", physical, body);
            assertThat(body, containsString(physical));
        }
    }

    /**
     * Verifies that every public alias resolves to its {@code -a} index and is that index's write
     * target, which is what lets the Content Manager swap the alias between the two physical slots.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testAliasesPointAtTheConcreteIndices() throws IOException, ParseException {
        for (String alias : ALIASES) {
            String physical = alias + SUFFIX_A;
            Response response = client().performRequest(new Request("GET", "/_alias/" + alias));
            String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

            logger.info("Alias response for [{}]: {}", alias, body);
            assertThat(body, containsString("\"" + physical + "\""));
            assertThat(body, containsString("\"" + alias + "\""));
            assertThat(body, containsString("\"is_write_index\":true"));
        }
    }

    /**
     * Verifies that every content index has its template installed, with a pattern that also covers
     * the {@code -b} shadow slot the Content Manager creates during a blue/green swap.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testTemplatesCreated() throws IOException, ParseException {
        for (String alias : ALIASES) {
            String template = alias + "-template";
            Response response =
                    client().performRequest(new Request("GET", "/_index_template/" + template));
            String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

            logger.info("Template response for [{}]: {}", template, body);
            assertThat(body, containsString(template));
            assertThat(body, containsString("\"" + alias + "*\""));
        }
    }

    /**
     * Verifies the check the issue prescribes: the alias resolves to the {@code -a} index and {@code
     * document.type} is an aggregatable keyword there, rather than the {@code text} field a
     * dynamically mapped index would have produced.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testEnrichmentsDocumentTypeIsAnAggregatableKeyword()
            throws IOException, ParseException {
        Response response =
                client()
                        .performRequest(
                                new Request("GET", "/" + ENRICHMENTS + "/_field_caps?fields=document.type"));
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

        logger.info("Field caps response for [document.type]: {}", body);
        assertThat(body, containsString("\"indices\":[\"" + ENRICHMENTS + SUFFIX_A + "\"]"));
        assertThat(body, containsString("\"type\":\"keyword\""));
        assertThat(body, containsString("\"aggregatable\":true"));
        assertThat(
                "document.type must not be a dynamically mapped text field",
                body,
                not(containsString("\"type\":\"text\"")));
    }

    /**
     * Verifies that the two aggregations the home overview's Threat catalog widget group issues in a
     * single request succeed. They returned a 400 while the index was dynamically mapped.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testThreatCatalogAggregationsSucceed() throws IOException, ParseException {
        Request search = new Request("POST", "/" + ENRICHMENTS + "/_search");
        search.setJsonEntity(
                """
                {
                  "size": 0,
                  "aggs": {
                    "ioc_feed_by_type": {"terms": {"field": "document.type", "size": 10}},
                    "threat_types": {"terms": {"field": "document.software.type", "size": 10}}
                  }
                }
                """);
        Response response = client().performRequest(search);
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

        logger.info("Threat catalog aggregation response: {}", body);
        assertThat("no shard may fail the aggregation", body, containsString("\"failed\":0"));
        assertThat(body, containsString("ioc_feed_by_type"));
        assertThat(body, containsString("threat_types"));
    }

    /**
     * Verifies that an IoC document is accepted. The enrichments mapping is {@code dynamic:
     * strict_allow_templates} and every IoC carries an {@code offset}, so a template missing that
     * field would reject every CTI write.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testIocDocumentIsAccepted() throws IOException, ParseException {
        Request index = new Request("PUT", "/" + ENRICHMENTS + "/_doc/setup-it-ioc");
        index.addParameter("refresh", "true");
        index.setJsonEntity(
                """
                {
                  "offset": 42,
                  "hash": {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
                  "document": {
                    "id": "ioc-1",
                    "type": "domain",
                    "name": "example.invalid",
                    "provider": "wazuh",
                    "confidence": 85,
                    "tags": ["test"],
                    "software": {"type": "malware", "name": "test", "alias": "test"}
                  }
                }
                """);
        Response response = client().performRequest(index);
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

        logger.info("IoC index response: {}", body);
        assertThat(body, containsString("\"result\":\"created\""));
        // The write went through the alias, so it must have landed on the concrete index.
        assertThat(body, containsString("\"_index\":\"" + ENRICHMENTS + SUFFIX_A + "\""));
    }

    /**
     * Clears the fielddata cache after each test to prevent flaky failures from the test framework's
     * post-test assertions.
     *
     * @throws IOException if there is an issue with the HTTP request
     */
    @After
    public void clearFieldData() throws IOException {
        Request request = new Request("POST", "/_cache/clear");
        request.addParameter("fielddata", "true");
        client().performRequest(request);
    }
}
