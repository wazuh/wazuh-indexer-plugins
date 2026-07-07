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

/**
 * Integration tests verifying that the setup plugin creates the events and findings data streams
 * (and their index templates) for every Wazuh Common Schema category, via REST API calls against an
 * external test cluster.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.SUITE)
public class DataStreamsIT extends OpenSearchRestTestCase {

    /** Wazuh Common Schema category keys, as defined in {@code SetupPlugin.categories}. */
    private static final String[] CATEGORIES = {
        "access-management",
        "applications",
        "cloud-services",
        "network-activity",
        "security",
        "system-activity",
        "other",
        "unclassified"
    };

    private static final String EVENTS_PREFIX = "wazuh-events-v5-";
    private static final String FINDINGS_PREFIX = "wazuh-findings-v5-";
    private static final int MAX_WAIT_SECONDS = 120;
    private static final int POLL_INTERVAL_MS = 500;

    /**
     * Preserves indices upon test completion to prevent the test framework from deleting indices
     * created by the SetupPlugin between tests.
     *
     * @return true to preserve indices
     */
    @Override
    protected boolean preserveIndicesUponCompletion() {
        return true;
    }

    /**
     * Preserves data streams upon test completion. The SetupPlugin creates data streams during
     * initialization, and these need to persist across all tests in this class.
     *
     * @return true to preserve data streams
     */
    @Override
    protected boolean preserveDataStreamsUponCompletion() {
        return true;
    }

    /**
     * Preserves index templates upon test completion. The SetupPlugin creates index templates for
     * data streams, and these need to persist across all tests.
     *
     * @return true to preserve templates
     */
    @Override
    protected boolean preserveTemplatesUponCompletion() {
        return true;
    }

    /**
     * Waits for the plugin initialization to complete by polling for the last category's findings
     * data stream, which is created after every other index in the setup plugin's initialization
     * order. CI runners may be slow due to resource constraints; timeout is {@value
     * #MAX_WAIT_SECONDS} seconds.
     *
     * @throws Exception if the data stream is not created within the timeout
     */
    @Before
    public void waitForPluginInitialization() throws Exception {
        String lastFindingsDataStream = FINDINGS_PREFIX + CATEGORIES[CATEGORIES.length - 1];
        long startTime = System.currentTimeMillis();
        long timeout = TimeUnit.SECONDS.toMillis(MAX_WAIT_SECONDS);

        while (System.currentTimeMillis() - startTime < timeout) {
            try {
                client().performRequest(new Request("GET", "/_data_stream/" + lastFindingsDataStream));
                logger.info("Setup plugin initialization is ready");
                return;
            } catch (ResponseException e) {
                if (e.getResponse().getStatusLine().getStatusCode() == 404) {
                    logger.debug("Waiting for [{}] data stream to be created...", lastFindingsDataStream);
                    Thread.sleep(POLL_INTERVAL_MS);
                } else {
                    throw e;
                }
            }
        }
        fail(
                "Timed out waiting for ["
                        + lastFindingsDataStream
                        + "] data stream to be created after "
                        + MAX_WAIT_SECONDS
                        + " seconds");
    }

    /**
     * Verifies that every category has its events data stream created during plugin initialization.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testEventsDataStreamsCreated() throws IOException, ParseException {
        for (String category : CATEGORIES) {
            String dataStream = EVENTS_PREFIX + category;
            Response response =
                    client().performRequest(new Request("GET", "/_data_stream/" + dataStream));
            String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

            logger.info("Data stream response for [{}]: {}", dataStream, body);
            assertThat(
                    "Events data stream for category [" + category + "] should be created",
                    body,
                    containsString(dataStream));
        }
    }

    /**
     * Verifies that every category has its findings data stream created during plugin initialization.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testFindingsDataStreamsCreated() throws IOException, ParseException {
        for (String category : CATEGORIES) {
            String dataStream = FINDINGS_PREFIX + category;
            Response response =
                    client().performRequest(new Request("GET", "/_data_stream/" + dataStream));
            String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

            logger.info("Data stream response for [{}]: {}", dataStream, body);
            assertThat(
                    "Findings data stream for category [" + category + "] should be created",
                    body,
                    containsString(dataStream));
        }
    }

    /**
     * Verifies that every category has its events index template created during plugin
     * initialization.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testEventsTemplatesCreated() throws IOException, ParseException {
        for (String category : CATEGORIES) {
            String template = EVENTS_PREFIX + category + "-template";
            Response response =
                    client().performRequest(new Request("GET", "/_index_template/" + template));
            String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

            logger.info("Template response for [{}]: {}", template, body);
            assertThat(
                    "Events template for category [" + category + "] should be created",
                    body,
                    containsString(template));
        }
    }

    /**
     * Verifies that every category has its findings index template created during plugin
     * initialization.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testFindingsTemplatesCreated() throws IOException, ParseException {
        for (String category : CATEGORIES) {
            String template = FINDINGS_PREFIX + category + "-template";
            Response response =
                    client().performRequest(new Request("GET", "/_index_template/" + template));
            String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

            logger.info("Template response for [{}]: {}", template, body);
            assertThat(
                    "Findings template for category [" + category + "] should be created",
                    body,
                    containsString(template));
        }
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
