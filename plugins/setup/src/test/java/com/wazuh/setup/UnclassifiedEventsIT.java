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
 * Integration tests for the unclassified events data stream. Verifies the creation and
 * configuration of the wazuh-events-v5-unclassified data stream using REST API calls against an
 * external test cluster.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.SUITE)
public class UnclassifiedEventsIT extends OpenSearchRestTestCase {

    private static final String UNCLASSIFIED_DATASTREAM = "wazuh-events-v5-unclassified";
    private static final String UNCLASSIFIED_INDEX_TEMPLATE = "streams-unclassified";
    private static final int MAX_WAIT_SECONDS = 60;
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
     * Waits for the plugin initialization to complete by polling for the unclassified data stream.
     * The SetupPlugin creates multiple data streams and templates during initialization, which
     * happens asynchronously after the cluster starts.
     *
     * @throws Exception if the data stream is not created within the timeout
     */
    @Before
    public void waitForPluginInitialization() throws Exception {
        long startTime = System.currentTimeMillis();
        long timeout = TimeUnit.SECONDS.toMillis(MAX_WAIT_SECONDS);

        while (System.currentTimeMillis() - startTime < timeout) {
            try {
                client().performRequest(new Request("GET", "/_data_stream/" + UNCLASSIFIED_DATASTREAM));
                logger.info("Unclassified data stream is ready");
                return;
            } catch (ResponseException e) {
                if (e.getResponse().getStatusLine().getStatusCode() == 404) {
                    logger.debug("Waiting for unclassified data stream to be created...");
                    Thread.sleep(POLL_INTERVAL_MS);
                } else {
                    throw e;
                }
            }
        }
        fail(
                "Timed out waiting for unclassified data stream to be created after "
                        + MAX_WAIT_SECONDS
                        + " seconds");
    }

    /**
     * Test to verify that the unclassified events data stream is created during plugin
     * initialization.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testUnclassifiedDataStreamCreated() throws IOException, ParseException {
        Response response =
                client().performRequest(new Request("GET", "/_data_stream/" + UNCLASSIFIED_DATASTREAM));
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

        logger.info("Data stream response: {}", body);
        assertThat(
                "Data stream should be created during plugin initialization",
                body,
                containsString(UNCLASSIFIED_DATASTREAM));
    }

    /**
     * Test to verify that the unclassified events index template is created during plugin
     * initialization.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testUnclassifiedTemplateCreated() throws IOException, ParseException {
        Response response =
                client()
                        .performRequest(new Request("GET", "/_index_template/" + UNCLASSIFIED_INDEX_TEMPLATE));
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

        logger.info("Template response: {}", body);
        assertThat(
                "Template should be created during plugin initialization",
                body,
                containsString(UNCLASSIFIED_INDEX_TEMPLATE));
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
