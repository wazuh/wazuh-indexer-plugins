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
import org.opensearch.plugins.Plugin;
import org.opensearch.test.OpenSearchIntegTestCase;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.List;

import static org.hamcrest.Matchers.containsString;

/**
 * Integration tests for the unclassified events data stream. Verifies the creation and
 * configuration of the wazuh-events-v5-unclassified data stream.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.SUITE)
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class UnclassifiedEventsIT extends OpenSearchIntegTestCase {

    private static final String UNCLASSIFIED_DATASTREAM = "wazuh-events-v5-unclassified";

    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {
        return List.of(SetupPlugin.class);
    }

    /**
     * Test to verify that the unclassified events data stream is created during plugin
     * initialization.
     *
     * @throws IOException    if there's an error performing the request
     * @throws ParseException if there's an error parsing the response
     */
    public void testUnclassifiedDataStreamCreated() throws IOException, ParseException {
        // Wait for initialization to complete.
        this.ensureGreen();

        // Get data streams and verify the unclassified data stream exists
        Response response = getRestClient().performRequest(new Request("GET", "/_data_stream/" + UNCLASSIFIED_DATASTREAM));
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

        logger.info("Data stream response: {}", body);
        assertThat("Data stream should exist", body, containsString(UNCLASSIFIED_DATASTREAM));
    }

    /**
     * Test to verify that the unclassified events index template is created during plugin
     * initialization.
     *
     * @throws IOException    if there's an error performing the request
     * @throws ParseException if there's an error parsing the response
     */
    public void testUnclassifiedTemplateCreated() throws IOException, ParseException {
        // Wait for initialization to complete.
        this.ensureGreen();

        // Get index templates and verify the unclassified template exists
        Response response = getRestClient().performRequest(new Request("GET", "/_index_template/" + UNCLASSIFIED_DATASTREAM));
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

        logger.info("Template response: {}", body);
        assertThat("Template should exist", body, containsString(UNCLASSIFIED_DATASTREAM));
        assertThat("Template should have correct index pattern", body, containsString("wazuh-events-v5-unclassified*"));
    }

    /**
     * Test to verify that the unclassified events ISM policy is created during plugin
     * initialization.
     *
     * @throws IOException    if there's an error performing the request
     * @throws ParseException if there's an error parsing the response
     */
    public void testUnclassifiedISMPolicyCreated() throws IOException, ParseException {
        // Wait for initialization to complete.
        this.ensureGreen();

        // Check if the ISM policy exists
        Response response =
                getRestClient().performRequest(new Request("GET", "/.opendistro-ism-config/_doc/unclassified-events-policy"));
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

        logger.info("ISM policy response: {}", body);
        assertThat("ISM policy should exist", body, containsString("unclassified-events-policy"));
        assertThat("ISM policy should have 7 day retention", body, containsString("7d"));
    }

    /**
     * Test to verify that data can be indexed into the unclassified events data stream.
     *
     * @throws IOException    if there's an error performing the request
     * @throws ParseException if there's an error parsing the response
     */
    public void testIndexDocumentIntoUnclassifiedDataStream() throws IOException, ParseException {
        // Wait for initialization to complete.
        this.ensureGreen();

        // Prepare test document
        String testDocument =
                "{"
                        + "\"@timestamp\": \"2024-02-19T10:00:00Z\","
                        + "\"event\": {"
                        + "\"original\": \"raw uncategorized event data\""
                        + "},"
                        + "\"wazuh\": {"
                        + "\"agent\": {"
                        + "\"id\": \"001\","
                        + "\"name\": \"agent-test\""
                        + "},"
                        + "\"space\": {"
                        + "\"name\": \"default\""
                        + "}"
                        + "}"
                        + "}";

        // Index document into the data stream
        Request request = new Request("POST", "/" + UNCLASSIFIED_DATASTREAM + "/_doc");
        request.setJsonEntity(testDocument);
        Response response = getRestClient().performRequest(request);

        assertEquals("Document should be indexed successfully", 201, response.getStatusLine().getStatusCode());

        // Refresh to make the document searchable
        getRestClient().performRequest(new Request("POST", "/" + UNCLASSIFIED_DATASTREAM + "/_refresh"));

        // Verify the document was indexed
        Response searchResponse =
                getRestClient().performRequest(new Request("GET", "/" + UNCLASSIFIED_DATASTREAM + "/_search"));
        String searchBody = EntityUtils.toString(searchResponse.getEntity(), StandardCharsets.UTF_8);

        logger.info("Search response: {}", searchBody);
        assertThat("Document should be found", searchBody, containsString("agent-test"));
    }

    /**
     * Test to verify that the unclassified data stream has the correct configuration.
     *
     * @throws IOException    if there's an error performing the request
     * @throws ParseException if there's an error parsing the response
     */
    public void testUnclassifiedDataStreamConfiguration() throws IOException, ParseException {
        // Wait for initialization to complete.
        this.ensureGreen();

        // Get the data stream settings
        Response response = getRestClient().performRequest(new Request("GET", "/" + UNCLASSIFIED_DATASTREAM + "/_settings"));
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

        logger.info("Settings response: {}", body);
        assertThat("Should have rollover alias configured", body, containsString("rollover_alias"));
        assertThat("Should have unclassified in rollover alias", body, containsString(UNCLASSIFIED_DATASTREAM));
    }
}
