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
     * Verifies that the process/service/package "previous" fields (added so that IT Hygiene
     * "modified" events can express what a field changed from, not just that it changed) are
     * mapped with the correct types and are actually aggregatable, not merely accepted as text.
     *
     * <p>This is a regression guard for {@code process.previous.parent.pid} in particular: it
     * depends on a fragile ECS self-reuse snapshot-timing workaround (see the comment in {@code
     * wcs/stateless/events/main/fields/custom/process.yml}) that a future WCS generator or
     * vendored ECS schema bump could silently break without any other test noticing.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testEventsPreviousFieldsAreMappedAndAggregatable() throws IOException, ParseException {
        Request index = new Request("POST", "/" + EVENTS_PREFIX + "security/_doc");
        index.addParameter("refresh", "true");
        index.setJsonEntity(
                """
                {
                  "@timestamp": "2026-07-30T19:27:34.682Z",
                  "event": {"type": "modified", "collector": "dbsync_processes", "module": "inventory"},
                  "process": {
                    "pid": 4184885,
                    "state": "S",
                    "previous": {
                      "pid": 999000123,
                      "state": "R",
                      "parent": {"pid": 999000111}
                    }
                  },
                  "service": {"name": "wazuh-indexer", "state": "active", "previous": {"state": "activating"}},
                  "package": {"name": "wcs-test-previous-fields", "previous": {"installed": "2026-07-01T10:00:00.000Z"}}
                }
                """);
        client().performRequest(index);

        Request search = new Request("GET", "/" + EVENTS_PREFIX + "security/_search");
        search.setJsonEntity(
                """
                {
                  "size": 0,
                  "query": {"term": {"process.previous.pid": 999000123}},
                  "aggs": {
                    "process_previous_state": {"terms": {"field": "process.previous.state"}},
                    "process_previous_parent_pid": {"terms": {"field": "process.previous.parent.pid"}},
                    "process_state": {"terms": {"field": "process.state"}},
                    "service_previous_state": {"terms": {"field": "service.previous.state"}},
                    "package_previous_installed": {"terms": {"field": "package.previous.installed"}}
                  }
                }
                """);
        Response response = client().performRequest(search);
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
        logger.info("Previous-fields aggregation response: {}", body);

        assertThat("process.previous.state should aggregate as keyword", body, containsString("\"key\":\"R\""));
        assertThat(
                "process.previous.parent.pid should aggregate as long",
                body,
                containsString("\"key\":999000111"));
        assertThat("process.state should aggregate as keyword", body, containsString("\"key\":\"S\""));
        assertThat(
                "service.previous.state should aggregate as keyword",
                body,
                containsString("\"key\":\"activating\""));
        assertThat(
                "package.previous.installed should aggregate as date",
                body,
                containsString("2026-07-01T10:00:00.000Z"));
    }

    /**
     * Verifies that the events template still rejects fields outside the WCS schema, i.e. that
     * {@code dynamic: strict_allow_templates} is doing its job and the assertions above are proof
     * of real field mappings, not permissive dynamic mapping.
     *
     * @throws IOException if there is an issue with the HTTP request
     */
    public void testEventsRejectUnmappedField() throws IOException {
        Request index = new Request("POST", "/" + EVENTS_PREFIX + "security/_doc");
        index.setJsonEntity(
                """
                {"@timestamp": "2026-08-05T00:00:00.000Z", "process": {"totally_bogus_unmapped_field": "x"}}
                """);

        ResponseException exception =
                expectThrows(ResponseException.class, () -> client().performRequest(index));
        assertEquals(400, exception.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Verifies that {@code service.previous.state} and {@code package.previous.installed} reach
     * the findings stream too. This is expected: {@code service}/{@code package} use {@code
     * fields: "*"} in every stateless events module's subset, and the WCS generator always folds
     * {@code stateless/events/main}'s custom fields into every other {@code stateless/events/*}
     * module, so these two fields are inherited automatically rather than by a per-module choice.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testFindingsInheritsServiceAndPackagePreviousFields() throws IOException, ParseException {
        Request index = new Request("POST", "/" + FINDINGS_PREFIX + "security/_doc");
        index.addParameter("refresh", "true");
        index.setJsonEntity(
                """
                {
                  "@timestamp": "2026-07-30T19:27:34.682Z",
                  "service": {"name": "wazuh-indexer", "state": "active", "previous": {"state": "activating"}},
                  "package": {"name": "wcs-test-findings-previous-fields", "previous": {"installed": "2026-07-01T10:00:00.000Z"}}
                }
                """);
        client().performRequest(index);

        Request search = new Request("GET", "/" + FINDINGS_PREFIX + "security/_search");
        search.setJsonEntity(
                """
                {
                  "size": 0,
                  "query": {"term": {"package.name": "wcs-test-findings-previous-fields"}},
                  "aggs": {
                    "service_previous_state": {"terms": {"field": "service.previous.state"}},
                    "package_previous_installed": {"terms": {"field": "package.previous.installed"}}
                  }
                }
                """);
        Response response = client().performRequest(search);
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
        logger.info("Findings inherited previous-fields aggregation response: {}", body);

        assertThat(body, containsString("\"key\":\"activating\""));
        assertThat(body, containsString("2026-07-01T10:00:00.000Z"));
    }

    /**
     * Verifies that the {@code process.state}/{@code process.previous.*} fields are mapped and
     * aggregatable in the findings stream too, keeping it at field parity with the events stream.
     * Mirrors {@link #testEventsPreviousFieldsAreMappedAndAggregatable}, and doubles as the
     * findings-side regression guard for the {@code process.previous.parent.pid} self-reuse
     * snapshot workaround.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testFindingsMapsProcessPreviousFields() throws IOException, ParseException {
        Request index = new Request("POST", "/" + FINDINGS_PREFIX + "security/_doc");
        index.addParameter("refresh", "true");
        index.setJsonEntity(
                """
                {
                  "@timestamp": "2026-07-30T19:27:34.682Z",
                  "process": {
                    "pid": 4184885,
                    "state": "S",
                    "previous": {
                      "pid": 999000123,
                      "state": "R",
                      "parent": {"pid": 999000111}
                    }
                  }
                }
                """);
        client().performRequest(index);

        Request search = new Request("GET", "/" + FINDINGS_PREFIX + "security/_search");
        search.setJsonEntity(
                """
                {
                  "size": 0,
                  "query": {"term": {"process.previous.pid": 999000123}},
                  "aggs": {
                    "process_previous_state": {"terms": {"field": "process.previous.state"}},
                    "process_previous_parent_pid": {"terms": {"field": "process.previous.parent.pid"}},
                    "process_state": {"terms": {"field": "process.state"}}
                  }
                }
                """);
        Response response = client().performRequest(search);
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
        logger.info("Findings process previous-fields aggregation response: {}", body);

        assertThat("process.previous.state should aggregate as keyword", body, containsString("\"key\":\"R\""));
        assertThat(
                "process.previous.parent.pid should aggregate as long",
                body,
                containsString("\"key\":999000111"));
        assertThat("process.state should aggregate as keyword", body, containsString("\"key\":\"S\""));
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
