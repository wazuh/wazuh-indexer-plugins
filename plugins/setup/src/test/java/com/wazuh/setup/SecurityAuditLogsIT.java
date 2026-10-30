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
import org.junit.Before;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;

/**
 * Integration tests verifying that the setup plugin creates the security audit log resources: the
 * {@code security-auditlogs} data stream, its index template and its ISM policy. The test cluster
 * has no security plugin, so the audit sink itself is not exercised here; the documents indexed
 * below have the shape of the security plugin's audit messages.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.SUITE)
public class SecurityAuditLogsIT extends OpenSearchRestTestCase {

    private static final String AUDIT_DATA_STREAM = "security-auditlogs";
    private static final String AUDIT_TEMPLATE = AUDIT_DATA_STREAM + "-template";
    private static final String AUDIT_POLICY = "security-auditlogs-policy";
    private static final String SETTINGS_INDEX = ".wazuh-settings";

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
     * Waits for the plugin initialization to complete by polling for the settings index, which is
     * registered last in the setup plugin's initialization order. CI runners may be slow due to
     * resource constraints; timeout is {@value #MAX_WAIT_SECONDS} seconds.
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
     * Verifies that the audit log data stream is created during plugin initialization, before the
     * security plugin's first audit event would create it without the retention policy.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testAuditDataStreamCreated() throws IOException, ParseException {
        Response response =
                client().performRequest(new Request("GET", "/_data_stream/" + AUDIT_DATA_STREAM));
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

        logger.info("Data stream response for [{}]: {}", AUDIT_DATA_STREAM, body);
        assertThat(body, containsString(".ds-" + AUDIT_DATA_STREAM));
    }

    /**
     * Verifies that the audit log index template carries the ISM policy and a priority above 0. The
     * security plugin puts its own template for the same data stream at priority 0 on every node
     * start, and that put fails when another template matching the name has the same priority,
     * which stops audit logging altogether.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testAuditTemplateCreated() throws IOException, ParseException {
        Response response =
                client().performRequest(new Request("GET", "/_index_template/" + AUDIT_TEMPLATE));
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

        logger.info("Template response for [{}]: {}", AUDIT_TEMPLATE, body);
        assertThat(body, containsString("\"priority\":1"));
        assertThat(body, containsString("\"dynamic\":false"));
        assertThat(body, containsString(AUDIT_POLICY));
    }

    /**
     * Verifies that the audit log ISM policy is indexed with a monthly rollover and a 90-day retention.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testAuditIsmPolicyCreated() throws IOException, ParseException {
        Response response =
                client().performRequest(new Request("GET", "/_plugins/_ism/policies/" + AUDIT_POLICY));
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

        logger.info("ISM policy response for [{}]: {}", AUDIT_POLICY, body);
        assertThat(body, containsString("\"min_index_age\":\"30d\""));
        assertThat(body, containsString("\"min_index_age\":\"90d\""));
        assertThat(body, containsString(".ds-" + AUDIT_DATA_STREAM + "-*"));
    }

    /**
     * Verifies that an audit message is stored and searchable by its mapped fields, and that the
     * request headers, whose names the client chooses, do not become fields of the mapping. A
     * client sending made-up headers on unauthenticated requests could otherwise fill the field
     * limit, after which every audit event is rejected.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testAuditMessageIsStoredWithoutMappingHeaderNames() throws IOException, ParseException {
        Request index = new Request("POST", "/" + AUDIT_DATA_STREAM + "/_doc");
        index.addParameter("refresh", "true");
        index.setJsonEntity(
                """
                {
                  "@timestamp": "2026-08-05T10:00:00.000Z",
                  "audit_format_version": 4,
                  "audit_category": "FAILED_LOGIN",
                  "audit_request_layer": "REST",
                  "audit_request_effective_user": "audit-test-user",
                  "audit_request_effective_user_is_admin": false,
                  "audit_request_remote_address": "192.0.2.10",
                  "audit_rest_request_path": "/_plugins/_security/authinfo",
                  "audit_rest_request_method": "GET",
                  "audit_rest_request_headers": {"X-Made-Up-Header-1": ["a"], "X-Made-Up-Header-2": ["b"]},
                  "audit_field_unknown_to_the_template": "kept in _source"
                }
                """);
        client().performRequest(index);

        Request search = new Request("GET", "/" + AUDIT_DATA_STREAM + "/_search");
        search.setJsonEntity(
                """
                {
                  "query": {
                    "bool": {
                      "filter": [
                        {"term": {"audit_category": "FAILED_LOGIN"}},
                        {"term": {"audit_request_effective_user": "audit-test-user"}}
                      ]
                    }
                  }
                }
                """);
        String hits =
                EntityUtils.toString(
                        client().performRequest(search).getEntity(), StandardCharsets.UTF_8);
        logger.info("Audit search response: {}", hits);
        assertThat(hits, containsString("\"audit_field_unknown_to_the_template\""));

        String mapping =
                EntityUtils.toString(
                        client()
                                .performRequest(new Request("GET", "/" + AUDIT_DATA_STREAM + "/_mapping"))
                                .getEntity(),
                        StandardCharsets.UTF_8);
        logger.info("Audit mapping response: {}", mapping);
        assertThat(mapping, not(containsString("X-Made-Up-Header-1")));
        assertThat(mapping, not(containsString("audit_field_unknown_to_the_template")));
    }
}
