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

/**
 * Integration tests for the retention of the security audit log. The security plugin creates the
 * {@code security-auditlogs} data stream itself, from its own index template, on the first audit
 * event; the setup plugin only ships the ISM policy that manages it. The test cluster has no
 * security plugin, so the tests create the template and the data stream the way the security
 * plugin does.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.SUITE)
public class SecurityAuditLogsIT extends OpenSearchRestTestCase {

    private static final String AUDIT_DATA_STREAM = "security-auditlogs";
    private static final String AUDIT_POLICY = "security-auditlogs-policy";
    private static final String SECURITY_PLUGIN_TEMPLATE = "opensearch-security-auditlog";
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
     * Verifies that the audit log data stream, created as the security plugin creates it, is managed
     * by the audit log ISM policy. The security plugin puts its own template for the data stream at
     * the default priority, which fails if another template matching the name has the same priority,
     * so the put also proves that the setup plugin ships no such template.
     *
     * @throws Exception if there is an issue with the HTTP requests or the wait is interrupted
     */
    public void testSecurityPluginDataStreamIsManagedByAuditPolicy() throws Exception {
        Request template = new Request("PUT", "/_index_template/" + SECURITY_PLUGIN_TEMPLATE);
        template.setJsonEntity(
                """
                {
                  "index_patterns": ["security-auditlogs"],
                  "data_stream": {"timestamp_field": {"name": "@timestamp"}},
                  "template": {"settings": {"number_of_shards": 1, "number_of_replicas": 0}}
                }
                """);
        client().performRequest(template);

        try {
            client().performRequest(new Request("PUT", "/_data_stream/" + AUDIT_DATA_STREAM));
        } catch (ResponseException e) {
            String error = EntityUtils.toString(e.getResponse().getEntity(), StandardCharsets.UTF_8);
            assertThat(error, containsString("resource_already_exists_exception"));
        }

        String explain = "";
        long deadline = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(MAX_WAIT_SECONDS);
        while (System.currentTimeMillis() < deadline) {
            explain =
                    EntityUtils.toString(
                            client()
                                    .performRequest(
                                            new Request(
                                                    "GET", "/_plugins/_ism/explain/.ds-" + AUDIT_DATA_STREAM + "-*"))
                                    .getEntity(),
                            StandardCharsets.UTF_8);
            if (explain.contains(AUDIT_POLICY)) {
                break;
            }
            Thread.sleep(POLL_INTERVAL_MS);
        }
        logger.info("ISM explain response for [{}]: {}", AUDIT_DATA_STREAM, explain);
        assertThat(explain, containsString(AUDIT_POLICY));
    }
}
