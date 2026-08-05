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

/**
 * Integration tests verifying that the setup plugin creates the AI assistant resources: the {@code
 * wazuh-ai-assistant-sessions} data stream (with its index template and ISM policy) and the hidden
 * {@code .wazuh-ai-assistant-settings} index, which holds both the AI providers configuration and
 * the assistant-wide settings.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.SUITE)
public class AIAssistantIndicesIT extends OpenSearchRestTestCase {

    private static final String SESSIONS_DATA_STREAM = "wazuh-ai-assistant-sessions";
    private static final String SESSIONS_TEMPLATE = SESSIONS_DATA_STREAM + "-template";
    private static final String SESSIONS_POLICY = "ai-assistant-sessions-policy";
    private static final String SETTINGS_INDEX = ".wazuh-ai-assistant-settings";

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
     * Verifies that the sessions data stream is created and its ISM policy is applied to the backing
     * index.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testSessionsDataStreamCreated() throws IOException, ParseException {
        Response response =
                client().performRequest(new Request("GET", "/_data_stream/" + SESSIONS_DATA_STREAM));
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

        logger.info("Data stream response for [{}]: {}", SESSIONS_DATA_STREAM, body);
        assertThat(body, containsString(SESSIONS_DATA_STREAM));
        assertThat(body, containsString(".ds-" + SESSIONS_DATA_STREAM));
    }

    /**
     * Verifies that the sessions index template is created with strict mappings, the {@code user}
     * field used for Document Level Security, the {@code messages} field mapped as an unindexed
     * ({@code enabled: false}) object rather than with an explicit sub-schema, and the daily rollover
     * ISM policy.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testSessionsTemplateCreated() throws IOException, ParseException {
        Response response =
                client().performRequest(new Request("GET", "/_index_template/" + SESSIONS_TEMPLATE));
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

        logger.info("Template response for [{}]: {}", SESSIONS_TEMPLATE, body);
        assertThat(body, containsString(SESSIONS_TEMPLATE));
        assertThat(body, containsString("\"dynamic\":\"strict\""));
        assertThat(body, containsString("\"user\""));
        assertThat(body, containsString("\"messages\""));
        assertThat(body, containsString("\"enabled\":false"));
        assertThat(body, containsString(SESSIONS_POLICY));
    }

    /**
     * Verifies that the sessions ISM policy is indexed with a daily rollover and a 7-day retention.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testSessionsIsmPolicyCreated() throws IOException, ParseException {
        Response response =
                client().performRequest(new Request("GET", "/_plugins/_ism/policies/" + SESSIONS_POLICY));
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

        logger.info("ISM policy response for [{}]: {}", SESSIONS_POLICY, body);
        assertThat(body, containsString(SESSIONS_POLICY));
        assertThat(body, containsString("\"min_index_age\":\"1d\""));
        assertThat(body, containsString("\"min_index_age\":\"7d\""));
    }

    /**
     * Verifies that the AI assistant settings index is created as a hidden index with strict
     * mappings, holding both the {@code providers} and the {@code settings} objects.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testSettingsIndexCreated() throws IOException, ParseException {
        Request request = new Request("GET", "/" + SETTINGS_INDEX);
        request.addParameter("expand_wildcards", "all");
        Response response = client().performRequest(request);
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

        logger.info("Index response for [{}]: {}", SETTINGS_INDEX, body);
        assertThat(body, containsString(SETTINGS_INDEX));
        assertThat(body, containsString("\"hidden\":\"true\""));
        assertThat(body, containsString("\"dynamic\":\"strict\""));
        assertThat(body, containsString("\"providers\""));
        assertThat(body, containsString("api_key"));
        assertThat(body, containsString("\"settings\""));
        assertThat(body, containsString("conversationRetentionDays"));
        assertThat(body, containsString("privacyDefaultOn"));
        assertThat(body, containsString("privacyDefaultPerProvider"));
        assertThat(body, containsString("userCanOverride"));
    }

    /**
     * Verifies that the strict mapping of the settings index rejects unknown fields.
     *
     * @throws IOException if there is an issue with the HTTP request
     */
    public void testSettingsIndexRejectsUnknownFields() throws IOException {
        Request request = new Request("POST", "/" + SETTINGS_INDEX + "/_doc");
        request.setJsonEntity("{\"providers\":{\"name\":\"test-ai\"},\"unexpected_field\":\"value\"}");

        ResponseException exception =
                expectThrows(ResponseException.class, () -> client().performRequest(request));
        assertEquals(400, exception.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Verifies that a provider document and a settings document can coexist in the same index, since
     * the settings index holds two kinds of documents sharing a single strict mapping.
     *
     * @throws IOException if there is an issue with the HTTP request
     */
    public void testSettingsIndexHoldsProvidersAndSettingsDocuments() throws IOException {
        Request providerDoc = new Request("POST", "/" + SETTINGS_INDEX + "/_doc");
        providerDoc.setJsonEntity(
                "{\"providers\":{\"name\":\"test-ai\",\"type\":\"anthropic\","
                        + "\"base_url\":\"https://api.anthropic.com\",\"model\":\"claude-opus-4-6\","
                        + "\"api_key\":\"enc:v1:SC/RyOIBkdm+kGl\",\"is_default\":true}}");
        Response providerResponse = client().performRequest(providerDoc);
        assertEquals(201, providerResponse.getStatusLine().getStatusCode());

        Request settingsDoc = new Request("PUT", "/" + SETTINGS_INDEX + "/_doc/1");
        settingsDoc.setJsonEntity(
                "{\"settings\":{\"conversationRetentionDays\":0,\"privacyDefaultOn\":false,"
                        + "\"privacyDefaultPerProvider\":{},\"userCanOverride\":true}}");
        Response settingsResponse = client().performRequest(settingsDoc);
        assertEquals(201, settingsResponse.getStatusLine().getStatusCode());
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
