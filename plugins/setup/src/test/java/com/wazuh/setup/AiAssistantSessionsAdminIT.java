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

import static org.hamcrest.Matchers.containsString;

/**
 * Integration tests for the administrative sessions API ({@code
 * /_plugins/_setup/ai_assistant/sessions}), which reads and deletes AI assistant conversations
 * across every user. Security is not enabled in this test cluster, so these tests cover the
 * endpoints' functional behavior (filtering, deletion); the Document Level Security bypass itself
 * is validated against a live, security-enabled cluster (see the setup plugin's development
 * documentation).
 */
@ThreadLeakScope(ThreadLeakScope.Scope.SUITE)
public class AiAssistantSessionsAdminIT extends OpenSearchRestTestCase {

    private static final String SESSIONS_URI = "/_plugins/_setup/ai_assistant/sessions";
    private static final String SESSIONS_DATA_STREAM = "wazuh-ai-assistant-sessions";

    @Override
    protected boolean preserveIndicesUponCompletion() {
        return true;
    }

    @Override
    protected boolean preserveDataStreamsUponCompletion() {
        return true;
    }

    /**
     * Indexes one session document per user before every test, so each test starts from a known,
     * non-empty state.
     *
     * @throws IOException if there is an issue with the HTTP request
     */
    @Before
    public void indexSessionsForTwoUsers() throws IOException {
        indexSession("admin-user-session", "admin");
        indexSession("demo-user-session", "wazuh-demo");
    }

    private void indexSession(String id, String user) throws IOException {
        Request request = new Request("PUT", "/" + SESSIONS_DATA_STREAM + "/_create/" + id);
        request.addParameter("refresh", "true");
        request.setJsonEntity(
                "{\"@timestamp\":\"2026-08-11T00:00:00.000Z\",\"user\":\""
                        + user
                        + "\",\"title\":\"test\",\"created_at\":\"2026-08-11T00:00:00.000Z\","
                        + "\"updated_at\":\"2026-08-11T00:00:00.000Z\",\"messages\":[]}");
        try {
            client().performRequest(request);
        } catch (ResponseException e) {
            if (e.getResponse().getStatusLine().getStatusCode() != 409) {
                throw e;
            }
        }
    }

    /**
     * Verifies that the search endpoint returns sessions belonging to every user when no {@code user}
     * filter is given.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testSearchReturnsSessionsAcrossUsers() throws IOException, ParseException {
        Response response = client().performRequest(new Request("GET", SESSIONS_URI));
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

        logger.info("Search response: {}", body);
        assertThat(body, containsString("\"admin-user-session\""));
        assertThat(body, containsString("\"demo-user-session\""));
    }

    /**
     * Verifies that the {@code user} query parameter restricts the search to one user's sessions.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testSearchFiltersByUser() throws IOException, ParseException {
        Request request = new Request("GET", SESSIONS_URI);
        request.addParameter("user", "wazuh-demo");
        Response response = client().performRequest(request);
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

        logger.info("Filtered search response: {}", body);
        assertThat(body, containsString("\"demo-user-session\""));
        assertFalse(body.contains("\"admin-user-session\""));
    }

    /**
     * Verifies that an out-of-range {@code size} parameter is rejected.
     *
     * @throws IOException if there is an issue with the HTTP request
     */
    public void testSearchRejectsOversizedPageSize() throws IOException {
        Request request = new Request("GET", SESSIONS_URI);
        request.addParameter("size", "10000");

        ResponseException exception =
                expectThrows(ResponseException.class, () -> client().performRequest(request));
        assertEquals(400, exception.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Verifies that a session belonging to any user can be deleted by id, and that deleting it a
     * second time reports {@code 404}.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testDeleteRemovesSessionRegardlessOfOwner() throws IOException, ParseException {
        Response response =
                client().performRequest(new Request("DELETE", SESSIONS_URI + "/demo-user-session"));
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
        logger.info("Delete response: {}", body);
        assertEquals(200, response.getStatusLine().getStatusCode());

        ResponseException notFound =
                expectThrows(
                        ResponseException.class,
                        () ->
                                client()
                                        .performRequest(new Request("DELETE", SESSIONS_URI + "/demo-user-session")));
        assertEquals(404, notFound.getResponse().getStatusLine().getStatusCode());
    }
}
