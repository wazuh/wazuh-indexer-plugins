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
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.test.rest.OpenSearchRestTestCase;
import org.junit.After;

import java.io.IOException;

import static org.hamcrest.Matchers.equalTo;

/**
 * Integration tests for the active responses index template. Verifies that the setup plugin creates
 * the streams-active-responses template, which backs the active-responses data stream used for
 * Active Response execution requests from monitor triggers.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.SUITE)
public class ActiveResponsesIT extends OpenSearchRestTestCase {

    private static final String ACTIVE_RESPONSES_INDEX_TEMPLATE = "streams-active-responses";

    /**
     * Test to verify that the active responses index template is created during plugin
     * initialization.
     */
    public void testActiveResponsesTemplateCreated()
            throws IOException, ParseException, InterruptedException {
        // Wait for setup plugin initialization to complete (template creation is async)
        int maxAttempts = 30;
        for (int i = 0; i < maxAttempts; i++) {
            try {
                Response response =
                        client()
                                .performRequest(
                                        new Request(
                                                "GET",
                                                "/_index_template/" + ACTIVE_RESPONSES_INDEX_TEMPLATE));
                if (response.getStatusLine().getStatusCode() == 200) {
                    return;
                }
            } catch (ResponseException e) {
                if (e.getResponse().getStatusLine().getStatusCode() != 404) {
                    throw e;
                }
            }
            Thread.sleep(1000);
        }
        Response response =
                client()
                        .performRequest(
                                new Request(
                                        "GET",
                                        "/_index_template/" + ACTIVE_RESPONSES_INDEX_TEMPLATE));
        assertThat(
                "Template should be created during plugin initialization",
                response.getStatusLine().getStatusCode(),
                equalTo(200));
    }

    @After
    public void clearFieldData() throws IOException {
        Request request = new Request("POST", "/_cache/clear");
        request.addParameter("fielddata", "true");
        client().performRequest(request);
    }
}
