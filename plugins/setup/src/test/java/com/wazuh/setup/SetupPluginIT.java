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
import org.opensearch.test.rest.OpenSearchRestTestCase;
import org.junit.After;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.hamcrest.Matchers.containsString;

/**
 * Integration tests for the SetupPlugin. This class checks if the plugin is installed and verifies
 * the presence of required plugins.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.SUITE)
public class SetupPluginIT extends OpenSearchRestTestCase {

    /**
     * Test to verify that the Wazuh Indexer Setup plugin is installed.
     *
     * @throws IOException Thrown if there is an issue with the HTTP request.
     * @throws ParseException Thrown if there is an issue parsing the response.
     */
    public void testPluginInstalled() throws IOException, ParseException {
        Response response = client().performRequest(new Request("GET", "/_cat/plugins"));
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

        logger.info("response body: {}", body);
        assertThat(body, containsString("wazuh-indexer-setup"));
    }

    /**
     * Test to verify that the Wazuh Indexer Setup plugin is installed via the nodes info API.
     *
     * @throws IOException Thrown if there is an issue with the HTTP request.
     * @throws ParseException Thrown if there is an issue parsing the response.
     */
    public void testPluginsAreInstalled() throws IOException, ParseException {
        Response response = client().performRequest(new Request("GET", "/_nodes/plugins"));
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

        assertThat(body, containsString("wazuh-indexer-setup"));
    }

    /**
     * Test to verify that the ISM plugin is installed via the nodes info API.
     *
     * @throws IOException Thrown if there is an issue with the HTTP request.
     * @throws ParseException Thrown if there is an issue parsing the response.
     */
    public void testISMPluginInstalled() throws IOException, ParseException {
        Response response = client().performRequest(new Request("GET", "/_nodes/plugins"));
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

        assertThat(body, containsString("opensearch-index-management"));
    }

    @After
    public void clearFieldData() throws IOException {
        Request request = new Request("POST", "/_cache/clear");
        request.addParameter("fielddata", "true");
        client().performRequest(request);
    }
}
