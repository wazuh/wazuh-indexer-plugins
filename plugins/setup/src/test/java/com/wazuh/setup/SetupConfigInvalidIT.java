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

import org.opensearch.client.Request;
import org.opensearch.client.ResponseException;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.OpenSearchRestTestCase;
import org.junit.Assert;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Integration test for an invalid configuration of the plugin. Two Gradle tasks run it, each on a
 * cluster that starts with the files of a folder of {@code src/test/resources/setup-config}:
 *
 * <ul>
 *   <li>{@code invalid}: a {@code setup.yml} that holds a value of the wrong type.
 *   <li>{@code invalid-policy}: a valid {@code setup.yml} that selects a policy file which Index
 *       State Management cannot read. On a node, the parser that rejects it comes from the Index
 *       Management plugin.
 * </ul>
 */
@ThreadLeakScope(ThreadLeakScope.Scope.SUITE)
public class SetupConfigInvalidIT extends OpenSearchRestTestCase {

    private static final String SETUP_STATUS_INDEX = ".wazuh-setup-status";
    private static final String SETUP_STATUS = "/" + SETUP_STATUS_INDEX + "/_doc/setup-status";
    private static final String ISM_INDEX = ".opendistro-ism-config";
    private static final int MAX_WAIT_SECONDS = 120;

    @Override
    protected boolean preserveIndicesUponCompletion() {
        return true;
    }

    /**
     * Performs a GET request and parses the response.
     *
     * @param endpoint the endpoint.
     * @return the response body.
     * @throws IOException if the request fails.
     */
    private static Map<String, Object> get(String endpoint) throws IOException {
        return OpenSearchRestTestCase.entityAsMap(
                OpenSearchRestTestCase.client().performRequest(new Request("GET", endpoint)));
    }

    /**
     * The initialization stops at the invalid configuration: the setup status is failed, and nothing
     * else the plugin creates exists. Only the setup status index does, to hold that status.
     *
     * @throws Exception if a request fails or the status is not set in time.
     */
    @SuppressWarnings("unchecked")
    public void testInitializationFailsBeforeAnythingIsCreated() throws Exception {
        OpenSearchTestCase.assertBusy(
                () -> {
                    try {
                        Map<String, Object> source =
                                (Map<String, Object>) SetupConfigInvalidIT.get(SETUP_STATUS).get("_source");
                        Assert.assertEquals("failed", source.get("status"));
                    } catch (ResponseException e) {
                        throw new AssertionError("The setup status is not available yet", e);
                    }
                },
                MAX_WAIT_SECONDS,
                TimeUnit.SECONDS);

        List<String> indices =
                OpenSearchRestTestCase.entityAsList(
                                OpenSearchRestTestCase.client()
                                        .performRequest(
                                                new Request(
                                                        "GET", "/_cat/indices?format=json&expand_wildcards=all&h=index")))
                        .stream()
                        .map(index -> (String) ((Map<String, Object>) index).get("index"))
                        .toList();
        Assert.assertEquals(List.of(SETUP_STATUS_INDEX), indices);

        List<String> templates =
                ((List<Map<String, Object>>)
                                SetupConfigInvalidIT.get("/_index_template").get("index_templates"))
                        .stream().map(template -> (String) template.get("name")).toList();
        Assert.assertEquals(List.of("setup-status"), templates);

        Assert.assertEquals(List.of(), SetupConfigInvalidIT.get("/_data_stream").get("data_streams"));

        ResponseException e =
                OpenSearchTestCase.expectThrows(
                        ResponseException.class, () -> SetupConfigInvalidIT.get("/" + ISM_INDEX));
        Assert.assertEquals(404, e.getResponse().getStatusLine().getStatusCode());
    }
}
